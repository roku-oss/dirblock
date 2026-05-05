#include "config.hpp"
#include "fanotify.hpp"
#include "log.hpp"
#include "notify.hpp"
#include "procinfo.hpp"

#include <algorithm>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <getopt.h>
#include <linux/limits.h>
#include <set>
#include <string>
#include <sys/select.h>
#include <unistd.h>
#include <vector>

static volatile sig_atomic_t g_running = 1;

static void signal_handler(int) {
    g_running = 0;
}

static void print_usage(const char* prog) {
    std::fprintf(stderr,
        "Usage: %s [--config PATH] [--dry-run] [--verbose|-v]\n"
        "\n"
        "  --config PATH   Path to dirblock.toml\n"
        "  --dry-run       Log but allow all accesses\n"
        "  --verbose, -v   Log all events including fast-path allows\n"
        "  --help, -h      Show this help\n",
        prog);
}

static std::string toml_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '\\' || c == '"') out += '\\';
        out += c;
    }
    return out;
}

static std::vector<AllowRule> build_dirblock_profile() {
    std::vector<AllowRule> profile;
    pid_t cur = getpid();

    for (int depth = 0; depth < 64; ++depth) {
        ProcSnapshot entry;
        if (!get_proc_snapshot(cur, entry)) break;
        if (entry.ppid <= 1) break;

        ProcSnapshot ancestor;
        if (!get_proc_snapshot(entry.ppid, ancestor)) break;

        AllowRule rule;
        rule.path = std::move(ancestor.exe);
        profile.push_back(std::move(rule));
        cur = entry.ppid;
    }

    return profile;
}

static void log_dirblock_profile(const std::vector<AllowRule>& profile) {
    LOG_INFO("generated built-in ancestry profile for this dirblock launch:");
    LOG_INFO("[profiles]");
    LOG_INFO("\"dirblock\" = [");
    for (const auto& rule : profile) {
        LOG_INFO("    \"%s\",", toml_escape(rule.path).c_str());
    }
    LOG_INFO("]");
}

int main(int argc, char* argv[]) {
    // Parse args
    std::string config_path;
    bool dry_run = false;

    static struct option long_opts[] = {
        {"config",  required_argument, nullptr, 'c'},
        {"dry-run", no_argument,       nullptr, 'd'},
        {"verbose", no_argument,       nullptr, 'v'},
        {"help",    no_argument,       nullptr, 'h'},
        {nullptr,   0,                 nullptr,  0 }
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "c:dvh", long_opts, nullptr)) != -1) {
        switch (opt) {
        case 'c': config_path = optarg; break;
        case 'd': dry_run = true; break;
        case 'v': g_log_level = LogLevel::Verbose; break;
        case 'h': print_usage(argv[0]); return 0;
        default:  print_usage(argv[0]); return 1;
        }
    }

    // Find config
    if (config_path.empty()) {
        // Try relative to binary location
        char self[PATH_MAX];
        ssize_t len = readlink("/proc/self/exe", self, sizeof(self) - 1);
        if (len > 0) {
            self[len] = '\0';
            std::string bin_dir(self);
            auto pos = bin_dir.rfind('/');
            if (pos != std::string::npos) {
                bin_dir.resize(pos);
                // Try ../config/dirblock.toml relative to binary
                std::string candidate = bin_dir + "/../config/dirblock.toml";
                if (access(candidate.c_str(), R_OK) == 0) {
                    config_path = candidate;
                }
            }
        }
    }
    if (config_path.empty()) {
        std::string home = get_real_home();
        std::string candidate = home + "/.config/dirblock/dirblock.toml";
        if (access(candidate.c_str(), R_OK) == 0) {
            config_path = candidate;
        }
    }
    if (config_path.empty()) {
        if (access("/etc/dirblock/dirblock.toml", R_OK) == 0) {
            config_path = "/etc/dirblock/dirblock.toml";
        }
    }
    if (config_path.empty()) {
        LOG_ERR("no config file found. Use --config or place dirblock.toml "
                "in ~/.config/dirblock/ or /etc/dirblock/");
        return 1;
    }

    std::vector<AllowRule> dirblock_profile = build_dirblock_profile();
    log_dirblock_profile(dirblock_profile);

    // Load config
    Config cfg;
    try {
        cfg = load_config(config_path);
    } catch (const std::exception& e) {
        LOG_ERR("config: %s", e.what());
        return 1;
    }
    resolve_builtin_profile(cfg, "dirblock", dirblock_profile);

    LOG_INFO("config loaded from %s", config_path.c_str());
    for (const auto& wd : cfg.watched) {
        std::string allow_list;
        // Format each rule as "filter:path" or just "path"
        for (const auto& rule : wd.allowlist) {
            if (!allow_list.empty()) allow_list += ", ";
            if (!rule.comm_filter.empty()) {
                allow_list += rule.comm_filter + ":";
            }
            allow_list += rule.path;
            if (!rule.profile_name.empty()) {
                allow_list += ";" + rule.profile_name;
            }
        }
        LOG_INFO("  watching: %s  allow: %s", wd.path.c_str(), allow_list.c_str());
    }
    if (dry_run) {
        LOG_INFO("  ** DRY RUN -- all accesses will be allowed **");
    }

    // Init fanotify
    int fan_fd;
    try {
        fan_fd = fan_init();
    } catch (const std::exception& e) {
        LOG_ERR("%s", e.what());
        return 1;
    }
    ScopedFd fan_guard(fan_fd);
    LOG_INFO("fanotify fd=%d", fan_fd);

    // Mark mount points
    std::set<std::string> mount_points;
    for (const auto& wd : cfg.watched) {
        try {
            mount_points.insert(get_mount_point(wd.path));
        } catch (const std::exception& e) {
            LOG_ERR("mount detection: %s", e.what());
            return 1;
        }
    }

    for (const auto& mp : mount_points) {
        try {
            fan_mark_mount(fan_fd, mp.c_str());
            LOG_INFO("marked mount %s", mp.c_str());
        } catch (const std::exception& e) {
            LOG_ERR("%s", e.what());
            return 1;
        }
    }

    LOG_INFO("watching %zu mount(s), %zu directories, waiting for events...",
             mount_points.size(), cfg.watched.size());

    // Signals
    struct sigaction sa = {};
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    // Notifier
    Notifier notifier;
    notifier.set_enabled(cfg.notify);

    // Event loop
    long long allowed_count = 0;
    long long denied_count = 0;
    char fd_path_buf[PATH_MAX];

    while (g_running) {
        // select with timeout for responsive shutdown
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fan_fd, &rfds);
        struct timeval tv = { 0, 500000 }; // 500ms

        int sel = select(fan_fd + 1, &rfds, nullptr, nullptr, &tv);
        if (sel <= 0) continue; // timeout or EINTR

        FanEvent events[170]; // 4096 / sizeof(fanotify_event_metadata)
        int count = fan_read_events(fan_fd, events, 170);

        for (int i = 0; i < count; ++i) {
            int efd = events[i].fd;
            pid_t pid = events[i].pid;

            try {
                const char* fd_path = get_fd_path(efd, fd_path_buf, sizeof(fd_path_buf));
                const WatchedDir* wd = find_watched_dir(fd_path, cfg.watched);

                if (!wd) {
                    // Not in a watched dir — fast path allow
                    LOG_VERBOSE("PASS: pid=%d -> %s", pid, fd_path ? fd_path : "?");
                    fan_respond(fan_fd, efd, true);
                    ++allowed_count;
                    ::close(efd);
                    continue;
                }

                std::string exe_path = get_exe_path(pid);
                bool allowed = is_exe_allowed(exe_path, pid, wd->allowlist);

                // Extract basename for logging
                const char* exe_name = exe_path.c_str();
                const char* slash = std::strrchr(exe_name, '/');
                if (slash) exe_name = slash + 1;

                if (allowed) {
                    LOG_VERBOSE("ALLOWED: pid=%d exe=%s (%s) -> %s",
                                pid, exe_name, exe_path.c_str(),
                                fd_path ? fd_path : "?");
                    fan_respond(fan_fd, efd, true);
                    ++allowed_count;
                } else if (dry_run) {
                    fan_respond(fan_fd, efd, true);
                    ++allowed_count;
                    std::string cmdline = get_cmdline(pid);
                    LOG_INFO("DRY-RUN DENY: pid=%d exe=%s (%s) [%s] -> %s",
                             pid, exe_name, exe_path.c_str(), cmdline.c_str(),
                             fd_path ? fd_path : "?");
                    notifier.send_deny(exe_name, exe_path,
                                       fd_path, wd->path);
                } else {
                    fan_respond(fan_fd, efd, false);
                    ++denied_count;
                    std::string cmdline = get_cmdline(pid);
                    LOG_INFO("DENIED: pid=%d exe=%s (%s) [%s] -> %s",
                             pid, exe_name, exe_path.c_str(), cmdline.c_str(),
                             fd_path ? fd_path : "?");
                    notifier.send_deny(exe_name, exe_path,
                                       fd_path, wd->path);
                }
            } catch (...) {
                // CRITICAL: always respond to prevent hanging the caller
                fan_respond(fan_fd, efd, true);
                LOG_ERR("exception processing event (allowed to avoid hang)");
            }
            ::close(efd);
        }
    }

    LOG_INFO("shutting down. allowed=%lld denied=%lld", allowed_count, denied_count);
    return 0;
}
