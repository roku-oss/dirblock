#include "config.hpp"
#include "log.hpp"
#include "procinfo.hpp"
#include "toml_mini.hpp"

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <unordered_map>
#include <utility>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;

std::string get_real_home() {
    // When running under sudo, expand ~ to the real user's home
    const char* sudo_user = std::getenv("SUDO_USER");
    if (sudo_user) {
        struct passwd* pw = getpwnam(sudo_user);
        if (pw) return pw->pw_dir;
    }
    const char* home = std::getenv("HOME");
    if (home) return home;
    struct passwd* pw = getpwuid(getuid());
    if (pw) return pw->pw_dir;
    return "/root";
}

static std::string expand_path(const std::string& p, const std::string& home) {
    if (!p.empty() && p[0] == '~') {
        return home + p.substr(1);
    }
    return p;
}

static void finalize_path_rule(AllowRule& rule, const std::string& home) {
    rule.path = expand_path(rule.path, home);
    rule.is_prefix = !rule.path.empty() && rule.path.back() == '/';
}

// Parse a profile entry. Profiles are path-only: no cmdline filters and no nesting.
static AllowRule parse_profile_entry(const std::string& entry,
                                     const std::string& home) {
    AllowRule rule;
    rule.path = entry;
    finalize_path_rule(rule, home);
    return rule;
}

// Parse an allowlist entry: "filter:path;profile" or just "path;profile".
// Uses ':' as delimiter for cmdline filters and ';' as delimiter for profiles.
// Returns AllowRule with expanded path, optional comm_filter, and optional profile.
static AllowRule parse_entry(const std::string& entry, const std::string& home) {
    AllowRule rule;

    // Split on FIRST ':'
    size_t colon_pos = entry.find(':');
    if (colon_pos != std::string::npos) {
        rule.comm_filter = entry.substr(0, colon_pos);
        rule.path = entry.substr(colon_pos + 1);
    } else {
        rule.comm_filter = "";
        rule.path = entry;
    }

    // Split profile suffix from the path after cmdline filter parsing.
    size_t semi_pos = rule.path.rfind(';');
    if (semi_pos != std::string::npos) {
        rule.profile_name = rule.path.substr(semi_pos + 1);
        rule.path = rule.path.substr(0, semi_pos);
        if (rule.profile_name.empty()) {
            throw std::runtime_error("empty ancestry profile in entry: " + entry);
        }
    }

    finalize_path_rule(rule, home);

    return rule;
}

using ProfileMap = std::unordered_map<std::string, std::vector<AllowRule>>;

static ProfileMap parse_profiles(const toml_mini::Document& data,
                                 const std::string& home) {
    ProfileMap profiles;
    if (!data.count("profiles")) return profiles;

    for (const auto& [name, val] : data.at("profiles")) {
        std::vector<AllowRule> rules;
        for (const auto& p : val.string_array) {
            AllowRule rule = parse_profile_entry(p, home);
            if (rule.path.empty()) {
                throw std::runtime_error("empty path in profile: " + name);
            }
            rules.push_back(std::move(rule));
        }
        if (rules.empty()) {
            throw std::runtime_error("empty ancestry profile: " + name);
        }
        profiles[name] = std::move(rules);
    }

    return profiles;
}

Config load_config(const std::string& path) {
    Config cfg;
    auto data = toml_mini::parse(path);

    // [general]
    if (data.count("general")) {
        auto& gen = data["general"];
        if (gen.count("notify") && gen["notify"].is_bool) {
            cfg.notify = gen["notify"].bool_val;
        }
    }

    std::string home = get_real_home();
    ProfileMap profiles = parse_profiles(data, home);

    // [watched]
    if (!data.count("watched")) {
        throw std::runtime_error("config missing [watched] section");
    }

    auto& watched_table = data["watched"];

    for (const auto& [key, val] : watched_table) {
        std::string expanded = expand_path(key, home);
        std::string resolved;
        try {
            resolved = fs::canonical(expanded).string();
        } catch (const fs::filesystem_error&) {
            LOG_WARN("watched dir does not exist: %s (%s), skipping",
                     key.c_str(), expanded.c_str());
            continue;
        }

        if (!fs::is_directory(resolved)) {
            LOG_WARN("watched path is not a directory: %s, skipping",
                     resolved.c_str());
            continue;
        }

        WatchedDir wd;
        wd.path = resolved;
        for (const auto& p : val.string_array) {
            AllowRule rule = parse_entry(p, home);
            if (!rule.profile_name.empty()) {
                auto it = profiles.find(rule.profile_name);
                if (it == profiles.end()) {
                    if (rule.profile_name != "dirblock") {
                        throw std::runtime_error("unknown ancestry profile '" +
                                                 rule.profile_name + "' in entry: " + p);
                    }
                    LOG_INFO("  built-in ancestry profile: \"%s\" on path \"%s\"",
                             rule.profile_name.c_str(), rule.path.c_str());
                } else {
                    rule.ancestry_profile = it->second;
                    LOG_INFO("  ancestry profile: \"%s\" on path \"%s\"",
                             rule.profile_name.c_str(), rule.path.c_str());
                }
            }
            if (!rule.comm_filter.empty()) {
                LOG_INFO("  cmdline filter: \"%s\" on path \"%s\"",
                         rule.comm_filter.c_str(), rule.path.c_str());
            }
            wd.allowlist.push_back(std::move(rule));
        }
        cfg.watched.push_back(std::move(wd));
    }

    if (cfg.watched.empty()) {
        throw std::runtime_error("no valid watched directories in config");
    }

    return cfg;
}

const WatchedDir* find_watched_dir(const char* fd_path,
                                    const std::vector<WatchedDir>& watched) {
    if (!fd_path) return nullptr;
    for (const auto& wd : watched) {
        size_t len = wd.path.size();
        // Check: fd_path starts with wd.path + "/" or equals wd.path
        if (std::strncmp(fd_path, wd.path.c_str(), len) == 0) {
            if (fd_path[len] == '/' || fd_path[len] == '\0') {
                return &wd;
            }
        }
    }
    return nullptr;
}

static bool rule_matches_exe(const AllowRule& rule, const std::string& exe_path) {
    if (rule.path.empty()) return false;
    if (rule.is_prefix) {
        return exe_path.size() >= rule.path.size() &&
               exe_path.compare(0, rule.path.size(), rule.path) == 0;
    }
    return exe_path == rule.path;
}

static bool entry_matches_profile(const std::string& exe_path,
                                  const std::vector<AllowRule>& profile) {
    for (const auto& rule : profile) {
        if (rule_matches_exe(rule, exe_path)) return true;
    }
    return false;
}

struct ObservedAncestor {
    pid_t pid = -1;
    std::string exe;
};

struct AncestryDeny {
    pid_t pid = -1;
    std::string exe_path;
    std::string profile_name;
    const char* reason = "";
    bool has_blocked_ancestor = false;
    ObservedAncestor blocked_ancestor;
    std::vector<ObservedAncestor> ancestors;
};

static std::string toml_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '\\' || c == '"') out += '\\';
        out += c;
    }
    return out;
}

static void set_ancestry_deny(AncestryDeny* deny, pid_t pid,
                              const std::string& exe_path,
                              const std::string& profile_name,
                              const char* reason,
                              const std::vector<ObservedAncestor>& ancestors) {
    if (!deny) return;
    deny->pid = pid;
    deny->exe_path = exe_path;
    deny->profile_name = profile_name;
    deny->reason = reason;
    deny->has_blocked_ancestor = false;
    deny->ancestors = ancestors;
}

static void log_ancestry_deny(const AncestryDeny& deny) {
    if (deny.has_blocked_ancestor) {
        LOG_INFO("ANCESTRY BLOCKED: pid=%d exe=%s profile=%s "
                 "ancestor_pid=%d ancestor_exe=%s",
                 deny.pid, deny.exe_path.c_str(), deny.profile_name.c_str(),
                 deny.blocked_ancestor.pid, deny.blocked_ancestor.exe.c_str());
    }
    LOG_INFO("ANCESTRY DENY: pid=%d exe=%s profile=%s reason=%s",
             deny.pid, deny.exe_path.c_str(), deny.profile_name.c_str(),
             deny.reason);
    if (deny.ancestors.empty()) return;

    LOG_INFO("observed ancestry for candidate profile:");
    LOG_INFO("\"%s_candidate\" = [", deny.profile_name.c_str());
    for (const auto& ancestor : deny.ancestors) {
        LOG_INFO("    \"%s\",  # pid=%d",
                 toml_escape(ancestor.exe).c_str(), ancestor.pid);
    }
    LOG_INFO("]");
}

static bool ancestry_matches(pid_t pid, const std::string& exe_path,
                             const std::string& profile_name,
                             const std::vector<AllowRule>& profile,
                             AncestryDeny* deny) {
    std::vector<ObservedAncestor> ancestors;

    ProcSnapshot subject;
    if (!get_proc_snapshot(pid, subject)) {
        set_ancestry_deny(deny, pid, exe_path, profile_name,
                          "accessing process could not be validated", ancestors);
        return false;
    }
    if (subject.exe != exe_path) {
        set_ancestry_deny(deny, pid, exe_path, profile_name,
                          "accessing process exe changed", ancestors);
        return false;
    }

    pid_t cur = pid;
    for (int depth = 0; depth < 64; ++depth) {
        ProcSnapshot entry;
        if (!get_proc_snapshot(cur, entry)) {
            set_ancestry_deny(deny, pid, exe_path, profile_name,
                              "ancestor chain changed", ancestors);
            return false;
        }

        pid_t ppid = entry.ppid;
        if (ppid <= 1) return true;

        ProcSnapshot ancestor;
        if (!get_proc_snapshot(ppid, ancestor)) {
            set_ancestry_deny(deny, pid, exe_path, profile_name,
                              "ancestor could not be validated", ancestors);
            return false;
        }
        ancestors.push_back(ObservedAncestor{ppid, ancestor.exe});

        if (!entry_matches_profile(ancestor.exe, profile)) {
            set_ancestry_deny(deny, pid, exe_path, profile_name,
                              "ancestor not in profile", ancestors);
            if (deny) {
                deny->has_blocked_ancestor = true;
                deny->blocked_ancestor = ancestors.back();
            }
            return false;
        }

        cur = ppid;
    }

    set_ancestry_deny(deny, pid, exe_path, profile_name,
                      "ancestry depth limit exceeded", ancestors);
    return false;
}

bool is_exe_allowed(const std::string& exe_path, pid_t pid,
                    const std::vector<AllowRule>& allowlist) {
    if (exe_path.empty()) return false;

    AncestryDeny ancestry_deny;
    bool have_ancestry_deny = false;

    for (const auto& rule : allowlist) {
        if (!rule_matches_exe(rule, exe_path)) continue;

        // Exe matched; filters and ancestry profiles must also match if present.
        if (!rule.comm_filter.empty()) {
            std::string cmdline = get_cmdline(pid);
            if (cmdline.find(rule.comm_filter) == std::string::npos) {
                continue;
            }
        }

        if (!rule.profile_name.empty()) {
            AncestryDeny rule_deny;
            if (!ancestry_matches(pid, exe_path, rule.profile_name,
                                  rule.ancestry_profile, &rule_deny)) {
                ancestry_deny = std::move(rule_deny);
                have_ancestry_deny = true;
                continue;
            }
        }

        return true;
    }

    if (have_ancestry_deny) {
        log_ancestry_deny(ancestry_deny);
    }
    return false;
}

void resolve_builtin_profile(Config& cfg, const std::string& name,
                             const std::vector<AllowRule>& profile) {
    for (auto& wd : cfg.watched) {
        for (auto& rule : wd.allowlist) {
            if (rule.profile_name == name && rule.ancestry_profile.empty()) {
                rule.ancestry_profile = profile;
            }
        }
    }
}

std::string get_mount_point(const std::string& path) {
    fs::path p = fs::canonical(path);
    struct stat st, parent_st;

    if (stat(p.c_str(), &st) != 0) {
        throw std::runtime_error("stat failed: " + p.string());
    }

    while (p.has_parent_path() && p != p.parent_path()) {
        fs::path parent = p.parent_path();
        if (stat(parent.c_str(), &parent_st) != 0) break;
        if (parent_st.st_dev != st.st_dev) break;
        st = parent_st;
        p = parent;
    }
    return p.string();
}
