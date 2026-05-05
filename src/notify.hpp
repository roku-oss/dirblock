#pragma once

#include <chrono>
#include <string>
#include <unordered_map>
#include <unistd.h>
#include <sys/wait.h>

class Notifier {
public:
    // Rate limit: at most one notification per watched dir per interval.
    static constexpr int RATE_LIMIT_SECS = 2;

    void send_deny(const std::string& exe_name,
                   const std::string& /* exe_path */,
                   const char* target_path,
                   const std::string& watched_dir) {
        if (!enabled_) return;

        auto now = std::chrono::steady_clock::now();
        auto& last = last_notify_[watched_dir];
        if (now - last < std::chrono::seconds(RATE_LIMIT_SECS)) return;
        last = now;

        // Reap any previous child
        if (child_pid_ > 0) {
            waitpid(child_pid_, nullptr, WNOHANG);
        }

        std::string summary = "dirblock: access denied";
        std::string body = std::string(exe_name.empty() ? "unknown" : exe_name)
            + " tried to open " + (target_path ? target_path : "file")
            + " in watched directory " + watched_dir;

        // Run notify-send as the real user (sudo runs us as root,
        // but D-Bus session bus rejects root connections).
        // We need SUDO_UID for setuid and the D-Bus socket path.
        const char* sudo_uid_str = std::getenv("SUDO_UID");
        uid_t real_uid = sudo_uid_str ? static_cast<uid_t>(std::atoi(sudo_uid_str)) : getuid();
        gid_t real_gid = real_uid; // typically uid == gid

        const char* sudo_gid_str = std::getenv("SUDO_GID");
        if (sudo_gid_str) real_gid = static_cast<gid_t>(std::atoi(sudo_gid_str));

        // Build D-Bus address from UID
        char dbus_env[128];
        std::snprintf(dbus_env, sizeof(dbus_env),
                      "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%u/bus",
                      real_uid);

        child_pid_ = fork();
        if (child_pid_ == 0) {
            // Drop privileges to real user
            setgid(real_gid);
            setuid(real_uid);
            putenv(dbus_env);
            execlp("notify-send", "notify-send",
                   "--urgency=critical",
                   "--app-name=dirblock",
                   summary.c_str(),
                   body.c_str(),
                   nullptr);
            _exit(1);
        }
        // Parent continues immediately (fire-and-forget)
    }

    void set_enabled(bool e) { enabled_ = e; }

private:
    bool enabled_ = true;
    pid_t child_pid_ = -1;
    std::unordered_map<std::string,
        std::chrono::steady_clock::time_point> last_notify_;
};
