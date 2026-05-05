#pragma once

#include <string>
#include <vector>
#include <unistd.h>

// Allowlist rule: may have optional cmdline filter and ancestry profile.
// Example: "claude-hud:~/.bun/bin/bun;desktop_shell" parses to:
//   path="<expanded>~/.bun/bin/bun"
//   comm_filter="claude-hud" (cmdline substring to match)
//   profile_name="desktop_shell" (ancestors must match this profile)
//   is_prefix=false
struct AllowRule {
    std::string path;           // expanded path
    std::string comm_filter;    // empty if no filter, otherwise substring to find in cmdline
    bool is_prefix = false;     // true if path ends with /
    std::string profile_name;   // empty if no ancestry profile
    std::vector<AllowRule> ancestry_profile; // path-only ancestor rules
};

struct WatchedDir {
    std::string path;                       // resolved absolute path
    std::vector<AllowRule> allowlist;       // pre-parsed allow rules
};

struct Config {
    bool notify = true;
    std::vector<WatchedDir> watched;
};

// Get the real user's home directory (SUDO_USER-aware).
std::string get_real_home();

// Load config from TOML file. Expands ~ to real user home (SUDO_USER-aware).
// Throws std::runtime_error on failure.
Config load_config(const std::string& path);

// Find the watched dir that fd_path falls under, or nullptr.
const WatchedDir* find_watched_dir(const char* fd_path,
                                    const std::vector<WatchedDir>& watched);

// Check if exe_path is allowed by the allowlist.
// Pre-parsed allowlist rules support both exact and prefix matches.
// Filters and ancestry profiles must also match when present.
bool is_exe_allowed(const std::string& exe_path, pid_t pid,
                    const std::vector<AllowRule>& allowlist);

// Fill unresolved rules for a generated built-in profile.
void resolve_builtin_profile(Config& cfg, const std::string& name,
                             const std::vector<AllowRule>& profile);

// Get the mount point for a given path.
std::string get_mount_point(const std::string& path);
