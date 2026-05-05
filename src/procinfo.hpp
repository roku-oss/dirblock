#pragma once

#include <cstdlib>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <utility>
#include <linux/limits.h>
#include <unistd.h>

struct ProcSnapshot {
    pid_t ppid = -1;
    unsigned long long starttime = 0;
    std::string exe;
};

// Resolve /proc/<pid>/exe to the real binary path.
// Returns empty string on failure.
inline std::string get_exe_path(pid_t pid) {
    char buf[PATH_MAX];
    char link[64];
    std::snprintf(link, sizeof(link), "/proc/%d/exe", pid);
    ssize_t len = readlink(link, buf, sizeof(buf) - 1);
    if (len <= 0) return {};
    buf[len] = '\0';
    // Strip " (deleted)" suffix if binary was replaced
    std::string path(buf, static_cast<size_t>(len));
    const char* suffix = " (deleted)";
    if (path.size() > 10 && path.compare(path.size() - 10, 10, suffix) == 0) {
        path.resize(path.size() - 10);
    }
    return path;
}

// Read stable identity fields from /proc/<pid>/stat.
// starttime distinguishes reused PIDs; ppid anchors the current ancestry walk.
inline bool get_proc_stat_identity(pid_t pid, pid_t& ppid,
                                   unsigned long long& starttime) {
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    std::ifstream in(path);
    if (!in.is_open()) return false;

    std::string line;
    if (!std::getline(in, line)) return false;

    size_t end_comm = line.rfind(") ");
    if (end_comm == std::string::npos) return false;

    std::istringstream fields(line.substr(end_comm + 2));
    std::string token;
    pid_t parsed_ppid = -1;
    unsigned long long parsed_starttime = 0;

    for (int index = 0; fields >> token; ++index) {
        if (index == 1) {
            parsed_ppid = static_cast<pid_t>(std::strtol(token.c_str(), nullptr, 10));
        } else if (index == 19) {
            parsed_starttime = std::strtoull(token.c_str(), nullptr, 10);
            break;
        }
    }

    if (parsed_ppid < 0 || parsed_starttime == 0) return false;
    ppid = parsed_ppid;
    starttime = parsed_starttime;
    return true;
}

inline bool get_proc_snapshot(pid_t pid, ProcSnapshot& snapshot) {
    pid_t ppid_before = -1;
    pid_t ppid_after = -1;
    unsigned long long start_before = 0;
    unsigned long long start_after = 0;

    if (!get_proc_stat_identity(pid, ppid_before, start_before)) return false;
    std::string exe = get_exe_path(pid);
    if (exe.empty()) return false;
    if (!get_proc_stat_identity(pid, ppid_after, start_after)) return false;
    if (start_before != start_after || ppid_before != ppid_after) return false;

    snapshot.ppid = ppid_before;
    snapshot.starttime = start_before;
    snapshot.exe = std::move(exe);
    return true;
}

// Resolve /proc/self/fd/<fd> to the file path.
// Writes into caller-provided buffer, returns pointer to buf or nullptr.
inline const char* get_fd_path(int fd, char* buf, size_t bufsz) {
    char link[64];
    std::snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t len = readlink(link, buf, bufsz - 1);
    if (len <= 0) return nullptr;
    buf[len] = '\0';
    return buf;
}

// Read /proc/<pid>/comm and return the process command name.
// Returns empty string on failure.
inline std::string get_comm(pid_t pid) {
    char buf[256];  // comm is max 15 bytes + newline, leave room
    char link[64];
    std::snprintf(link, sizeof(link), "/proc/%d/comm", pid);
    FILE* f = fopen(link, "r");
    if (!f) return {};
    if (fgets(buf, sizeof(buf), f)) {
        fclose(f);
        std::string result(buf);
        // trim trailing newline
        if (!result.empty() && result.back() == '\n') {
            result.pop_back();
        }
        return result;
    }
    fclose(f);
    return {};
}

// Read /proc/<pid>/cmdline and return as space-separated string.
// Returns empty string on failure.
inline std::string get_cmdline(pid_t pid) {
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    FILE* f = fopen(path, "r");
    if (!f) return {};

    char buf[4096];
    size_t len = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);

    if (len == 0) return {};
    buf[len] = '\0';

    // Replace null bytes with spaces
    for (size_t i = 0; i < len; ++i) {
        if (buf[i] == '\0') buf[i] = ' ';
    }

    std::string result(buf);
    // trim trailing spaces
    while (!result.empty() && result.back() == ' ') {
        result.pop_back();
    }
    return result;
}
