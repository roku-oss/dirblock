#pragma once

#include <cstdint>
#include <unistd.h>
#include <linux/fanotify.h>
#include <sys/fanotify.h>

// Thin RAII wrapper for file descriptors
class ScopedFd {
public:
    explicit ScopedFd(int fd = -1) : fd_(fd) {}
    ~ScopedFd() { close(); }
    ScopedFd(const ScopedFd&) = delete;
    ScopedFd& operator=(const ScopedFd&) = delete;
    ScopedFd(ScopedFd&& o) noexcept : fd_(o.fd_) { o.fd_ = -1; }
    ScopedFd& operator=(ScopedFd&& o) noexcept {
        close();
        fd_ = o.fd_;
        o.fd_ = -1;
        return *this;
    }
    int get() const { return fd_; }
    int release() { int f = fd_; fd_ = -1; return f; }
    void close() { if (fd_ >= 0) { ::close(fd_); fd_ = -1; } }
    explicit operator bool() const { return fd_ >= 0; }
private:
    int fd_;
};

struct FanEvent {
    uint64_t mask;
    int fd;      // file descriptor for the accessed file — caller must close
    int pid;
};

// Initialize fanotify. Returns fd or throws.
int fan_init();

// Mark a mount point for FAN_OPEN_PERM events. Throws on error.
void fan_mark_mount(int fan_fd, const char* path);

// Read events from fanotify fd into buf. Returns number of events parsed.
// Caller must respond to each event and close the fd.
int fan_read_events(int fan_fd, FanEvent* events, int max_events);

// Write allow/deny response for a permission event.
void fan_respond(int fan_fd, int event_fd, bool allow);
