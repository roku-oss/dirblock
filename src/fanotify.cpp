#include "fanotify.hpp"
#include "log.hpp"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <stdexcept>
#include <unistd.h>

int fan_init() {
    int fd = fanotify_init(
        FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_UNLIMITED_QUEUE,
        O_RDONLY);
    if (fd < 0) {
        throw std::runtime_error(
            std::string("fanotify_init: ") + std::strerror(errno));
    }
    return fd;
}

void fan_mark_mount(int fan_fd, const char* path) {
    int ret = fanotify_mark(fan_fd,
        FAN_MARK_ADD | FAN_MARK_MOUNT,
        FAN_OPEN_PERM,
        AT_FDCWD, path);
    if (ret < 0) {
        throw std::runtime_error(
            std::string("fanotify_mark(") + path + "): " + std::strerror(errno));
    }
}

int fan_read_events(int fan_fd, FanEvent* events, int max_events) {
    alignas(struct fanotify_event_metadata)
    char buf[4096];

    // Cap read size so we never pull more events than we can process.
    // Unprocessed FAN_OPEN_PERM events would hang the calling processes.
    size_t max_bytes = static_cast<size_t>(max_events) * sizeof(struct fanotify_event_metadata);
    size_t read_size = max_bytes < sizeof(buf) ? max_bytes : sizeof(buf);

    ssize_t len = read(fan_fd, buf, read_size);
    if (len <= 0) return 0;

    int count = 0;
    auto* meta = reinterpret_cast<struct fanotify_event_metadata*>(buf);

    while (FAN_EVENT_OK(meta, len) && count < max_events) {
        if (meta->vers != FANOTIFY_METADATA_VERSION) {
            LOG_ERR("fanotify metadata version mismatch");
            break;
        }
        events[count].mask = meta->mask;
        events[count].fd = meta->fd;
        events[count].pid = meta->pid;
        ++count;
        meta = FAN_EVENT_NEXT(meta, len);
    }
    return count;
}

void fan_respond(int fan_fd, int event_fd, bool allow) {
    struct fanotify_response resp;
    resp.fd = event_fd;
    resp.response = allow ? FAN_ALLOW : FAN_DENY;
    ssize_t ret = write(fan_fd, &resp, sizeof(resp));
    if (ret < 0) {
        LOG_ERR("fanotify response write failed: %s", std::strerror(errno));
    }
}
