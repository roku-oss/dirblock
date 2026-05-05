#pragma once

#include <cstdio>
#include <cstdarg>

enum class LogLevel { Quiet, Normal, Verbose };

inline LogLevel g_log_level = LogLevel::Normal;

inline void log_msg(const char* prefix, const char* fmt, ...) {
    std::va_list args;
    va_start(args, fmt);
    std::fprintf(stderr, "%s: ", prefix);
    std::vfprintf(stderr, fmt, args);
    std::fputc('\n', stderr);
    std::fflush(stderr);
    va_end(args);
}

#define LOG_ERR(fmt, ...)  log_msg("ERROR", fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) log_msg("WARN", fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...) log_msg("dirblock", fmt, ##__VA_ARGS__)
#define LOG_VERBOSE(fmt, ...) \
    do { if (g_log_level >= LogLevel::Verbose) log_msg("dirblock", fmt, ##__VA_ARGS__); } while(0)
