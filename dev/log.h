#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <errno.h>
#include <string.h>

#define LOG(level, ...) do {if (level <= LOG_DEBUG) log_print(level, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__);} while(0)

enum {
    LOG_NONE,
    LOG_ERROR,
    LOG_WARNING,
    LOG_INFO,
    LOG_DEBUG
};

void log_set_thread_name(const char *name);
void log_print(int level, const char *file, int line, const char *function, const char *format, ...);

#endif
