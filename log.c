#include "os.h"
#include "log.h"

static __thread char thread_name[64] = {0};

void log_thread_name(const char *name)
{
    strncpy(thread_name, name, sizeof(thread_name));
}

void log_printf(int level, const char *file, int line, const char *function, const char *fmt, ...)
{
    if (level >= LOG_DEBUG) {
        return;
    }
    va_list argptr;
    struct timeval tv;
    struct tm tm;
    gettimeofday(&tv, NULL);
    localtime_r(&tv.tv_sec, &tm);
    printf("%d/%02d/%02d %02d:%02d:%02d.%06ld %s %s:%d|%s: ",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, (long)tv.tv_usec, thread_name, file, line, function);
    va_start(argptr, fmt);
    vprintf(fmt, argptr);
    va_end(argptr);
}

