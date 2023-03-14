#ifndef LOG_H
#define LOG_H

#define LOG_ERROR 0
#define LOG_WARNING 1
#define LOG_INFO 2
#define LOG_DEBUG 3

void log_file_open();
void log_file_close();

void log_thread_name(const char *name);
void log_printf(int level, const char *file, int line, const char *function, const char *fmt, ...);
#define LOG(level, ...) log_printf(level, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__)

#endif
