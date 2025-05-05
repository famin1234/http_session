#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include "mem.h"

void *mem_malloc(size_t size)
{
    return malloc(size);
}

void mem_free(void *ptr)
{
    free(ptr);
}

void *mem_realloc(void *ptr, size_t size)
{
    return realloc(ptr, size);
}

char *mem_strdup(const char *s)
{
    char *dest;
    size_t size = strlen(s) + 1;

    dest = (char *)mem_malloc(size);
    memcpy(dest, s, size);
    return dest;
}

void string_init(struct string_t *string, size_t size)
{
    string->buf = mem_malloc(size);
    string->buf[0] = '\0';
    string->size = size;
    string->len = 0;
}

void string_strcat(struct string_t *string, const char *s)
{
    string_strncat(string, s, strlen(s));
}

void string_strncat(struct string_t *string, const char *s, size_t len)
{
    size_t size;

    if (string->size - string->len <= len) {
        size = string->size;
        while (size <= string->len + len) size <<= 1;
        string->buf = mem_realloc(string->buf, size);
            string->size = size;
    }
    memcpy(string->buf + string->len, s, len);
    string->len += len;
    string->buf[string->len] = '\0';
}

void string_sprintf(struct string_t *string, const char *format, ...)
{
    int n;
    size_t size;
    va_list ap;

    while (1) {
        va_start(ap, format);
        n = vsnprintf(string->buf + string->len, string->size - string->len, format, ap);
        va_end(ap);
        if (n > -1 && n < string->size - string->len) {
            string->len += n;
            break;
        }
        size = string->size;
        if (n > -1) {
            while (size <= string->len + n) size <<= 1;
        } else {
            size <<= 1;
        }
        string->buf = mem_realloc(string->buf, size);
            string->size = size;
    }
}

void string_uninit(struct string_t *string)
{
    mem_free(string->buf);
    string->buf = NULL;
    string->size = 0;
    string->len = 0;
}
