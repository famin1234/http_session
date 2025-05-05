#ifndef MEM_H
#define MEM_H

#include <stdio.h>
#include <stddef.h>

struct string_t {
    char *buf;
    size_t size;
    size_t len;
};

void *mem_malloc(size_t size);
void *mem_realloc(void *ptr, size_t size);
char *mem_strdup(const char *s);
void mem_free(void *ptr);

#define string_buf(string) ((string)->buf)
#define string_size(string) ((string)->size)
#define string_len(string) ((string)->len)
#define string_null {}

void string_init(struct string_t *string, size_t size);
void string_strcat(struct string_t *string, const char *s);
void string_strncat(struct string_t *string, const char *s, size_t len);
void string_sprintf(struct string_t *string, const char *format, ...);
void string_uninit(struct string_t *string);

#endif
