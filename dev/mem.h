#ifndef MEM_H
#define MEM_H

#include <stddef.h>

void *mem_malloc(size_t size);
void *mem_realloc(void *ptr, size_t size);
char *mem_strdup(const char *s);
void mem_free(void *ptr);

#endif
