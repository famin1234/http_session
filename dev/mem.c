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
