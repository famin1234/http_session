#ifndef MEM_H
#define MEM_H

#include "os.h"

#define is_power_of_2(x)    ((x) != 0 && (((x) & ((x) - 1)) == 0))
#define MEM_GROW_SHIFT 3
#define MEM_GROW_SIZE (1 << (MEM_GROW_SHIFT))
#define MEM_MAX_SIZE  (65536 / (MEM_GROW_SIZE) * (MEM_GROW_SIZE))

struct string_t {
    size_t size;
    size_t len;
    char *buf;
};

struct fifo_t {
    void **datas;
    size_t size;
    size_t in;
    size_t out;
};

int mem_pools_init();
void mem_pools_clean();

void *mem_malloc(size_t size);
void *mem_realloc(void *ptr, size_t size);
char *mem_strdup(const char *s);
void mem_free(void *ptr);

#define string_buf(string) ((string)->buf)
#define string_size(string) ((string)->size)
#define string_len(string) ((string)->len)
#define string_null { 0, 0, NULL}

int  string_init(struct string_t *string, size_t size);
int  string_strcat(struct string_t *string, const char *s);
int  string_strncat(struct string_t *string, const char *s, size_t len);
int  string_sprint(struct string_t *string, const char *format, ...);
void string_clean(struct string_t *string);

void   fifo_init(struct fifo_t *fifo, size_t size);
size_t fifo_size(struct fifo_t *fifo);
size_t fifo_len(struct fifo_t *fifo);
void   fifo_push_tail(struct fifo_t *fifo, void *data);
void   fifo_pop_head(struct fifo_t *fifo);
void   *fifo_head(struct fifo_t *fifo);
void   *fifo_tail(struct fifo_t *fifo);
void   *fifo_get(struct fifo_t *fifo, size_t index);
void   fifo_clean(struct fifo_t *fifo);

void mem_performance_test();

#endif
