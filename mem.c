#include "os.h"
#include "log.h"
#include "mem.h"

struct mem_pool_t {
    size_t  mem_size;
    int64_t mem_count;
    int64_t alloc_count;
    int64_t free_count;
    struct atomic_stack_t atomic_stack;
};

struct mem_node_t {
    struct atomic_node_t node; // must be first
    size_t  mem_size;
};

#if MEM_POOL
static struct mem_pool_t mem_pools[MEM_MAX_SIZE / MEM_GROW_SIZE];
#endif

int mem_pools_init()
{
#if MEM_POOL
    size_t i;
    struct mem_pool_t *mem_pool;

    for (i = 0; i < sizeof(mem_pools) / sizeof(struct mem_pool_t); i++) {
        mem_pool = &mem_pools[i];
        mem_pool->mem_size = (i + 1) * MEM_GROW_SIZE;
        atomic_stack_init(&mem_pool->atomic_stack);
    }
#endif
    return 0;
}

void mem_pools_clean()
{
#if MEM_POOL
    struct mem_pool_t *mem_pool;
    struct mem_node_t *mem_node;
    size_t i;

    LOG(LOG_INFO, "%-20s | %-20s | %-20s | %-20s | %-20s\n", "mem_size", "mem_count", "alloc_count", "free_count", "leak_count");
    LOG(LOG_INFO, "---------------------|----------------------|----------------------|----------------------|----------------------\n");
    for (i = 0; i < sizeof(mem_pools) / sizeof(struct mem_pool_t); i++) {
        mem_pool = &mem_pools[i];
        if (mem_pool->mem_count > 0) {
            LOG(LOG_INFO, "%-20zd | %-20"PRId64" | %-20"PRId64" | %-20"PRId64" | %-20"PRId64"\n",
                    mem_pool->mem_size, mem_pool->mem_count, mem_pool->alloc_count, mem_pool->free_count, mem_pool->alloc_count - mem_pool->free_count);
        }
        while ((mem_node = (struct mem_node_t *)atomic_stack_pop(&mem_pool->atomic_stack))) {
            free(mem_node);
            __sync_fetch_and_sub(&mem_pool->mem_count, 1);
        }
        atomic_stack_clean(&mem_pool->atomic_stack);
    }
    LOG(LOG_INFO, "---------------------|----------------------|----------------------|----------------------|----------------------\n");
#endif
}

void *mem_malloc(size_t size)
{
#if MEM_POOL
    struct mem_pool_t *mem_pool;
    struct mem_node_t *mem_node;

    if (!size) {
        return NULL;
    }
    if (size <= MEM_MAX_SIZE) {
        mem_pool = &mem_pools[(size - 1) >> MEM_GROW_SHIFT];
    } else {
        mem_pool = NULL;
    }
    if (mem_pool) {
        assert(size <= mem_pool->mem_size);
        mem_node = (struct mem_node_t *)atomic_stack_pop(&mem_pool->atomic_stack);
        if (!mem_node) {
            mem_node = malloc(sizeof(struct mem_node_t) + mem_pool->mem_size);
            if (!mem_node) {
                return NULL;
            }
            mem_node->mem_size = mem_pool->mem_size;
            __sync_fetch_and_add(&mem_pool->mem_count, 1);
        }
        __sync_fetch_and_add(&mem_pool->alloc_count, 1);
        return (void *)mem_node + sizeof(struct mem_node_t);
    }
    mem_node = malloc(sizeof(struct mem_node_t) + size);
    if (!mem_node) {
        return NULL;
    }
    mem_node->mem_size = size;
    return (void *)mem_node + sizeof(struct mem_node_t);
#else
    return malloc(size);
#endif
}

void mem_free(void *ptr)
{
#if MEM_POOL
    struct mem_node_t *mem_node;
    struct mem_pool_t *mem_pool;

    if (!ptr) {
        return;
    }
    mem_node = ptr - sizeof(struct mem_node_t);
    if (mem_node->mem_size <= MEM_MAX_SIZE) {
        mem_pool = &mem_pools[(mem_node->mem_size - 1) >> MEM_GROW_SHIFT];
    } else {
        mem_pool = NULL;
    }
    if (mem_pool) {
        assert(mem_node->mem_size == mem_pool->mem_size);
        __sync_fetch_and_add(&mem_pool->free_count, 1);
        atomic_stack_push(&mem_pool->atomic_stack, (struct atomic_node_t *)mem_node);
    } else {
        free(mem_node);
    }
#else
    free(ptr);
#endif
}

void *mem_realloc(void *ptr, size_t size)
{
#if MEM_POOL
    struct mem_node_t *mem_node;
    void *ptr2;

    if (!ptr) {
        return mem_malloc(size);
    }
    if (!size) {
        mem_free(ptr);
        return NULL;
    }
    mem_node = ptr - sizeof(struct mem_node_t);
    if (mem_node->mem_size >= size) {
        return ptr;
    }
    ptr2 = mem_malloc(size);
    if (ptr2) {
        memcpy(ptr2, ptr, mem_node->mem_size);
    }
    mem_free(ptr);
    return ptr2;
#else
    return realloc(ptr, size);
#endif
}

char *mem_strdup(const char *s)
{
    char *dest;

    dest = mem_malloc(strlen(s) + 1);
    if (dest) {
        strcpy(dest, s);
    }
    return dest;
}

int string_init(struct string_t *string, size_t size)
{
    string->size = size;
    string->len = 0;
    string->buf = mem_malloc(size);
    if (string->buf) {
        string->buf[0] = '\0';
        return 0;
    }
    return -1;
}

int string_strcat(struct string_t *string, const char *s)
{
    return string_strncat(string, s, strlen(s));
}

int string_strncat(struct string_t *string, const char *s, size_t len)
{
    size_t size;

    if (string->size - string->len <= len) {
        size = string->size;
        while (size <= string->len + len) size <<= 1;
        string->buf = mem_realloc(string->buf, size);
        if (string->buf) {
            string->size = size;
        } else {
            return -1;
        }
    }
    memcpy(string->buf + string->len, s, len);
    string->len += len;
    string->buf[string->len] = '\0';
    return 0;
}

int string_sprint(struct string_t *string, const char *format, ...)
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
        if (string->buf) {
            string->size = size;
        } else {
            return -1;
        }
    }
    return 0;
}

void string_clean(struct string_t *string)
{
    mem_free(string->buf);
    string->buf = NULL;
    string->size = string->len = 0;
}

void fifo_init(struct fifo_t *fifo, size_t size)
{
    assert(is_power_of_2(size));
    fifo->datas = mem_malloc(size * sizeof(void*));
    fifo->size = size;
    fifo->in = 0;
    fifo->out = 0;
}

size_t fifo_size(struct fifo_t *fifo)
{
    return fifo->size;
}

size_t fifo_len(struct fifo_t *fifo)
{
    return fifo->in - fifo->out;
}

void fifo_push_tail(struct fifo_t *fifo, void *data)
{
    assert(fifo_len(fifo) < fifo->size);
    fifo->datas[fifo->in & (fifo->size - 1)] = data;
    fifo->in++;
}

void fifo_pop_head(struct fifo_t *fifo)
{
    assert(0 < fifo_len(fifo));
    fifo->datas[fifo->out & (fifo->size - 1)] = NULL;
    fifo->out++;
}

void *fifo_head(struct fifo_t *fifo)
{
    if (0 < fifo_len(fifo)) {
        return fifo->datas[fifo->out & (fifo->size - 1)];
    } else {
        return NULL;
    }
}

void *fifo_tail(struct fifo_t *fifo)
{
    if (0 < fifo_len(fifo)) {
        return fifo->datas[(fifo->in - 1) & (fifo->size - 1)];
    } else {
        return NULL;
    }
}

void *fifo_get(struct fifo_t *fifo, size_t index)
{
    if (index < fifo_len(fifo)) {
        return fifo->datas[(fifo->out + index) & (fifo->size - 1)];
    } else {
        assert(index == fifo_len(fifo));
    }
    return NULL;
}

void fifo_clean(struct fifo_t *fifo)
{
    mem_free(fifo->datas);
    fifo->size = 0;
    fifo->in = 0;
    fifo->out = 0;
}

void mem_performance_test()
{
    void *p[100];
    int i, j;

    for (i = 0; i < 100000; i++) {
        for (j = 0; j < sizeof(p) / sizeof(void*); j++) {
            p[j] = mem_malloc(4096);
        }
        for (j = 0; j < sizeof(p) / sizeof(void*); j++) {
            mem_free(p[j]);
        }
    }
}
