#ifndef ATOMIC_STACK_H
#define ATOMIC_STACK_H

#include "os.h"

#if __SIZEOF_POINTER__ == 4
typedef int32_t version_type_t;
typedef int64_t data_type_t;
#define ATOMIC_HEAD_NODE(_h) (_h).node
#define ATOMIC_HEAD_VERSION(_h) (_h).version
#define ATOMIC_HEAD_SET(_h, _n, _v) \
    (_h).node = (_n); \
(_h).version = (_v);

#elif __SIZEOF_POINTER__ == 8
#if HAS_128BIT_CAS
typedef int64_t version_type_t;
typedef __int128_t data_type_t;
#define ATOMIC_HEAD_NODE(_h) (_h).node
#define ATOMIC_HEAD_VERSION(_h) (_h).version
#define ATOMIC_HEAD_SET(_h, _n, _v) \
    (_h).node = (_n); \
(_h).version = (_v);

#else
typedef int64_t version_type_t;
typedef int64_t data_type_t;
#define ATOMIC_HEAD_NODE(_h) ((struct atomic_node_t *)(((((intptr_t)(_h).data) << 16) >> 16) | (((~((((intptr_t)(_h).data) << 16 >> 63) - 1)) >> 48) << 48))) // sign extend
#define ATOMIC_HEAD_VERSION(_h) (((intptr_t)(_h).data) >> 48)
#define ATOMIC_HEAD_SET(_h, _n, _v) (_h).data = ((((intptr_t)(_n)) & 0x0000FFFFFFFFFFFFULL) | (((_v) & 0xFFFFULL) << 48))
#endif
#endif

struct atomic_node_t {
    struct atomic_node_t *next;
};

struct atomic_head_t {
    union {
        struct {
            struct atomic_node_t *node;
#if !ATOMIC_STACK_SPINLOCK
            version_type_t version;
#endif
        };
#if !ATOMIC_STACK_SPINLOCK
        data_type_t data;
#endif
    };
};

struct atomic_stack_t {
#if ATOMIC_STACK_SPINLOCK
    pthread_spinlock_t spinlock;
#endif
    struct atomic_head_t head;
};

void atomic_stack_init(struct atomic_stack_t *atomic_stack);
void atomic_stack_push(struct atomic_stack_t *atomic_stack, struct atomic_node_t *node);
struct atomic_node_t *atomic_stack_pop(struct atomic_stack_t *atomic_stack);
void atomic_stack_clean(struct atomic_stack_t *atomic_stack);

#endif
