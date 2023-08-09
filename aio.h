#ifndef AIO_THREAD_H
#define AIO_THREAD_H

#include "os.h"

struct aio_t;
typedef void (*aio_handle_t)(struct aio_t *);

struct aio_thread_t {
    pthread_t tid;
    char name[64];
    int  exit;
};

struct aio_t {
    struct list_head_t node;
    aio_handle_t exec;
    //aio_handle_t done;
    void *extra;
    void *net_thread;
    void *data;
};

int aio_init();
void aio_clean();

int aio_busy(struct aio_t *aio);
void aio_handle_exec(struct aio_t *aio);
void aio_handle_done(struct aio_t *aio);

int aio_thread_init(struct aio_thread_t *aio_thread);
void *aio_thread_loop(void *data);
void aio_thread_clean(struct aio_thread_t *aio_thread);
void aio_thread_signal();

#endif
