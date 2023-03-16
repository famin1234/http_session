#ifndef AIO_THREAD_H
#define AIO_THREAD_H

#include "os.h"

struct aio_t;
typedef void (*aio_handle_t)(struct aio_t *);


struct aio_list_t {
    struct list_head_t list;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
};

struct aio_loop_t {
    char name[64];
    int  exit;
};

struct aio_t {
    struct list_head_t node;
    aio_handle_t exec;
    aio_handle_t done;
    void *extra;
    void *net_loop;
    void *data;
};

int aio_init();
void aio_clean();

int aio_busy(struct aio_t *aio);
void aio_handle_exec(struct aio_t *aio);
void aio_handle_done(struct aio_t *aio);

int aio_loop_init(struct aio_loop_t *aio_loop);
void *aio_loop_loop(void *data);
void aio_loop_clean(struct aio_loop_t *aio_loop);
void aio_loop_signal();

#endif
