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

struct aio_thread_t {
    pthread_t         tid;
    char              name[64];
    int               exit;
};

struct aio_t {
    struct list_head_t node;
    aio_handle_t exec;
    aio_handle_t done;
    void *extra;
    void *net_thread;
    void *data;
};

extern struct aio_thread_t *aio_threads;
extern int aio_threads_num;

int aio_init();
void aio_clean();

int aio_busy(struct aio_t *aio);
void aio_handle_exec(struct aio_t *aio);
void aio_handle_done(struct aio_t *aio);

int aio_threads_run(int num);
void aio_threads_signal_exit();
int aio_threads_join();

#endif
