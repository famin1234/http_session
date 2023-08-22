#ifndef AIO_THREAD_H
#define AIO_THREAD_H
#include "os.h"

struct aio_thread_t {
    pthread_t tid;
    char name[64];
    int  exit;
};

int aio_threads_create(int n);
void aio_threads_join();
void aio_threads_signal();
void aio_threads_exit();

#endif
