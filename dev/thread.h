#ifndef TASK_H
#define TASK_H

#include <unistd.h>
#define _GNU_SOURCE
#include <pthread.h>

#include "list.h"

extern int pthread_setname_np (pthread_t __target_thread, const char *__name);

struct task_t {
    struct list_head_t node;
    void (*handle)(struct task_t *);
    void *data;
};

struct thread_t {
    pthread_t tid;
    char name[64];
    void *data;
};

int threads_init();
int threads_run();
int threads_uninit();

extern struct thread_t *net_threads;
extern int net_threads_num;
extern struct thread_t *task_threads;
extern int task_threads_num;

#endif
