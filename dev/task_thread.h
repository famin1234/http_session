#ifndef THREAD_H
#define THREAD_H

#include <pthread.h>
#include "task.h"
#include "net.h"

extern int pthread_setname_np (pthread_t __target_thread, const char *__name);

struct task_thread_t {
    pthread_t tid;
    char name[64];
};

int task_threads_create(int n);
int task_threads_post(struct task_t *task);
int task_threads_exit();

extern struct task_thread_t *task_threads;
extern int task_threads_num;

#endif
