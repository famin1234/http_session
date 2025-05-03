#ifndef NET_THREAD_H
#define NET_THREAD_H

#include <pthread.h>
#include "task.h"
#include "net.h"

struct net_thread_t {
    pthread_t tid;
    char name[64];
    struct net_loop_t net_loop;
};

int net_threads_create(int n);
int net_threads_exit();

extern struct net_thread_t *net_threads;
extern int net_threads_num;

#endif
