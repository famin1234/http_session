#ifndef OS_H
#define OS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <assert.h>
#include <time.h>
#include <inttypes.h>

#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <sys/epoll.h>
#include <pthread.h>

#include "list.h"
#include "rbtree.h"
#include "atomic_stack.h"

struct action_t;
typedef void (*action_handle_t)(struct action_t *);
struct action_t {
    struct list_head_t node;
    action_handle_t handle;
    action_handle_t callback;
    void *net_thread;
    void *data;
    void *extra;
};

struct module_t {
    int (*module_init)(struct module_t *module);
    int (*module_clean)(struct module_t *module);
    int (*net_thread_init)(struct module_t *module);
    int (*net_thread_clean)(struct module_t *module);
};

#endif
