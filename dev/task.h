#ifndef TASK_H
#define TASK_H

#include "list.h"

struct task_t {
    struct list_head_t node;
    void (*handle)(struct task_t *);
    void *arg;
};

#endif
