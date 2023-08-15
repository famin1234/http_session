#ifndef ACTION_H
#define ACTION_H

#include "os.h"

struct action_t {
    struct list_head_t node;
    void (*handle)(struct action_t *);
    void (*callback)(struct action_t *);
    void *net_thread;
    void *data;
};

#endif
