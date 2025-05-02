#ifndef NET_H
#define NET_H

#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <assert.h>

#include "list.h"
#include "rbtree.h"
#include "task_thread.h"

#define CONN_EVENT_NONE 0
#define CONN_EVENT_READ (1 << 0)
#define CONN_EVENT_WRITE (1 << 1)
#define CONN_EVENT_TIMEOUT (1 << 2)
#define CONN_EVENT_ABORT (1 << 3)

struct conn_t;
struct net_event_t {

    int (*init)(struct net_event_t *net_event);
    int (*mod)(struct net_event_t *net_event, struct conn_t *conn, int events);
    int (*wait)(struct net_event_t *net_event, int timeout);
    int (*uninit)(struct net_event_t *net_event);

    struct conn_t      *conns[2];
    int notified;
    pthread_mutex_t    mutex;
    struct list_head_t task_list;
    struct rb_root     timer_root;
    int64_t timer_expire;
    struct list_head_t active_list;
    int64_t time;
    int stop;


    void *sub_module;
};

struct conn_t {
    struct net_event_t *net_event;
    int sock;
    union {
        struct sockaddr addr;
        struct sockaddr_in in;
        struct sockaddr_in6 in6;
    };
    int64_t timer_expire;
    struct rb_node     timer_node;
    struct list_head_t     active_node;
    int events;
    struct {
        int active:1;
        int read_ready:1;
        int write_ready:1;
    } flags;
    void (*handle)(struct conn_t *conn, int events);
    void *arg;
};

int net_event_init(struct net_event_t *net_event);
void net_event_loop(struct net_event_t *net_event);
void net_event_uninit(struct net_event_t *net_event);

struct conn_t *conn_socket(int domain, int type, int protocol);
void conn_close(struct conn_t *conn);
int conn_nonblock(struct conn_t *conn);

int conn_timer_add(struct conn_t *conn, int64_t timer_expire);
int conn_timer_mod(struct conn_t *conn, int64_t timer_expire);
int conn_timer_del(struct conn_t *conn);

int conn_events_mod(struct conn_t *conn, int events);
void conn_read_ready(struct conn_t *conn, int ready);
void conn_write_ready(struct conn_t *conn, int ready);

#endif
