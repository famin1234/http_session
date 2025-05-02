#ifndef NET_THREAD_H
#define NET_THREAD_H


#include "list.h"
#include "rbtree.h"

#define CONN_EVENT_NONE 0
#define CONN_EVENT_READ (1 << 0)
#define CONN_EVENT_WRITE (1 << 1)
#define CONN_EVENT_TIMEOUT (1 << 2)
#define CONN_EVENT_ABORT (1 << 3)

struct conn_t;
struct net_thread_t {
    pthread_t tid;
    char name[64];
    int                efd;

    struct conn_t      *conns[2];
    int notified;
    pthread_mutex_t    mutex;
    struct list_head_t task_list;
    struct rb_root     timer_root;
    int64_t timer_expire;
    struct list_head_t active_list;
    int64_t time;
    int stop;

    int64_t            event_add;
    int64_t            event_mod;
    int64_t            event_del;
};

struct conn_t {
    struct net_thread_t *net_thread;
    int sock;
    union {
        struct sockaddr addr;
        struct sockaddr_in in;
        struct sockaddr_in6 in6;
    };
    int64_t timer_expire;
    struct rb_node     timer_node;
    struct list_head_t     active_node;
    uint32_t events;
    struct {
        int active:1;
        int read_ready:1;
        int write_ready:1;
    } flags;
    void (*handle)(struct conn_t *conn, int events);
    void *arg;
};

int conn_timer_add(struct conn_t *conn, int64_t timer_expire);
int conn_timer_mod(struct conn_t *conn, int64_t timer_expire);
int conn_timer_del(struct conn_t *conn);

int conn_events_select(struct conn_t *conn, int events);
void conn_read_ready(struct conn_t *conn, int ready);
void conn_write_ready(struct conn_t *conn, int ready);
void conn_close(struct conn_t *conn);

int net_threads_create(int n);
int net_threads_exit();

extern struct net_thread_t *net_threads;
extern int net_threads_num;

#endif
