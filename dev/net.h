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
#include "thread.h"

#define CONN_EVENT_NONE 0
#define CONN_EVENT_READ (1 << 0)
#define CONN_EVENT_WRITE (1 << 1)
#define CONN_EVENT_TIMEOUT (1 << 2)
#define CONN_EVENT_ABORT (1 << 3)

enum {
    CONN_OK,
    CONN_EAGIN,
    CONN_ERR,
};

struct conn_t;

struct net_handle_t {
    struct conn_t *conns[2];
    struct list_head_t listen_list;
    struct list_head_t task_list;
    struct list_head_t active_list;
    struct rb_root timer_root;
    int64_t timer_expire;
    int64_t time;
    int notified;
    pthread_mutex_t mutex;

    int epoll_fd;
    int64_t event_add;
    int64_t event_mod;
    int64_t event_del;

    int exit;
    void *data;
};

struct conn_addr_t {
    union {
        struct sockaddr addr;
        struct sockaddr_in in;
        struct sockaddr_in6 in6;
    };
};

struct conn_t {
    int sock;
    struct conn_addr_t addr;
    struct net_handle_t *net_handle;
    int64_t timer_expire;
    struct rb_node timer_node;
    struct list_head_t active_node;
    int events;
    struct {
        int active:1;
        int read_ready:1;
        int write_ready:1;
        int read_enable:1;
        int write_enable:1;
    } flags;
    int (*handle_read)(struct conn_t *conn);
    int (*handle_write)(struct conn_t *conn);
    int (*handle_timeout)(struct conn_t *conn);
    void *data;
};

int net_handle_init(struct net_handle_t *net_handle);
void net_handle_uninit(struct net_handle_t *net_handle);
void net_handle_loop(struct net_handle_t *net_handle);
int net_handle_post(struct net_handle_t *net_handle, struct task_t *task);
int net_handle_listen(struct net_handle_t *net_handle, struct conn_addr_t *addr, struct conn_t **conn_listen);

int conn_accept(struct conn_t *conn_listen, struct conn_t **conn_accept);
void conn_close(struct conn_t *conn);

int conn_events_add(struct conn_t *conn, int events);
int conn_events_del(struct conn_t *conn, int events);
void conn_read_ready(struct conn_t *conn, int ready);
void conn_write_ready(struct conn_t *conn, int ready);

int conn_timer_add(struct conn_t *conn, int timeout);
int conn_timer_mod(struct conn_t *conn, int timeout);
int conn_timer_del(struct conn_t *conn);

int conn_nonblock(struct conn_t *conn);

int conn_addr_pton(struct conn_addr_t *addr, const char *host, unsigned short port);
const char *conn_addr_ntop(const struct conn_addr_t *addr, char *dst, size_t size);

#endif
