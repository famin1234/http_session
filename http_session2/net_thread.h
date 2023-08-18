#ifndef NET_THREAD_H
#define NET_THREAD_H

#include "os.h"

#define CONN_READ 1
#define CONN_WRITE 2
#define TIMER_PERIOD 100
#define RECURSION_MAX 4

#define EPOLL_FD_MAX 1024
#define LISTEN_MAX 1024

struct conn_t;
typedef int net_socket_t;
typedef void (*conn_handle_t)(struct conn_t *conn);

struct net_thread_t {
    pthread_t          tid;
    char               name[64];
    int                exit;
    int                efd;
    struct conn_t      *conns[2];
    struct list_head_t ready_list;
    int                ready_num;
    struct list_head_t list;
    pthread_mutex_t    mutex;
    int                signaled;
    struct rb_root     timer_root;
    struct rb_root     keepalive_root;
    int64_t            time_current;
    int64_t            timer_last;

    int64_t            event_add;
    int64_t            event_mod;
    int64_t            event_del;
};

union conn_addr_t {
    struct sockaddr addr;
    struct sockaddr_in in;
    struct sockaddr_in6 in6;
};

struct conn_t {
    net_socket_t sock;
    union conn_addr_t peer_addr;
    struct net_thread_t *net_thread;
    struct list_head_t ready_node;
    struct rb_node keepalive_node;
    struct rb_node timer_node;
    int64_t timer_expire;
    uint32_t events;
    struct {
        int read_ready:1;
        int write_ready:1;
        int in_ready_list:1;
        int read_enable:1;
        int write_enable:1;
        int timer_set:1;
        int lock:1;
        int closed:1;
    } flags;
    conn_handle_t handle_read;
    conn_handle_t handle_write;
    conn_handle_t handle_timeout;
    void *data;
};


int conn_addr_pton(union conn_addr_t *conn_addr, const char *host, unsigned short port);
const char *conn_addr_ntop(union conn_addr_t *conn_addr, char *buf, socklen_t size);
uint16_t conn_addr_port(union conn_addr_t *conn_addr);
int conn_addr_compare(const union conn_addr_t *conn_addr1, const union conn_addr_t *conn_addr2);

struct conn_t *conn_alloc(void);
void conn_close(struct conn_t *conn);
void conn_free(struct conn_t *conn);
int conn_nonblock(struct conn_t *conn);
void conn_handle(struct conn_t *conn);
void conn_enable(struct conn_t *conn, int flags);
void conn_disable(struct conn_t *conn, int flags);
void conn_ready_set(struct conn_t *conn, int flags);
void conn_ready_unset(struct conn_t *conn, int flags);
void conn_timer_set(struct conn_t *conn, int64_t timeout);
void conn_timer_unset(struct conn_t *conn);
int conn_keepalive_set(struct conn_t *conn);
struct conn_t *conn_keepalive_get(struct net_thread_t *net_thread, union conn_addr_t *peer_addr);
void conn_keepalive_unset(struct conn_t *conn);

int net_thread_event_init(struct net_thread_t *net_thread);
int net_thread_event_add(struct net_thread_t *net_thread, struct conn_t *conn, uint32_t events);
int net_thread_event_mod(struct net_thread_t *net_thread, struct conn_t *conn, uint32_t events);
int net_thread_event_del(struct net_thread_t *net_thread, struct conn_t *conn);
int net_thread_event_wait(struct net_thread_t *net_thread);
int net_thread_event_clean(struct net_thread_t *net_thread);

int net_listen_list_add(const char *host, unsigned short port, conn_handle_t handle);
void net_thread_action_callback(struct net_thread_t *net_thread, struct action_t *action);
int net_threads_create(int n);
void net_threads_join();
void net_threads_exit();

void net_thread_action_add(struct action_t *action);
void net_thread_action_call(struct action_t *action);
#endif
