#ifndef CONN_H
#define CONN_H

#include "os.h"
#include "aio.h"

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
    struct list_head_t done_list;
    pthread_mutex_t    done_mutex;
    int                signaled;
    struct rb_root     timer_root;
    struct rb_root     keepalive_root;
    int64_t            time_current;
    int64_t            timer_last;

    int64_t            event_add;
    int64_t            event_mod;
    int64_t            event_del;
};

struct conn_addr_t {
    union {
        struct sockaddr addr;
        struct sockaddr_in in;
        struct sockaddr_in6 in6;
    };
    socklen_t addrlen;
};

struct net_listen_t {
    struct conn_addr_t conn_addr;
    conn_handle_t handle;
    struct list_head_t node;
};

struct conn_t {
    net_socket_t sock;
    struct conn_addr_t peer_addr;
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
    } flag;
    conn_handle_t handle_read;
    conn_handle_t handle_write;
    conn_handle_t handle_timeout;
    void *data;
};

extern struct net_thread_t *net_threads;
extern int net_threads_num;

int net_init();
void net_clean();

int net_listen_list_add(const char *host, unsigned short port, conn_handle_t handle);

int conn_addr_pton(struct conn_addr_t *conn_addr, const char *host, unsigned short port);
const char *conn_addr_ntop(struct conn_addr_t *conn_addr, char *buf, socklen_t size);
uint16_t conn_addr_port(struct conn_addr_t *conn_addr);
int conn_addr_compare(const struct conn_addr_t *conn_addr1, const struct conn_addr_t *conn_addr2);

struct conn_t *conn_alloc(void);
void conn_close(struct conn_t *conn);
void conn_free(struct conn_t *conn);
int conn_nonblock(struct conn_t *conn);
void conn_handle(struct conn_t *conn);
void conn_enable(struct conn_t *conn, int flag);
void conn_disable(struct conn_t *conn, int flag);
void conn_ready_set(struct conn_t *conn, int flag);
void conn_ready_unset(struct conn_t *conn, int flag);
void conn_timer_set(struct conn_t *conn, int64_t timeout);
void conn_timer_unset(struct conn_t *conn);
int conn_keepalive_set(struct conn_t *conn);
struct conn_t *conn_keepalive_get(struct net_thread_t *net_thread, struct conn_addr_t *peer_addr);
void conn_keepalive_unset(struct conn_t *conn);

void net_thread_aio_add(struct aio_t *aio);
int net_threads_run(int num);
void net_threads_signal_exit();
void net_threads_join();

#endif
