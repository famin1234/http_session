#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/time.h>
#include "mem.h"
#include "log.h"
#include "net_epoll.h"
#include "net.h"

#define LISTEN_MAX 1024
#define TIMER_PERIOD 100
#define ABS(x) (x >= 0 ? x : x)

int conn_addr_pton(struct conn_addr_t *conn_addr, const char *host, unsigned short port)
{
    int ret;

    ret = inet_pton(AF_INET, host, &conn_addr->in.sin_addr);
    if (ret > 0) {
        conn_addr->in.sin_family = AF_INET;
        conn_addr->in.sin_port = htons(port);
        return ret;
    }
    ret = inet_pton(AF_INET6, host, &conn_addr->in6.sin6_addr);
    if (ret > 0) {
        conn_addr->in6.sin6_family = AF_INET6;
        conn_addr->in6.sin6_port = htons(port);
        conn_addr->in6.sin6_flowinfo = 0;
        conn_addr->in6.sin6_scope_id = 0;
        return ret;
    }
    return ret;
}

const char *conn_addr_ntop(const struct conn_addr_t *conn_addr, char *dst, size_t size)
{
    size_t len;
    if (conn_addr->addr.sa_family == AF_INET) {
        inet_ntop(AF_INET, &conn_addr->in.sin_addr, dst, size);
        len = strlen(dst);
        snprintf(dst + len, size - len, ":%d", ntohs(conn_addr->in.sin_port));
    } else if (conn_addr->addr.sa_family == AF_INET6) {
        inet_ntop(AF_INET6, &conn_addr->in6.sin6_addr, dst, size);
        len = strlen(dst);
        snprintf(dst + len, size - len, ":%d", ntohs(conn_addr->in6.sin6_port));
    } else {
        return NULL;
    }
    return dst;
}

int socket_listen(const struct conn_addr_t *conn_addr)
{
    int on = 1;
    int sock;
    char str[64];

    sock = socket(conn_addr->addr.sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        LOG(LOG_ERROR, "sock=%d %s error:%s\n", sock, conn_addr_ntop(conn_addr, str, sizeof(str)), strerror(errno));
        return -1;
    }
    if (conn_addr->addr.sa_family == AF_INET6) {
        if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on))) {
            LOG(LOG_ERROR, "sock=%d %s error:%s\n", sock, conn_addr_ntop(conn_addr, str, sizeof(str)), strerror(errno));
            close(sock);
            return -1;
        }
    }
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) {
        LOG(LOG_ERROR, "sock=%d %s error:%s\n", sock, conn_addr_ntop(conn_addr, str, sizeof(str)), strerror(errno));
        close(sock);
        return -1;
    }
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on))) {
        LOG(LOG_ERROR, "sock=%d %s error:%s\n", sock, conn_addr_ntop(conn_addr, str, sizeof(str)), strerror(errno));
        close(sock);
        return -1;
    }
    if (bind(sock, &conn_addr->addr, sizeof(struct conn_addr_t)) != 0) {
        LOG(LOG_ERROR, "sock=%d %s error:%s\n", sock, conn_addr_ntop(conn_addr, str, sizeof(str)), strerror(errno));
        close(sock);
        return -1;
    }
    if (listen(sock, LISTEN_MAX)) {
        LOG(LOG_ERROR, "sock=%d %s error:%s\n", sock, conn_addr_ntop(conn_addr, str, sizeof(str)), strerror(errno));
        close(sock);
        return -1;
    }
    LOG(LOG_INFO, "sock=%d %s listen ok\n", sock, conn_addr_ntop(conn_addr, str, sizeof(str)));
    return sock;
}

struct conn_t *conn_socket(int domain, int type, int protocol)
{
    int sock;
    struct conn_t *conn = NULL;

    sock = socket(domain, type, protocol);
    if (sock > 0) {
        conn = (struct conn_t *)mem_malloc(sizeof(struct conn_t));
        memset(conn, 0, sizeof(struct conn_t));
        conn->sock = sock;
    }
    return conn;
}

void conn_close(struct conn_t *conn)
{
    if (conn->flags.active) {
        list_del(&conn->active_node);
    }
    close(conn->sock);
    mem_free(conn);
}

int conn_nonblock(struct conn_t *conn)
{
    int flagss, r;
    while ((flagss = fcntl(conn->sock, F_GETFL, 0)) == -1 && errno == EINTR);
    if (flagss == -1) {
        return -1;
    }
    while ((r = fcntl(conn->sock, F_SETFL, flagss | O_NONBLOCK)) == -1 && errno == EINTR);
    if (r == -1) {
        return -1;
    }
    return 0;
}

static int conn_timer_compare(struct conn_t *conn1, struct conn_t *conn2)
{
    if (conn1->timer_expire < conn2->timer_expire) {
        return -1;
    }
    if (conn1->timer_expire > conn2->timer_expire) {
        return 1;
    }
    if (conn1->sock < conn2->sock) {
        return -1;
    }
    if (conn1->sock > conn2->sock) {
        return 1;
    }
    return 0;
}

int conn_timer_add(struct conn_t *conn, int timeout)
{
    struct rb_node **p = &conn->net_loop->timer_root.rb_node;
    struct rb_node *parent = NULL;
    struct conn_t *tmp;
    int cmp;

    conn->timer_expire = conn->net_loop->time + timeout;
    while (*p)
    {
        parent = *p;
        tmp = rb_entry(parent, struct conn_t, timer_node);
        cmp = conn_timer_compare(conn, tmp);
        if (cmp < 0)
            p = &(*p)->rb_left;
        else if (cmp > 0)
            p = &(*p)->rb_right;
        else
            return -1;
    }
    rb_link_node(&conn->timer_node, parent, p);
    rb_insert_color(&conn->timer_node, &conn->net_loop->timer_root);
    return 0;
}

int conn_timer_update(struct conn_t *conn, int timeout)
{
    int64_t diff = conn->net_loop->time + timeout - conn->timer_expire;

    if (ABS(diff) >= TIMER_PERIOD) {
        conn_timer_del(conn);
        conn_timer_add(conn, timeout);
    }
    return 0;
}

int conn_timer_del(struct conn_t *conn)
{
    rb_erase(&conn->timer_node, &conn->net_loop->timer_root);
    return 0;
}

int conn_events_add(struct conn_t *conn, int events)
{
    if (events & CONN_EVENT_READ) {
        if (conn->flags.read_ready) {
            if (!conn->flags.active) {
                list_add_tail(&conn->active_node, &conn->net_loop->active_list);
                conn->flags.active = 1;
            }
            events &= (~CONN_EVENT_READ);
        }
        conn->flags.read_enable = 1;
    }
    if (events & CONN_EVENT_WRITE) {
        if (conn->flags.write_ready) {
            if (!conn->flags.active) {
                list_add_tail(&conn->active_node, &conn->net_loop->active_list);
                conn->flags.active = 1;
            }
            events &= (~CONN_EVENT_WRITE);
        }
        conn->flags.write_enable = 1;
    }
    return net_loop_poll_set(conn->net_loop, conn, conn->events | events);
}

int conn_events_del(struct conn_t *conn, int events)
{
    if (events & CONN_EVENT_READ) {
        conn->flags.read_enable = 0;
    }
    if (events & CONN_EVENT_WRITE) {
        conn->flags.write_enable = 0;
    }
    if (conn->flags.read_enable == 0 && conn->flags.write_enable == 0) {
        if (conn->flags.active) {
            list_del(&conn->active_node);
            conn->flags.active = 0;
        }
    }
    return net_loop_poll_set(conn->net_loop, conn, conn->events & (~events));
}

void conn_read_ready(struct conn_t *conn, int ready)
{
    conn->flags.read_ready = ready;
}

void conn_write_ready(struct conn_t *conn, int ready)
{
    conn->flags.write_ready = ready;
}

static int net_loop_pipe_read(struct conn_t *conn)
{
    char buf[4096];
    ssize_t n;

    n = read(conn->sock, buf, sizeof(buf));
    if (n > 0) {
        LOG(LOG_DEBUG, "sock=%d read=%zd\n", conn->sock, n);
        conn_events_add(conn, CONN_EVENT_READ);
    } else if(n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        LOG(LOG_DEBUG, "sock=%d read=%zd EAGAIN\n", conn->sock, n);
        conn->flags.read_ready = 0;
        conn_events_add(conn, CONN_EVENT_READ);
    } else {
        LOG(LOG_ERROR, "sock=%d read=%zd error: %s\n", conn->sock, n, strerror(errno));
    }
    return 0;
}

static int net_loop_pipe_write(struct conn_t *conn)
{
    ssize_t n;

    n = write(conn->sock, "1", 1);
    if (n > 0) {
        LOG(LOG_DEBUG, "sock=%d write=%zd\n", conn->sock, n);
    } else if(n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        LOG(LOG_DEBUG, "sock=%d write=%zd EAGAIN\n", conn->sock, n);
    } else {
        LOG(LOG_ERROR, "sock=%d write=%zd error: %s\n", conn->sock, n, strerror(errno));
    }
    return 0;
}

int net_loop_init(struct net_loop_t *net_loop)
{
    int fds[2];
    struct conn_t *conn;

    if (net_loop_poll_init(net_loop)) {
        return -1;
    }

    if (pipe(fds)) {
        LOG(LOG_ERROR, "pipe error: %s\n", strerror(errno));
        net_loop_poll_uninit(net_loop);
        return -1;
    }

    pthread_mutex_init(&net_loop->mutex, NULL);
    INIT_LIST_HEAD(&net_loop->task_list);
    net_loop->timer_root = RB_ROOT;
    INIT_LIST_HEAD(&net_loop->active_list);

    net_loop->conns[0] = conn = mem_malloc(sizeof(struct conn_t));
    memset(conn, 0, sizeof(struct conn_t));
    conn->net_loop = net_loop;
    conn->sock = fds[0];
    conn_nonblock(conn);
    conn->handle_read = net_loop_pipe_read;

    net_loop->conns[1] = conn = mem_malloc(sizeof(struct conn_t));
    memset(conn, 0, sizeof(struct conn_t));
    conn->net_loop = net_loop;
    conn->sock = fds[1];
    conn_nonblock(conn);
    conn->handle_write = net_loop_pipe_write;

    LOG(LOG_DEBUG, "sock=%d open\n", net_loop->conns[0]->sock);
    LOG(LOG_DEBUG, "sock=%d open\n", net_loop->conns[1]->sock);
    conn_events_add(net_loop->conns[0], CONN_EVENT_READ);
    return 0;
}

void net_loop_loop(struct net_loop_t *net_loop)
{
    struct conn_t *conn;
    struct rb_node *rb_node;
    struct task_t *task;
    struct list_head_t task_list;
    struct timeval tv;
    int loop;

    INIT_LIST_HEAD(&task_list);
    while (1) {
        loop = 0;
        net_loop_poll_wait(net_loop, list_empty(&net_loop->active_list) ? 100 : 0);
        gettimeofday(&tv, NULL);
        net_loop->time = tv.tv_sec * 1000  + tv.tv_usec / 1000;
        while (!list_empty(&net_loop->active_list) && loop++ < 100) {
            conn = d_list_head(&net_loop->active_list, struct conn_t, active_node);
            list_del(&conn->active_node);
            conn->flags.active = 0;
            if (conn->flags.read_ready) {
                if (conn->handle_read(conn)) {
                    continue;
                }
            }
            if (conn->flags.write_ready) {
                if (conn->handle_write(conn)) {
                    continue;
                }
            }
        }
        pthread_mutex_lock(&net_loop->mutex);
        list_splice_init(&net_loop->task_list, &task_list);
        net_loop->notified = 0;
        pthread_mutex_unlock(&net_loop->mutex);
        while (!list_empty(&task_list)) {
            task = d_list_head(&task_list, struct task_t, node);
            list_del(&task->node);
            task->handle(task);
        }
        if (net_loop->time >= net_loop->timer_expire) {
            while ((rb_node = rb_first(&net_loop->timer_root))) {
                conn = rb_entry(rb_node, struct conn_t, timer_node);
                if (net_loop->time >= conn->timer_expire) {
                    conn_timer_del(conn);
                    conn->handle_timeout(conn);
                } else {
                    break;
                }
            }
        }
        if (net_loop->exit) {
            break;
        }
    }
}

int net_loop_post(struct net_loop_t *net_loop, struct task_t *task)
{
    int notify;

    pthread_mutex_lock(&net_loop->mutex);
    list_add_tail(&task->node, &net_loop->task_list);
    if (net_loop->notified) {
        notify = 0;
    } else {
        notify = 1;
        net_loop->notified = 1;
    }
    pthread_mutex_unlock(&net_loop->mutex);
    if (notify) {
        net_loop_pipe_write(net_loop->conns[1]);
    }
    LOG(LOG_DEBUG, "notify=%d\n", notify);
    return 0;
}

int net_loop_exit(struct net_loop_t *net_loop)
{
    pthread_mutex_lock(&net_loop->mutex);
    net_loop->exit = 1;
    pthread_mutex_unlock(&net_loop->mutex);
    return 0;
}

void net_loop_uninit(struct net_loop_t *net_loop)
{
    conn_events_del(net_loop->conns[0], CONN_EVENT_READ | CONN_EVENT_WRITE);
    LOG(LOG_DEBUG, "sock=%d close\n", net_loop->conns[0]->sock);
    LOG(LOG_DEBUG, "sock=%d close\n", net_loop->conns[1]->sock);
    conn_close(net_loop->conns[0]);
    conn_close(net_loop->conns[1]);
    net_loop_poll_uninit(net_loop);
}
