#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/time.h>
#include <sys/epoll.h>

#include "mem.h"
#include "log.h"
#include "net.h"

#define LISTEN_MAX 1024
#define EPOLL_FD_MAX 1024
#define TIMER_PERIOD 100
#define ABS(x) ((x) >= 0 ? (x) : (x))

static int net_handle_epoll_init(struct net_handle_t *net_handle)
{
    net_handle->epoll_fd = epoll_create(EPOLL_FD_MAX);
    if (net_handle->epoll_fd < 0) {
        LOG(LOG_ERROR, "epoll create fd=%d error: %s\n", net_handle->epoll_fd, strerror(errno));
        mem_free(net_handle);
        return -1;
    }
    LOG(LOG_INFO, "epoll create fd=%d\n", net_handle->epoll_fd);
    return 0;
}

static int net_handle_epoll_uninit(struct net_handle_t *net_handle)
{
    LOG(LOG_INFO, "epoll close fd=%d\n", net_handle->epoll_fd);
    LOG(LOG_INFO, "event_add=%"PRId64" event_mod=%"PRId64" event_del=%"PRId64"\n",
            net_handle->event_add, net_handle->event_mod, net_handle->event_del);
    close(net_handle->epoll_fd);
    net_handle->epoll_fd = -1;
    return 0;
}

static int net_handle_epoll_set(struct net_handle_t *net_handle, struct conn_t *conn, int events)
{
    struct epoll_event ev;

    if (conn->events != events) {
        ev.data.ptr = conn;
        ev.events = EPOLLET;
        if (events & CONN_EVENT_READ) {
            ev.events |= EPOLLIN;
        }
        if (events & CONN_EVENT_WRITE) {
            ev.events |= EPOLLOUT;
        }
        if (conn->events == 0) {
            if (epoll_ctl(net_handle->epoll_fd, EPOLL_CTL_ADD, conn->sock, &ev)) {
                LOG(LOG_ERROR, "fd=%d conn=%d add error: %s\n", net_handle->epoll_fd, conn->sock, strerror(errno));
                assert(0);
                return -1;
            }
            net_handle->event_add++;
        } else if (events > 0) {
            if (epoll_ctl(net_handle->epoll_fd, EPOLL_CTL_MOD, conn->sock, &ev)) {
                LOG(LOG_ERROR, "fd=%d conn=%d mod error: %s\n", net_handle->epoll_fd, conn->sock, strerror(errno));
                assert(0);
                return -1;
            }
            net_handle->event_mod++;
        } else {
            if (epoll_ctl(net_handle->epoll_fd, EPOLL_CTL_DEL, conn->sock, &ev)) {
                LOG(LOG_ERROR, "fd=%d conn=%d del error: %s\n", net_handle->epoll_fd, conn->sock, strerror(errno));
                assert(0);
                return -1;
            }
            net_handle->event_del++;
        }
        conn->events = events;
    }
    return 0;
}

static int net_handle_epoll_wait(struct net_handle_t *net_handle, int timeout)
{
    struct epoll_event evs[EPOLL_FD_MAX];
    struct conn_t *conn;
    int i, nfds;

    nfds = epoll_wait(net_handle->epoll_fd, evs, EPOLL_FD_MAX, timeout);
    for (i = 0; i < nfds; i++) {
        conn = evs[i].data.ptr;
        if (evs[i].events & (EPOLLIN | EPOLLERR | EPOLLHUP)) {
            conn_read_ready(conn, 1);
            if (!conn->flags.active) {
                list_add_tail(&conn->active_node, &net_handle->active_list);
                conn->flags.active = 1;
            }
        }
        if (evs[i].events & (EPOLLOUT | EPOLLERR | EPOLLHUP)) {
            conn_write_ready(conn, 1);
            if (!conn->flags.active) {
                list_add_tail(&conn->active_node, &net_handle->active_list);
                conn->flags.active = 1;
            }
        }
    }
    return 0;
}

static int net_handle_pipe_read(struct conn_t *conn)
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

static int net_handle_pipe_write(struct conn_t *conn)
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

int net_handle_init(struct net_handle_t *net_handle)
{
    int fds[2];
    struct conn_t *conn;

    if (pipe(fds)) {
        LOG(LOG_ERROR, "pipe error: %s\n", strerror(errno));
        return -1;
    }
    if (net_handle_epoll_init(net_handle)) {
        return -1;
    }

    pthread_mutex_init(&net_handle->mutex, NULL);
    INIT_LIST_HEAD(&net_handle->listen_list);
    INIT_LIST_HEAD(&net_handle->task_list);
    INIT_LIST_HEAD(&net_handle->active_list);
    net_handle->timer_root = RB_ROOT;

    net_handle->conns[0] = conn = mem_malloc(sizeof(struct conn_t));
    memset(conn, 0, sizeof(struct conn_t));
    conn->net_handle = net_handle;
    conn->sock = fds[0];
    conn_nonblock(conn);
    conn->handle_read = net_handle_pipe_read;

    net_handle->conns[1] = conn = mem_malloc(sizeof(struct conn_t));
    memset(conn, 0, sizeof(struct conn_t));
    conn->net_handle = net_handle;
    conn->sock = fds[1];
    conn_nonblock(conn);
    conn->handle_write = net_handle_pipe_write;

    LOG(LOG_DEBUG, "sock=%d open\n", net_handle->conns[0]->sock);
    LOG(LOG_DEBUG, "sock=%d open\n", net_handle->conns[1]->sock);
    conn_events_add(net_handle->conns[0], CONN_EVENT_READ);
    return 0;
}

void net_handle_uninit(struct net_handle_t *net_handle)
{
    conn_events_del(net_handle->conns[0], CONN_EVENT_READ | CONN_EVENT_WRITE);
    LOG(LOG_DEBUG, "sock=%d close\n", net_handle->conns[0]->sock);
    LOG(LOG_DEBUG, "sock=%d close\n", net_handle->conns[1]->sock);
    conn_close(net_handle->conns[0]);
    conn_close(net_handle->conns[1]);
    net_handle_epoll_uninit(net_handle);
}

void net_handle_loop(struct net_handle_t *net_handle)
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
        net_handle_epoll_wait(net_handle, list_empty(&net_handle->active_list) ? 100 : 0);
        gettimeofday(&tv, NULL);
        net_handle->time = tv.tv_sec * 1000  + tv.tv_usec / 1000;
        while (!list_empty(&net_handle->active_list) && loop++ < 100) {
            conn = d_list_head(&net_handle->active_list, struct conn_t, active_node);
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
        pthread_mutex_lock(&net_handle->mutex);
        list_splice_init(&net_handle->task_list, &task_list);
        net_handle->notified = 0;
        pthread_mutex_unlock(&net_handle->mutex);
        while (!list_empty(&task_list)) {
            task = d_list_head(&task_list, struct task_t, node);
            list_del(&task->node);
            task->handle(task);
        }
        if (net_handle->time >= net_handle->timer_expire) {
            while ((rb_node = rb_first(&net_handle->timer_root))) {
                conn = rb_entry(rb_node, struct conn_t, timer_node);
                if (net_handle->time >= conn->timer_expire) {
                    conn_timer_del(conn);
                    conn->handle_timeout(conn);
                } else {
                    break;
                }
            }
        }
        if (net_handle->exit) {
            break;
        }
    }
}

int net_handle_post(struct net_handle_t *net_handle, struct task_t *task)
{
    int notify;

    pthread_mutex_lock(&net_handle->mutex);
    if (task) {
        list_add_tail(&task->node, &net_handle->task_list);
    } else {
        net_handle->exit = 1;
    }
    if (net_handle->notified) {
        notify = 0;
    } else {
        notify = 1;
        net_handle->notified = 1;
    }
    pthread_mutex_unlock(&net_handle->mutex);
    if (notify) {
        net_handle_pipe_write(net_handle->conns[1]);
    }
    LOG(LOG_DEBUG, "notify=%d\n", notify);
    return 0;
}

int net_handle_listen(struct net_handle_t *net_handle, struct conn_addr_t *addr, struct conn_t **conn_listen)
{
    int sock;
    int on;
    char str[64];
    struct conn_t *conn;

    sock = socket(addr->addr.sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        LOG(LOG_ERROR, "sock=%d %s error:%s\n", sock, conn_addr_ntop(addr, str, sizeof(str)), strerror(errno));
        return CONN_ERR;
    }
    if (addr->addr.sa_family == AF_INET6) {
        if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on))) {
            LOG(LOG_ERROR, "sock=%d %s error:%s\n", sock, conn_addr_ntop(addr, str, sizeof(str)), strerror(errno));
            close(sock);
            return CONN_ERR;
        }
    }
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) {
        LOG(LOG_ERROR, "sock=%d %s error:%s\n", sock, conn_addr_ntop(addr, str, sizeof(str)), strerror(errno));
        close(sock);
        return CONN_ERR;
    }
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on))) {
        LOG(LOG_ERROR, "sock=%d %s error:%s\n", sock, conn_addr_ntop(addr, str, sizeof(str)), strerror(errno));
        close(sock);
        return CONN_ERR;
    }
    if (bind(sock, &addr->addr, sizeof(struct conn_addr_t)) != 0) {
        LOG(LOG_ERROR, "sock=%d %s error:%s\n", sock, conn_addr_ntop(addr, str, sizeof(str)), strerror(errno));
        close(sock);
        return CONN_ERR;
    }
    if (listen(sock, LISTEN_MAX)) {
        LOG(LOG_ERROR, "sock=%d %s error:%s\n", sock, conn_addr_ntop(addr, str, sizeof(str)), strerror(errno));
        close(sock);
        return CONN_ERR;
    }
    LOG(LOG_INFO, "sock=%d %s listen ok\n", sock, conn_addr_ntop(addr, str, sizeof(str)));
    *conn_listen = conn = mem_malloc(sizeof(struct conn_t));
    memset(conn, 0, sizeof(struct conn_t));
    conn->sock = sock;
    conn->addr = *addr;
    conn->net_handle = net_handle;
    conn_nonblock(conn);
    return CONN_OK;
}

int conn_accept(struct conn_t *conn_listen, struct conn_t **conn_accept)
{
    int sock;
    struct conn_t *conn = NULL;
    struct conn_addr_t addr;
    socklen_t addrlen;
    char str[64];

    addrlen = sizeof(struct conn_addr_t);
    sock = accept(conn_listen->sock, &addr.addr, &addrlen);
    if (sock > 0) {
        LOG(LOG_DEBUG, "sock=%d accept=%d %s\n", conn_listen->sock, sock, conn_addr_ntop(&addr, str, sizeof(str)));
        conn_events_add(conn_listen, CONN_EVENT_READ);
        *conn_accept = conn = (struct conn_t *)mem_malloc(sizeof(struct conn_t));
        memset(conn, 0, sizeof(struct conn_t));
        conn->sock = sock;
        conn->addr = addr;
        conn->net_handle = conn_listen->net_handle;
        return CONN_OK;
    } else if(sock == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        LOG(LOG_DEBUG, "sock=%d accept=%d EAGAIN\n", conn_listen->sock, sock);
        conn_listen->flags.read_ready = 0;
        return CONN_EAGIN;
    } else {
        conn_events_add(conn_listen, CONN_EVENT_READ);
        LOG(LOG_ERROR, "sock=%d accept=%d error:%s\n", conn_listen->sock, sock, strerror(errno));
        return CONN_ERR;
    }
    return CONN_OK;
}

void conn_close(struct conn_t *conn)
{
    if (conn->flags.active) {
        list_del(&conn->active_node);
    }
    close(conn->sock);
    mem_free(conn);
}

int conn_events_add(struct conn_t *conn, int events)
{
    if (events & CONN_EVENT_READ) {
        if (conn->flags.read_ready) {
            if (!conn->flags.active) {
                list_add_tail(&conn->active_node, &conn->net_handle->active_list);
                conn->flags.active = 1;
            }
            events &= (~CONN_EVENT_READ);
        }
        conn->flags.read_enable = 1;
    }
    if (events & CONN_EVENT_WRITE) {
        if (conn->flags.write_ready) {
            if (!conn->flags.active) {
                list_add_tail(&conn->active_node, &conn->net_handle->active_list);
                conn->flags.active = 1;
            }
            events &= (~CONN_EVENT_WRITE);
        }
        conn->flags.write_enable = 1;
    }
    return net_handle_epoll_set(conn->net_handle, conn, conn->events | events);
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
    return net_handle_epoll_set(conn->net_handle, conn, conn->events & (~events));
}

void conn_read_ready(struct conn_t *conn, int ready)
{
    conn->flags.read_ready = ready;
}

void conn_write_ready(struct conn_t *conn, int ready)
{
    conn->flags.write_ready = ready;
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
    struct rb_node **p = &conn->net_handle->timer_root.rb_node;
    struct rb_node *parent = NULL;
    struct conn_t *tmp;
    int cmp;

    conn->timer_expire = conn->net_handle->time + timeout;
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
    rb_insert_color(&conn->timer_node, &conn->net_handle->timer_root);
    return 0;
}

int conn_timer_update(struct conn_t *conn, int timeout)
{
    int64_t diff = conn->net_handle->time + timeout - conn->timer_expire;

    if (ABS(diff) >= TIMER_PERIOD) {
        conn_timer_del(conn);
        conn_timer_add(conn, timeout);
    }
    return 0;
}

int conn_timer_del(struct conn_t *conn)
{
    rb_erase(&conn->timer_node, &conn->net_handle->timer_root);
    return 0;
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

int conn_addr_pton(struct conn_addr_t *addr, const char *host, unsigned short port)
{
    int ret;

    ret = inet_pton(AF_INET, host, &addr->in.sin_addr);
    if (ret > 0) {
        addr->in.sin_family = AF_INET;
        addr->in.sin_port = htons(port);
        return ret;
    }
    ret = inet_pton(AF_INET6, host, &addr->in6.sin6_addr);
    if (ret > 0) {
        addr->in6.sin6_family = AF_INET6;
        addr->in6.sin6_port = htons(port);
        addr->in6.sin6_flowinfo = 0;
        addr->in6.sin6_scope_id = 0;
        return ret;
    }
    return ret;
}

const char *conn_addr_ntop(const struct conn_addr_t *addr, char *dst, size_t size)
{
    size_t len;
    if (addr->addr.sa_family == AF_INET) {
        inet_ntop(AF_INET, &addr->in.sin_addr, dst, size);
        len = strlen(dst);
        snprintf(dst + len, size - len, ":%d", ntohs(addr->in.sin_port));
    } else if (addr->addr.sa_family == AF_INET6) {
        inet_ntop(AF_INET6, &addr->in6.sin6_addr, dst, size);
        len = strlen(dst);
        snprintf(dst + len, size - len, ":%d", ntohs(addr->in6.sin6_port));
    } else {
        return NULL;
    }
    return dst;
}
