#include <sys/epoll.h>
#include "mem.h"
#include "log.h"
#include "net.h"

#define EPOLL_FD_MAX 1024
struct net_epoll_t {
    int fd;
    int64_t            event_add;
    int64_t            event_mod;
    int64_t            event_del;
};

int net_loop_epoll_init(struct net_loop_t *net_loop)
{
    struct net_epoll_t *net_epoll;

    net_epoll = (struct net_epoll_t *)mem_malloc(sizeof(struct net_epoll_t));
    memset(net_epoll, 0, sizeof(struct net_epoll_t));
    net_epoll->fd = epoll_create(EPOLL_FD_MAX);
    if (net_epoll->fd < 0) {
        LOG(LOG_ERROR, "epoll create fd=%d error: %s\n", net_epoll->fd, strerror(errno));
        mem_free(net_epoll);
        return -1;
    }
    LOG(LOG_INFO, "epoll create fd=%d\n", net_epoll);
    net_loop->arg = (void *)net_epoll;
    return 0;
}

int net_loop_epoll_add(struct net_loop_t *net_loop, struct conn_t *conn, int events)
{
    struct net_epoll_t *net_epoll;
    struct epoll_event ev;

    if (conn->events == events) {
        return 0;
    }
    ev.data.ptr = conn;
    ev.events = EPOLLET;
    if (events & CONN_EVENT_READ) {
        ev.events |= EPOLLIN;
    }
    if (events & CONN_EVENT_WRITE) {
        ev.events |= EPOLLOUT;
    }
    net_epoll = (struct net_epoll_t *)net_loop->arg;
    if (conn->events == 0) {
        if (epoll_ctl(net_epoll->fd, EPOLL_CTL_ADD, conn->sock, &ev)) {
            LOG(LOG_ERROR, "fd=%d conn=%d add error: %s\n", net_epoll->fd, conn->sock, strerror(errno));
            assert(0);
            return -1;
        }
        net_epoll->event_add++;
    } else if (events > 0) {
        if (epoll_ctl(net_epoll->fd, EPOLL_CTL_MOD, conn->sock, &ev)) {
            LOG(LOG_ERROR, "fd=%d conn=%d mod error: %s\n", net_epoll->fd, conn->sock, strerror(errno));
            assert(0);
            return -1;
        }
        net_epoll->event_mod++;
    } else {
        if (epoll_ctl(net_epoll->fd, EPOLL_CTL_DEL, conn->sock, &ev)) {
            LOG(LOG_ERROR, "fd=%d conn=%d del error: %s\n", net_epoll->fd, conn->sock, strerror(errno));
            assert(0);
            return -1;
        }
        net_epoll->event_del++;
    }
    conn->events = events;
    return 0;
}

int net_loop_epoll_del(struct net_loop_t *net_loop, struct conn_t *conn, int events)
{
    return 0;
}

int net_loop_epoll_wait(struct net_loop_t *net_loop, int timeout)
{
    struct net_epoll_t *net_epoll = (struct net_epoll_t *)net_loop->arg;
    struct epoll_event evs[EPOLL_FD_MAX];
    struct conn_t *conn;
    int i, nfds;

    nfds = epoll_wait(net_epoll->fd, evs, EPOLL_FD_MAX, timeout);
    for (i = 0; i < nfds; i++) {
        conn = evs[i].data.ptr;
        if (evs[i].events & (EPOLLIN | EPOLLERR | EPOLLHUP)) {
            conn_read_ready(conn, 1);
            if (!conn->flags.active) {
                list_add_tail(&conn->active_node, &net_loop->active_list);
                conn->flags.active = 1;
            }
        }
        if (evs[i].events & (EPOLLOUT | EPOLLERR | EPOLLHUP)) {
            conn_write_ready(conn, 1);
            if (!conn->flags.active) {
                list_add_tail(&conn->active_node, &net_loop->active_list);
                conn->flags.active = 1;
            }
        }
    }
    return 0;
}

int net_loop_epoll_uninit(struct net_loop_t *net_loop)
{
    struct net_epoll_t *net_epoll = (struct net_epoll_t *)net_loop->arg;

    LOG(LOG_INFO, "epoll close fd=%d\n", net_epoll->fd);
    LOG(LOG_INFO, "event_add=%"PRId64" event_mod=%"PRId64" event_del=%"PRId64"\n",
            net_epoll->event_add, net_epoll->event_mod, net_epoll->event_del);
    close(net_epoll->fd);
    mem_free(net_epoll);
    net_loop->arg = NULL;
    return 0;
}

