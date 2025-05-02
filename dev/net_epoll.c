#include <sys/epoll.h>
#include "mem.h"
#include "log.h"
#include "net.h"

#define EPOLL_FD_MAX 1024
struct net_loop_poll_t {
    int fd;
    int64_t            event_add;
    int64_t            event_mod;
    int64_t            event_del;
};

int net_loop_poll_init(struct net_loop_t *net_loop)
{
    struct net_loop_poll_t *net_loop_poll;

    net_loop_poll = (struct net_loop_poll_t *)mem_malloc(sizeof(struct net_loop_poll_t));
    memset(net_loop_poll, 0, sizeof(struct net_loop_poll_t));
    net_loop_poll->fd = epoll_create(EPOLL_FD_MAX);
    if (net_loop_poll->fd < 0) {
        LOG(LOG_ERROR, "epoll create fd=%d error: %s\n", net_loop_poll->fd, strerror(errno));
        mem_free(net_loop_poll);
        return -1;
    }
    LOG(LOG_INFO, "epoll create fd=%d\n", net_loop_poll);
    net_loop->arg = (void *)net_loop_poll;
    return 0;
}

int net_loop_poll_add(struct net_loop_t *net_loop, struct conn_t *conn, int events)
{
    struct net_loop_poll_t *net_loop_poll;
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
    net_loop_poll = (struct net_loop_poll_t *)net_loop->arg;
    if (conn->events == 0) {
        if (epoll_ctl(net_loop_poll->fd, EPOLL_CTL_ADD, conn->sock, &ev)) {
            LOG(LOG_ERROR, "fd=%d conn=%d add error: %s\n", net_loop_poll->fd, conn->sock, strerror(errno));
            assert(0);
            return -1;
        }
        net_loop_poll->event_add++;
    } else if (events > 0) {
        if (epoll_ctl(net_loop_poll->fd, EPOLL_CTL_MOD, conn->sock, &ev)) {
            LOG(LOG_ERROR, "fd=%d conn=%d mod error: %s\n", net_loop_poll->fd, conn->sock, strerror(errno));
            assert(0);
            return -1;
        }
        net_loop_poll->event_mod++;
    } else {
        if (epoll_ctl(net_loop_poll->fd, EPOLL_CTL_DEL, conn->sock, &ev)) {
            LOG(LOG_ERROR, "fd=%d conn=%d del error: %s\n", net_loop_poll->fd, conn->sock, strerror(errno));
            assert(0);
            return -1;
        }
        net_loop_poll->event_del++;
    }
    conn->events = events;
    return 0;
}

int net_loop_poll_del(struct net_loop_t *net_loop, struct conn_t *conn, int events)
{
    return 0;
}

int net_loop_poll_wait(struct net_loop_t *net_loop, int timeout)
{
    struct net_loop_poll_t *net_loop_poll = (struct net_loop_poll_t *)net_loop->arg;
    struct epoll_event evs[EPOLL_FD_MAX];
    struct conn_t *conn;
    int i, nfds;

    nfds = epoll_wait(net_loop_poll->fd, evs, EPOLL_FD_MAX, timeout);
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

int net_loop_poll_uninit(struct net_loop_t *net_loop)
{
    struct net_loop_poll_t *net_loop_poll = (struct net_loop_poll_t *)net_loop->arg;

    LOG(LOG_INFO, "epoll close fd=%d\n", net_loop_poll->fd);
    LOG(LOG_INFO, "event_add=%"PRId64" event_mod=%"PRId64" event_del=%"PRId64"\n",
            net_loop_poll->event_add, net_loop_poll->event_mod, net_loop_poll->event_del);
    close(net_loop_poll->fd);
    mem_free(net_loop_poll);
    net_loop->arg = NULL;
    return 0;
}

