#include <sys/epoll.h>
#include "mem.h"
#include "log.h"
#include "net.h"

#define EPOLL_FD_MAX 1024
struct epoll_module_t {
    int fd;
    int64_t            event_add;
    int64_t            event_mod;
    int64_t            event_del;
};

int epoll_module_init(struct net_event_t *net_event)
{
    struct epoll_module_t *epoll_module;

    epoll_module = (struct epoll_module_t *)mem_malloc(sizeof(struct epoll_module_t));
    memset(epoll_module, 0, sizeof(struct epoll_module_t));
    epoll_module->fd = epoll_create(EPOLL_FD_MAX);
    if (epoll_module->fd < 0) {
        LOG(LOG_ERROR, "epoll create fd=%d error: %s\n", epoll_module->fd, strerror(errno));
        mem_free(epoll_module);
        return -1;
    }
    LOG(LOG_INFO, "epoll create fd=%d\n", epoll_module);
    net_event->sub_module = (void *)epoll_module;
    return 0;
}

int epoll_module_mod(struct net_event_t *net_event, struct conn_t *conn, int events)
{
    struct epoll_module_t *epoll_module;
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
    epoll_module = (struct epoll_module_t *)net_event->sub_module;
    if (conn->events == 0) {
        if (epoll_ctl(epoll_module->fd, EPOLL_CTL_ADD, conn->sock, &ev)) {
            LOG(LOG_ERROR, "fd=%d conn=%d add error: %s\n", epoll_module->fd, conn->sock, strerror(errno));
            assert(0);
            return -1;
        }
        epoll_module->event_add++;
    } else if (events > 0) {
        if (epoll_ctl(epoll_module->fd, EPOLL_CTL_MOD, conn->sock, &ev)) {
            LOG(LOG_ERROR, "fd=%d conn=%d mod error: %s\n", epoll_module->fd, conn->sock, strerror(errno));
            assert(0);
            return -1;
        }
        epoll_module->event_mod++;
    } else {
        if (epoll_ctl(epoll_module->fd, EPOLL_CTL_DEL, conn->sock, &ev)) {
            LOG(LOG_ERROR, "fd=%d conn=%d del error: %s\n", epoll_module->fd, conn->sock, strerror(errno));
            assert(0);
            return -1;
        }
        epoll_module->event_del++;
    }
    conn->events = events;
    return 0;
}

int epoll_module_wait(struct net_event_t *net_event, int timeout)
{
    struct epoll_module_t *epoll_module = (struct epoll_module_t *)net_event->sub_module;
    struct epoll_event evs[EPOLL_FD_MAX];
    struct conn_t *conn;
    int i, nfds;

    nfds = epoll_wait(epoll_module->fd, evs, EPOLL_FD_MAX, timeout);
    for (i = 0; i < nfds; i++) {
        conn = evs[i].data.ptr;
        if (evs[i].events & (EPOLLIN | EPOLLERR | EPOLLHUP)) {
            conn_read_ready(conn, 1);
            if (!conn->flags.active) {
                list_add_tail(&conn->active_node, &net_event->active_list);
                conn->flags.active = 1;
            }
        }
        if (evs[i].events & (EPOLLOUT | EPOLLERR | EPOLLHUP)) {
            conn_write_ready(conn, 1);
            if (!conn->flags.active) {
                list_add_tail(&conn->active_node, &net_event->active_list);
                conn->flags.active = 1;
            }
        }
    }
    return 0;
}

int epoll_module_uninit(struct net_event_t *net_event)
{
    struct epoll_module_t *epoll_module = (struct epoll_module_t *)net_event->sub_module;

    LOG(LOG_INFO, "epoll close fd=%d\n", epoll_module->fd);
    LOG(LOG_INFO, "event_add=%"PRId64" event_mod=%"PRId64" event_del=%"PRId64"\n",
            epoll_module->event_add, epoll_module->event_mod, epoll_module->event_del);
    close(epoll_module->fd);
    mem_free(epoll_module);
    net_event->sub_module = NULL;
    return 0;
}

