#ifndef NET_EPOLL_H
#define NET_EPOLL_H

#include "net.h"

int net_loop_epoll_init(struct net_loop_t *net_loop);
int net_loop_epoll_add(struct net_loop_t *net_loop, struct conn_t *conn, int events);
int net_loop_epoll_del(struct net_loop_t *net_loop, struct conn_t *conn, int events);
int net_loop_epoll_wait(struct net_loop_t *net_loop, int timeout);
int net_loop_epoll_uninit(struct net_loop_t *net_loop);

#define net_loop_poll_init net_loop_epoll_init
#define net_loop_poll_add net_loop_epoll_add
#define net_loop_poll_del net_loop_epoll_del
#define net_loop_poll_wait net_loop_epoll_wait
#define net_loop_poll_uninit net_loop_epoll_uninit

#endif
