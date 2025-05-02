#ifndef NET_EPOLL_H
#define NET_EPOLL_H

#include "net.h"

int net_loop_poll_init(struct net_loop_t *net_loop);
int net_loop_poll_add(struct net_loop_t *net_loop, struct conn_t *conn, int events);
int net_loop_poll_del(struct net_loop_t *net_loop, struct conn_t *conn, int events);
int net_loop_poll_wait(struct net_loop_t *net_loop, int timeout);
int net_loop_poll_uninit(struct net_loop_t *net_loop);

#endif
