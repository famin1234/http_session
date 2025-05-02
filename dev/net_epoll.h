#ifndef NET_EPOLL_H
#define NET_EPOLL_H

#include "net.h"

int epoll_module_init(struct net_event_t *net_event);
int epoll_module_mod(struct net_event_t *net_event, struct conn_t *conn, int events);
int epoll_module_wait(struct net_event_t *net_event, int timeout);
int epoll_module_uninit(struct net_event_t *net_event);

#endif
