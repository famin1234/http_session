#include "net_module.h"

int epoll_module_init(struct net_module_t *net_module);
int epoll_module_mod(struct net_module_t *net_module, struct conn_t *conn, int events);
int epoll_module_wait(struct net_module_t *net_module, int timeout);
int epoll_module_uninit(struct net_module_t *net_module);
