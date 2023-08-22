#ifndef DNS_H
#define DNS_H

#include "os.h"

struct dns_cache_t {
    int lock;
    int del:1;

    char *host;
    void *dns_client;
    struct rb_node rb_node;
    struct list_head_t addr_list;
    int ttl;
};

struct dns_addr_t {
    int af;
    union {
        struct in_addr in_addr;
        struct in6_addr in6_addr;
    };
    struct list_head_t node;
};

void dns_init();
void dns_clean();

void dns_cache_table_query(struct action_t *action, const char *host);
void dns_cache_table_unquery(struct action_t *action);

#endif
