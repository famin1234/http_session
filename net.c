#include "mem.h"
#include "log.h"
#include "aio.h"
#include "net.h"

struct list_head_t net_listen_list;

int net_init()
{
    INIT_LIST_HEAD(&net_listen_list);
    return 0;
}

void net_clean()
{
    struct net_listen_t *nl;

    while (!list_empty(&net_listen_list)) {
        nl = d_list_head(&net_listen_list, struct net_listen_t, node);
        list_del(&nl->node);
        mem_free(nl);
    }
}

int net_listen_list_add(const char *host, unsigned short port, conn_handle_t handle)
{
    struct net_listen_t *nl;
    union conn_addr_t conn_addr;

    if (conn_addr_pton(&conn_addr, host, port) > 0) {
        nl = mem_malloc(sizeof(struct net_listen_t));
        nl->conn_addr = conn_addr;
        nl->handle = handle;
        list_add_tail(&nl->node, &net_listen_list);
    } else {
        LOG(LOG_DEBUG, "%s:%d is not ip\n", host, port);
        return -1;
    }
    return 0;
}

int net_listen(net_socket_t sock, union conn_addr_t *conn_addr)
{
    int on = 1;
    if (conn_addr->addr.sa_family == AF_INET6) {
        if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on))) {
            return -1;
        }
    }
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) {
        return -1;
    }
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on))) {
        return -1;
    }
    if (bind(sock, &conn_addr->addr, sizeof(union conn_addr_t)) != 0) {
        return -1;
    }
    if (listen(sock, LISTEN_MAX)) {
        return -1;
    }
    return 0;
}

int conn_addr_pton(union conn_addr_t *conn_addr, const char *host, unsigned short port)
{
    if (inet_pton(AF_INET, host, &conn_addr->in.sin_addr) == 1) {
        conn_addr->in.sin_family = AF_INET;
        conn_addr->in.sin_port = htons(port);
        return 1;
    }
    if (inet_pton(AF_INET6, host, &conn_addr->in6.sin6_addr) == 1) {
        conn_addr->in6.sin6_family = AF_INET6;
        conn_addr->in6.sin6_port = htons(port);
        conn_addr->in6.sin6_flowinfo = 0;
        conn_addr->in6.sin6_scope_id = 0;
        return 1;
    }
    return -1;
}

const char *conn_addr_ntop(union conn_addr_t *conn_addr, char *buf, socklen_t size)
{
    char str[64];
    if (conn_addr->addr.sa_family == AF_INET) {
        inet_ntop(AF_INET, &conn_addr->in.sin_addr, str, sizeof(str));
        snprintf(buf, size, "%s:%d", str, ntohs(conn_addr->in.sin_port));
    } else if (conn_addr->addr.sa_family == AF_INET6) {
        inet_ntop(AF_INET6, &conn_addr->in6.sin6_addr, str, sizeof(str));
        snprintf(buf, size, "%s:%d", str, ntohs(conn_addr->in6.sin6_port));
    } else {
        return NULL;
    }
    return buf;
}

uint16_t conn_addr_port(union conn_addr_t *conn_addr)
{
    if (conn_addr->addr.sa_family == AF_INET) {
        return ntohs(conn_addr->in.sin_port);
    } else if (conn_addr->addr.sa_family == AF_INET6) {
        return ntohs(conn_addr->in6.sin6_port);
    }
    return 0;
}

int conn_addr_compare(const union conn_addr_t *conn_addr1, const union conn_addr_t *conn_addr2)
{
    if (conn_addr1->addr.sa_family < conn_addr2->addr.sa_family) {
        return -1;
    }
    if (conn_addr1->addr.sa_family > conn_addr2->addr.sa_family) {
        return 1;
    }
    if (conn_addr1->addr.sa_family == AF_INET) {
        if (conn_addr1->in.sin_port < conn_addr2->in.sin_port) {
            return -1;
        }
        if (conn_addr1->in.sin_port > conn_addr2->in.sin_port) {
            return 1;
        }
        return memcmp(&conn_addr1->in.sin_addr, &conn_addr2->in.sin_addr, sizeof(struct in_addr));
    }
    if (conn_addr1->addr.sa_family == AF_INET6) {
        if (conn_addr1->in6.sin6_port < conn_addr2->in6.sin6_port) {
            return -1;
        }
        if (conn_addr1->in6.sin6_port > conn_addr2->in6.sin6_port) {
            return 1;
        }
        return memcmp(&conn_addr1->in6.sin6_addr, &conn_addr2->in6.sin6_addr, sizeof(struct in6_addr));
    }
    return 0;
}

struct conn_t *conn_alloc(void)
{
    struct conn_t *conn = NULL;

    conn = mem_malloc(sizeof(struct conn_t));
    memset(conn, 0, sizeof(struct conn_t));
    INIT_LIST_HEAD(&conn->ready_node);
    return conn;
}

void conn_free(struct conn_t *conn)
{
    mem_free(conn);
}

void conn_close(struct conn_t *conn)
{
    assert(conn->sock > 0);
    LOG(LOG_DEBUG, "sock=%d close\n", conn->sock);
    conn_disable(conn, CONN_READ | CONN_WRITE);
    conn_timer_unset(conn);
    close(conn->sock);
    if (conn->flags.lock) {
        conn->flags.closed = 1;
    } else {
        conn_free(conn);
    }
}

struct conn_t *conn_socket(int domain, int type, int protocol)
{
    int sock = -1;
    struct conn_t *conn = NULL;
    sock = socket(domain, type, protocol);
    if (sock > 0) {
        conn = conn_alloc();
        conn->sock = sock;
    }
    return conn;
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

void conn_enable(struct conn_t *conn, int flags)
{
    struct net_thread_t *net_thread = conn->net_thread;
    int err;
    uint32_t events;

    events = conn->events;
    if (flags & CONN_READ) {
        conn->flags.read_enable = 1;
        if (conn->flags.read_ready) {
            if (!conn->flags.in_ready_list) {
                list_add_tail(&conn->ready_node, &net_thread->ready_list);
                conn->flags.in_ready_list = 1;
                net_thread->ready_num++;
            }
        } else {
            events |= CONN_READ;
        }
    }
    if (flags & CONN_WRITE) {
        conn->flags.write_enable = 1;
        if (conn->flags.write_ready) {
            if (!conn->flags.in_ready_list) {
                list_add_tail(&conn->ready_node, &net_thread->ready_list);
                conn->flags.in_ready_list = 1;
                net_thread->ready_num++;
            }
        } else {
            events |= CONN_WRITE;
        }
    }
    if (events != conn->events) {
        if (conn->events) {
            err = net_thread_event_mod(net_thread, conn, events);
        } else {
            err = net_thread_event_add(net_thread, conn, events);
        }
        if (!err) {
            conn->events = events;
        }
    }
}

void conn_disable(struct conn_t *conn, int flags)
{
    struct net_thread_t *net_thread = conn->net_thread;
    int err;
    uint32_t events;

    events = conn->events;
    if (flags & CONN_READ) {
        conn->flags.read_enable = 0;
        events &= (~CONN_READ);
    }
    if (flags & CONN_WRITE) {
        conn->flags.write_enable = 0;
        events &= (~CONN_WRITE);
    }
    if (events != conn->events) {
        if (events) {
            err = net_thread_event_mod(net_thread, conn, events);
        } else {
            err = net_thread_event_del(net_thread, conn);
        }
        if (!err) {
            conn->events = events;
        }
    }
    if (conn->flags.read_enable == 0 && conn->flags.write_enable == 0) {
        if (conn->flags.in_ready_list) {
            list_del(&conn->ready_node);
            conn->flags.in_ready_list = 0;
            net_thread->ready_num--;
        }
    }
}

void conn_ready_set(struct conn_t *conn, int flags)
{
    if (flags & CONN_READ) {
        conn->flags.read_ready = 1;
    }
    if (flags & CONN_WRITE) {
        conn->flags.write_ready = 1;
    }
}

void conn_ready_unset(struct conn_t *conn, int flags)
{
    if (flags & CONN_READ) {
        conn->flags.read_ready = 0;
    }
    if (flags & CONN_WRITE) {
        conn->flags.write_ready = 0;
    }
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

static int conn_timer_insert(struct conn_t *conn)
{
    struct net_thread_t *net_thread = conn->net_thread;
    struct rb_node **p = &net_thread->timer_root.rb_node;
    struct rb_node *parent = NULL;
    struct conn_t *tmp;
    int cmp;

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
    rb_insert_color(&conn->timer_node, &net_thread->timer_root);
    return 0;
}

void conn_timer_set(struct conn_t *conn, int64_t timeout)
{
    struct net_thread_t *net_thread = conn->net_thread;
    int64_t expire;

    expire = net_thread->time_current + timeout;
    if (conn->flags.timer_set) {
        if (expire - conn->timer_expire >= TIMER_PERIOD) {
            conn->timer_expire = expire;
            rb_erase(&conn->timer_node, &net_thread->timer_root);
            conn_timer_insert(conn);
        }
    } else {
        conn->timer_expire = expire;
        if (conn_timer_insert(conn)) {
            assert(0);
        } else {
            conn->flags.timer_set = 1;
        }
    }
}

void conn_timer_unset(struct conn_t *conn)
{
    struct net_thread_t *net_thread = conn->net_thread;

    if (conn->flags.timer_set) {
        rb_erase(&conn->timer_node, &net_thread->timer_root);
        conn->flags.timer_set = 0;
    }
}

int conn_keepalive_set(struct conn_t *conn)
{
    struct net_thread_t *net_thread = conn->net_thread;
    struct rb_node **p = &net_thread->keepalive_root.rb_node;
    struct rb_node *parent = NULL;
    struct conn_t *tmp;
    int cmp;

    while (*p) {
        parent = *p;
        tmp = rb_entry(parent, struct conn_t, keepalive_node);
        cmp = conn_addr_compare(&conn->peer_addr, &tmp->peer_addr);
        if (cmp == 0) {
            if (conn->sock < tmp->sock) {
                cmp = -1;
            } else if (conn->sock > tmp->sock) {
                cmp = 1;
            } else {
                cmp = 0;
            }
        }
        if (cmp < 0) {
            p = &(*p)->rb_left;
        } else if (cmp > 0) {
            p = &(*p)->rb_right;
        } else {
            assert(0);
            return -1;
        }
    }
    rb_link_node(&conn->keepalive_node, parent, p);
    rb_insert_color(&conn->keepalive_node, &net_thread->keepalive_root);
    return 0;
}

struct conn_t *conn_keepalive_get(struct net_thread_t *net_thread, union conn_addr_t *peer_addr)
{
    struct rb_node *node = net_thread->keepalive_root.rb_node;
    struct conn_t *conn;
    int cmp;

    while (node) {
        conn = rb_entry(node, struct conn_t, keepalive_node);
        cmp = conn_addr_compare(peer_addr, &conn->peer_addr);
        if (cmp < 0) {
            node = node->rb_left;
        } else if (cmp > 0) {
            node = node->rb_right;
        } else {
            conn_keepalive_unset(conn);
            return conn;
        }
    }
    return NULL;
}

void conn_keepalive_unset(struct conn_t *conn)
{
    struct net_thread_t *net_thread = conn->net_thread;

    rb_erase(&conn->keepalive_node, &net_thread->keepalive_root);
}

int net_thread_event_init(struct net_thread_t *net_thread)
{
    net_thread->efd = epoll_create(EPOLL_FD_MAX);
    if (net_thread->efd < 0) {
        return -1;
    }
    LOG(LOG_INFO, "%s efd %d create\n", net_thread->name, net_thread->efd);
    return 0;
}

int net_thread_event_add(struct net_thread_t *net_thread, struct conn_t *conn, uint32_t events)
{
    struct epoll_event ee;

    ee.events = EPOLLET;
    if (events & CONN_READ) {
        ee.events |= EPOLLIN;
    }
    if (events & CONN_WRITE) {
        ee.events |= EPOLLOUT;
    }
    ee.data.ptr = conn;
    if (epoll_ctl(net_thread->efd, EPOLL_CTL_ADD, conn->sock, &ee)) {
        LOG(LOG_ERROR, "efd=%d conn=%d add error: %s\n", net_thread->efd, conn->sock, strerror(errno));
        assert(0);
        return -1;
    }
    net_thread->event_add++;
    return 0;
}

int net_thread_event_mod(struct net_thread_t *net_thread, struct conn_t *conn, uint32_t events)
{
    struct epoll_event ee;

    ee.events = EPOLLET;
    if (events & CONN_READ) {
        ee.events |= EPOLLIN;
    }
    if (events & CONN_WRITE) {
        ee.events |= EPOLLOUT;
    }
    ee.data.ptr = conn;
    if (epoll_ctl(net_thread->efd, EPOLL_CTL_MOD, conn->sock, &ee)) {
        LOG(LOG_ERROR, "efd=%d conn=%d mod error: %s\n", net_thread->efd, conn->sock, strerror(errno));
        assert(0);
        return -1;
    }
    net_thread->event_mod++;
    return 0;
}

int net_thread_event_del(struct net_thread_t *net_thread, struct conn_t *conn)
{
    struct epoll_event ee;

    ee.events = 0;
    ee.data.ptr = NULL;
    if (epoll_ctl(net_thread->efd, EPOLL_CTL_DEL, conn->sock, &ee)) {
        LOG(LOG_ERROR, "efd=%d conn=%d del error: %s\n", net_thread->efd, conn->sock, strerror(errno));
        assert(0);
        return -1;
    }
    net_thread->event_del++;
    return 0;
}

int net_thread_event_wait(struct net_thread_t *net_thread)
{
    struct epoll_event ees[EPOLL_FD_MAX];
    struct conn_t *conn;
    int i, nfds;

    nfds = epoll_wait(net_thread->efd, ees, EPOLL_FD_MAX, net_thread->ready_num > 0 ? 0 : 100);
    for (i = 0; i < nfds; i++) {
        conn = ees[i].data.ptr;
        if (ees[i].events & (EPOLLIN | EPOLLERR | EPOLLHUP)) {
            conn->flags.read_ready = 1;
            if (conn->flags.read_enable && !conn->flags.in_ready_list) {
                list_add_tail(&conn->ready_node, &net_thread->ready_list);
                conn->flags.in_ready_list = 1;
                net_thread->ready_num++;
            }
        }
        if (ees[i].events & (EPOLLOUT | EPOLLERR | EPOLLHUP)) {
            conn->flags.write_ready = 1;
            if (conn->flags.write_enable && !conn->flags.in_ready_list) {
                list_add_tail(&conn->ready_node, &net_thread->ready_list);
                conn->flags.in_ready_list = 1;
                net_thread->ready_num++;
            }
        }
    }
    return nfds;
}

int net_thread_event_clean(struct net_thread_t *net_thread)
{
    LOG(LOG_INFO, "%s efd %d close\n", net_thread->name, net_thread->efd);
    close(net_thread->efd);
    return 0;
}

static void net_thread_time_update(struct net_thread_t *net_thread)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);
    net_thread->time_current = tv.tv_sec * 1000  + tv.tv_usec / 1000;
}

void net_thread_aio_add(struct aio_t *aio)
{
    struct net_thread_t *net_thread = aio->net_thread;
    struct conn_t *conn;

    pthread_mutex_lock(&net_thread->aio_mutex);
    list_add_tail(&aio->node, &net_thread->aio_list);
    if (net_thread->signaled) {
        conn = NULL;
    } else {
        net_thread->signaled = 1;
        conn = net_thread->conns[1];
    }
    pthread_mutex_unlock(&net_thread->aio_mutex);
    if (conn) {
        write(conn->sock, "1", 1);
    }
}

void net_thread_aio_call(struct aio_t *aio)
{
    aio_handle_t aio_handle;

    aio_handle = aio->exec;
    aio->exec = NULL;
    aio_handle(aio);
}

static void net_thread_pipe_read(struct conn_t *conn)
{
    struct net_thread_t *net_thread = conn->net_thread;
    char buf[4096];
    ssize_t n;

    n = read(conn->sock, buf, sizeof(buf));
    if (n > 0) {
        LOG(LOG_DEBUG, "sock=%d read=%zd\n", conn->sock, n);
        conn_enable(conn, CONN_READ);
    } else if(n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        net_thread->signaled = 0;
        conn_ready_unset(conn, CONN_READ);
        conn_enable(conn, CONN_READ);
    } else {
        LOG(LOG_ERROR, "sock=%d read=%zd error: %s\n", conn->sock, n, strerror(errno));
    }
}

int net_thread_init(struct net_thread_t *net_thread)
{
    int fds[2];
    struct conn_t *conn;

    if (net_thread_event_init(net_thread)) {
        LOG(LOG_ERROR, "%s net_thread_event_init error: %s\n", net_thread->name, strerror(errno));
        return -1;
    }
    if (pipe(fds)) {
        LOG(LOG_ERROR, "%s pipe error: %s\n", net_thread->name, strerror(errno));
        close(net_thread->efd);
        return -1;
    }
    INIT_LIST_HEAD(&net_thread->ready_list);
    INIT_LIST_HEAD(&net_thread->aio_list);
    pthread_mutex_init(&net_thread->aio_mutex, NULL);
    net_thread->timer_root = RB_ROOT;
    net_thread->keepalive_root = RB_ROOT;

    conn = conn_alloc();
    conn->sock = fds[0];
    conn_nonblock(conn);
    conn->net_thread = net_thread;
    conn->handle_read = net_thread_pipe_read;
    net_thread->conns[0] = conn;

    conn = conn_alloc();
    conn->sock = fds[1];
    conn_nonblock(conn);
    conn->net_thread = net_thread;
    net_thread->conns[1] = conn;

    LOG(LOG_INFO, "%s efd=%d pipe=(%d %d)\n", net_thread->name, net_thread->efd, fds[0], fds[1]);
    conn_enable(net_thread->conns[0], CONN_READ);
    return 0;
}

void *net_thread_loop(void *data)
{
    struct net_thread_t *net_thread = data;
    int loop;
    struct list_head_t aio_list;
    struct conn_t *conn;
    struct rb_node *rb_node;
    struct aio_t *aio;

    log_thread_name(net_thread->name);
    INIT_LIST_HEAD(&aio_list);
    while (1) {
        loop = 0;
        net_thread_event_wait(net_thread);
        net_thread_time_update(net_thread);
        while (!list_empty(&net_thread->ready_list) && loop++ < 100) {
            conn = d_list_head(&net_thread->ready_list, struct conn_t, ready_node);
            list_del(&conn->ready_node);
            conn->flags.in_ready_list = 0;
            net_thread->ready_num--;
            conn->flags.lock = 1;
            if (conn->flags.read_enable && conn->flags.read_ready) {
                conn->handle_read(conn);
            }
            if (conn->flags.write_enable && conn->flags.write_ready) {
                conn->handle_write(conn);
            }
            conn->flags.lock = 0;
            if (conn->flags.closed) {
                conn_free(conn);
            }
        }
        pthread_mutex_lock(&net_thread->aio_mutex);
        list_splice_init(&net_thread->aio_list, &aio_list);
        pthread_mutex_unlock(&net_thread->aio_mutex);
        while (!list_empty(&aio_list)) {
            aio = d_list_head(&aio_list, struct aio_t, node);
            list_del(&aio->node);
            net_thread_aio_call(aio);
        }
        if (net_thread->time_current - net_thread->timer_last >= TIMER_PERIOD) {
            while ((rb_node = rb_first(&net_thread->timer_root))) {
                conn = rb_entry(rb_node, struct conn_t, timer_node);
                if (net_thread->time_current >= conn->timer_expire) {
                    conn_timer_unset(conn);
                    conn->handle_timeout(conn);
                } else {
                    break;
                }
            }
            net_thread->timer_last = net_thread->time_current;
        }
        if (net_thread->exit) {
            while ((rb_node = rb_first(&net_thread->timer_root))) {
                conn = rb_entry(rb_node, struct conn_t, timer_node);
                conn_timer_unset(conn);
                conn->handle_timeout(conn);
            }
            break;
        }
    }
    return NULL;
}

void net_thread_clean(struct net_thread_t *net_thread)
{
    conn_close(net_thread->conns[0]);
    conn_close(net_thread->conns[1]);
    net_thread_event_clean(net_thread);
    pthread_mutex_destroy(&net_thread->aio_mutex);
    LOG(LOG_INFO, "event_add=%"PRId64" event_mod=%"PRId64" event_del=%"PRId64"\n",
            net_thread->event_add, net_thread->event_mod, net_thread->event_del);
}
