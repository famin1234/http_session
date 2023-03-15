#include "mem.h"
#include "log.h"
#include "aio.h"
#include "net.h"

static struct list_head_t net_listen_list;
struct net_thread_t *net_threads = NULL;
int net_threads_num = 0;

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
    struct conn_addr_t conn_addr;

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

static int net_listen(net_socket_t sock, struct conn_addr_t *conn_addr)
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
    if (bind(sock, &conn_addr->addr, conn_addr->addrlen) != 0) {
        return -1;
    }
    if (listen(sock, LISTEN_MAX)) {
        return -1;
    }
    return 0;
}

int conn_addr_pton(struct conn_addr_t *conn_addr, const char *host, unsigned short port)
{
    if (inet_pton(AF_INET, host, &conn_addr->in.sin_addr) == 1) {
        conn_addr->in.sin_family = AF_INET;
        conn_addr->in.sin_port = htons(port);
        conn_addr->addrlen = sizeof(struct sockaddr_in);
        return 1;
    }
    if (inet_pton(AF_INET6, host, &conn_addr->in6.sin6_addr) == 1) {
        conn_addr->in6.sin6_family = AF_INET6;
        conn_addr->in6.sin6_port = htons(port);
        conn_addr->in6.sin6_flowinfo = 0;
        conn_addr->in6.sin6_scope_id = 0;
        conn_addr->addrlen = sizeof(struct sockaddr_in6);
        return 1;
    }
    return -1;
}

const char *conn_addr_ntop(struct conn_addr_t *conn_addr, char *buf, socklen_t size)
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

uint16_t conn_addr_port(struct conn_addr_t *conn_addr)
{
    if (conn_addr->addr.sa_family == AF_INET) {
        return ntohs(conn_addr->in.sin_port);
    } else if (conn_addr->addr.sa_family == AF_INET6) {
        return ntohs(conn_addr->in6.sin6_port);
    }
    return 0;
}

int conn_addr_compare(const struct conn_addr_t *conn_addr1, const struct conn_addr_t *conn_addr2)
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
    if (conn->flag.lock) {
        conn->flag.closed = 1;
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
    int flags, r;
    while ((flags = fcntl(conn->sock, F_GETFL, 0)) == -1 && errno == EINTR);
    if (flags == -1) {
        return -1;
    }
    while ((r = fcntl(conn->sock, F_SETFL, flags | O_NONBLOCK)) == -1 && errno == EINTR);
    if (r == -1) {
        return -1;
    }
    return 0;
}

void conn_enable(struct conn_t *conn, int flag)
{
    struct net_thread_t *net_thread = conn->net_thread;
    int err;
    struct epoll_event ev;
    int op;

    ev.events = conn->events;
    if (flag & CONN_READ) {
        conn->flag.read_enable = 1;
        if (conn->flag.read_ready) {
            if (!conn->flag.in_ready_list) {
                list_add_tail(&conn->ready_node, &net_thread->ready_list);
                conn->flag.in_ready_list = 1;
                net_thread->ready_num++;
            }
        } else {
            ev.events |= EPOLLIN;
        }
    }
    if (flag & CONN_WRITE) {
        conn->flag.write_enable = 1;
        if (conn->flag.write_ready) {
            if (!conn->flag.in_ready_list) {
                list_add_tail(&conn->ready_node, &net_thread->ready_list);
                conn->flag.in_ready_list = 1;
                net_thread->ready_num++;
            }
        } else {
            ev.events |= EPOLLOUT;
        }
    }
    if (ev.events != conn->events) {
        ev.data.ptr = conn;
        if (conn->events) {
            op = EPOLL_CTL_MOD;
            net_thread->event_mod++;
        } else {
            ev.events |= EPOLLET;
            op = EPOLL_CTL_ADD;
            net_thread->event_add++;
        }
        err = epoll_ctl(net_thread->efd, op, conn->sock, &ev);
        if (err) {
            LOG(LOG_ERROR, "efd=%d conn=%d op=%d error: %s\n", net_thread->efd, conn->sock, op, strerror(errno));
            assert(0);
        } else {
            conn->events = ev.events;
        }
    }
}

void conn_disable(struct conn_t *conn, int flag)
{
    struct net_thread_t *net_thread = conn->net_thread;
    int err;
    struct epoll_event ev;
    int op;

    ev.events = conn->events;
    if (flag & CONN_READ) {
        conn->flag.read_enable = 0;
        ev.events &= (~EPOLLIN);
    }
    if (flag & CONN_WRITE) {
        conn->flag.write_enable = 0;
        ev.events &= (~EPOLLOUT);
    }
    if (ev.events != conn->events) {
        ev.data.ptr = conn;
        if (ev.events & (EPOLLIN | EPOLLOUT)) {
            op = EPOLL_CTL_MOD;
            net_thread->event_mod++;
        } else {
            ev.events = 0;
            op = EPOLL_CTL_DEL;
            net_thread->event_del++;
        }
        err = epoll_ctl(net_thread->efd, op, conn->sock, &ev);
        if (err) {
            LOG(LOG_ERROR, "efd=%d conn=%d op=%d error: %s\n", net_thread->efd, conn->sock, op, strerror(errno));
            assert(0);
        } else {
            conn->events = ev.events;
        }
    }
    if (conn->flag.read_enable == 0 && conn->flag.write_enable == 0) {
        if (conn->flag.in_ready_list) {
            list_del(&conn->ready_node);
            conn->flag.in_ready_list = 0;
            net_thread->ready_num--;
        }
    }
}

void conn_ready_set(struct conn_t *conn, int flag)
{
    if (flag & CONN_READ) {
        conn->flag.read_ready = 1;
    }
    if (flag & CONN_WRITE) {
        conn->flag.write_ready = 1;
    }
}

void conn_ready_unset(struct conn_t *conn, int flag)
{
    if (flag & CONN_READ) {
        conn->flag.read_ready = 0;
    }
    if (flag & CONN_WRITE) {
        conn->flag.write_ready = 0;
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

    if (timeout < INT64_MAX - net_thread->time_current) {
        expire = net_thread->time_current + timeout;
    } else {
        expire = INT64_MAX;
    }
    if (conn->flag.timer_set) {
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
            conn->flag.timer_set = 1;
        }
    }
}

void conn_timer_unset(struct conn_t *conn)
{
    struct net_thread_t *net_thread = conn->net_thread;

    if (conn->flag.timer_set) {
        rb_erase(&conn->timer_node, &net_thread->timer_root);
        conn->flag.timer_set = 0;
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

struct conn_t *conn_keepalive_get(struct net_thread_t *net_thread, struct conn_addr_t *peer_addr)
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

static void net_thread_time_update(struct net_thread_t *net_thread)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);
    net_thread->time_current = tv.tv_sec * 1000  + tv.tv_usec / 1000;
}

static int net_thread_init(struct net_thread_t *net_thread)
{
    int fds[2];
    struct conn_t *conn;

    net_thread->efd = epoll_create(EPOLL_FD_MAX);
    if (net_thread->efd < 0) {
        LOG(LOG_ERROR, "%s epoll_create error: %s\n", net_thread->name, strerror(errno));
        return -1;
    }
    if (pipe(fds)) {
        LOG(LOG_ERROR, "%s pipe error: %s\n", net_thread->name, strerror(errno));
        close(net_thread->efd);
        return -1;
    }
    INIT_LIST_HEAD(&net_thread->ready_list);
    INIT_LIST_HEAD(&net_thread->done_list);
    pthread_mutex_init(&net_thread->done_mutex, NULL);
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

    net_thread_time_update(net_thread);
    LOG(LOG_INFO, "%s efd=%d pipe=(%d %d)\n", net_thread->name, net_thread->efd, fds[0], fds[1]);
    conn_enable(net_thread->conns[0], CONN_READ);
    return 0;
}

static void *net_thread_loop(void *data)
{
    struct net_thread_t *net_thread = data;
    struct epoll_event ees[EPOLL_FD_MAX];
    int i, nfds, loop;
    struct list_head_t done_list;
    struct conn_t *conn;
    struct rb_node *rb_node;
    struct aio_t *aio;

    log_thread_name(net_thread->name);
    INIT_LIST_HEAD(&done_list);
    while (1) {
        nfds = epoll_wait(net_thread->efd, ees, EPOLL_FD_MAX, net_thread->ready_num > 0 ? 0 : 100);
        net_thread_time_update(net_thread);
        for (i = 0; i < nfds; i++) {
            conn = ees[i].data.ptr;
            if (ees[i].events & (EPOLLIN | EPOLLERR | EPOLLHUP)) {
                conn->flag.read_ready = 1;
                if (conn->flag.read_enable && !conn->flag.in_ready_list) {
                    list_add_tail(&conn->ready_node, &net_thread->ready_list);
                    conn->flag.in_ready_list = 1;
                    net_thread->ready_num++;
                }
            }
            if (ees[i].events & (EPOLLOUT | EPOLLERR | EPOLLHUP)) {
                conn->flag.write_ready = 1;
                if (conn->flag.write_enable && !conn->flag.in_ready_list) {
                    list_add_tail(&conn->ready_node, &net_thread->ready_list);
                    conn->flag.in_ready_list = 1;
                    net_thread->ready_num++;
                }
            }
        }
        loop = 0;
        while (!list_empty(&net_thread->ready_list) && loop++ < 100) {
            conn = d_list_head(&net_thread->ready_list, struct conn_t, ready_node);
            list_del(&conn->ready_node);
            conn->flag.in_ready_list = 0;
            net_thread->ready_num--;
            conn->flag.lock = 1;
            if (conn->flag.read_enable && conn->flag.read_ready) {
                conn->handle_read(conn);
            }
            if (conn->flag.write_enable && conn->flag.write_ready) {
                conn->handle_write(conn);
            }
            conn->flag.lock = 0;
            if (conn->flag.closed) {
                conn_free(conn);
            }
        }
        pthread_mutex_lock(&net_thread->done_mutex);
        list_splice_init(&net_thread->done_list, &done_list);
        pthread_mutex_unlock(&net_thread->done_mutex);
        while (!list_empty(&done_list)) {
            aio = d_list_head(&done_list, struct aio_t, node);
            list_del(&aio->node);
            aio_handle_done(aio);
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
    LOG(LOG_INFO, "event_add=%"PRId64" event_mod=%"PRId64" event_del=%"PRId64"\n",
            net_thread->event_add, net_thread->event_mod, net_thread->event_del);
    return NULL;
}

static void net_thread_clean(struct net_thread_t *net_thread)
{
    conn_close(net_thread->conns[0]);
    conn_close(net_thread->conns[1]);
    close(net_thread->efd);
    LOG(LOG_INFO, "%s efd %d close\n", net_thread->name, net_thread->efd);
    pthread_mutex_destroy(&net_thread->done_mutex);
}

void net_thread_aio_add(struct aio_t *aio)
{
    struct net_thread_t *net_thread = aio->net_thread;
    struct conn_t *conn;

    pthread_mutex_lock(&net_thread->done_mutex);
    list_add_tail(&aio->node, &net_thread->done_list);
    if (net_thread->signaled) {
        conn = NULL;
    } else {
        net_thread->signaled = 1;
        conn = net_thread->conns[1];
    }
    pthread_mutex_unlock(&net_thread->done_mutex);
    if (conn) {
        write(conn->sock, "1", 1);
    }
}

int net_threads_run(int num)
{
    struct conn_t *conn;
    net_socket_t sock;
    struct net_listen_t *nl;
    char str[64];
    int i;

    assert(net_threads_num == 0);
    net_threads_num = num;
    net_threads = mem_malloc(sizeof(struct net_thread_t) * net_threads_num);
    memset(net_threads, 0, sizeof(struct net_thread_t) * net_threads_num);
    for (i = 0; i < net_threads_num; i++) {
        snprintf(net_threads[i].name, sizeof(net_threads[i].name), "net[%d]", i);
        if (net_thread_init(&net_threads[i])) {
            LOG(LOG_ERROR, "%s net_thread_init error\n", net_threads[i].name);
            assert(0);
        }
    }
    list_for_each_entry(nl, &net_listen_list, node) {
        for (i = 0; i < net_threads_num; i++) {
            if (i == 0) {
                sock = socket(nl->conn_addr.addr.sa_family, SOCK_STREAM, IPPROTO_TCP);
                if (sock < 0) {
                    LOG(LOG_ERROR, "%s sock=%d %s error:%s\n", net_threads[i].name, sock, conn_addr_ntop(&nl->conn_addr, str, sizeof(str)), strerror(errno));
                    break;
                }
                if (net_listen(sock, &nl->conn_addr)) {
                    LOG(LOG_ERROR, "%s sock=%d %s listen error: %s\n", net_threads[i].name, sock, conn_addr_ntop(&nl->conn_addr, str, sizeof(str)), strerror(errno));
                    close(sock);
                    break;
                }
                LOG(LOG_INFO, "%s sock=%d %s listen ok\n", net_threads[i].name, sock, conn_addr_ntop(&nl->conn_addr, str, sizeof(str)));
            } else {
                sock = dup(sock);
                if (sock < 0) {
                    LOG(LOG_ERROR, "%s sock=%d %s listen dup error: %s\n", net_threads[i].name, sock, conn_addr_ntop(&nl->conn_addr, str, sizeof(str)), strerror(errno));
                    break;
                }
                LOG(LOG_INFO, "%s sock=%d %s listen dup ok\n", net_threads[i].name, sock, conn_addr_ntop(&nl->conn_addr, str, sizeof(str)));
            }
            conn = conn_alloc();
            conn->sock = sock;
            conn->peer_addr = nl->conn_addr;
            conn->net_thread = &net_threads[i];
            conn_nonblock(conn);
            conn->handle_read = nl->handle;
            conn->handle_write = NULL;
            conn->handle_timeout = conn_close;
            conn->data = NULL;
            conn_timer_set(conn, INT64_MAX);
            conn_enable(conn, CONN_READ);
        }
    }
    for (i = 0; i < net_threads_num; i++) {
        if (pthread_create(&net_threads[i].tid, NULL, net_thread_loop, &net_threads[i])) {
            LOG(LOG_ERROR, "%s pthread_create error\n", net_threads[i].name);
            assert(0);
        }
    }
    return 0;
}

void net_threads_signal_exit()
{
    int i;

    for (i = 0; i < net_threads_num; i++) {
        net_threads[i].exit = 1;
    }
}

void net_threads_join()
{
    int i;

    for (i = 0; i < net_threads_num; i++) {
        pthread_join(net_threads[i].tid, NULL);
    }
    for (i = 0; i < net_threads_num; i++) {
        net_thread_clean(&net_threads[i]);
    }
    mem_free(net_threads);
    net_threads = NULL;
    net_threads_num = 0;
}
