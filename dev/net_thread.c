#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/time.h>
#include <sys/epoll.h>

#include "list.h"
#include "mem.h"
#include "log.h"
#include "task_thread.h"
#include "net_thread.h"

#define EPOLL_FD_MAX 1024


struct net_thread_t *net_threads = NULL;
int net_threads_num = 0;

static int net_thread_event_init(struct net_thread_t *net_thread)
{
    net_thread->efd = epoll_create(EPOLL_FD_MAX);
    if (net_thread->efd < 0) {
        LOG(LOG_ERROR, "%s epoll_create efd=%d error: %s\n", net_thread->name, net_thread->efd, strerror(errno));
        return -1;
    }
    LOG(LOG_INFO, "%s epoll_create efd=%d ok\n", net_thread->name, net_thread->efd);
    return 0;
}

static int net_thread_event_uninit(struct net_thread_t *net_thread)
{
    LOG(LOG_INFO, "%s efd=%d close\n", net_thread->name, net_thread->efd);
    close(net_thread->efd);
    return 0;
}

static int net_thread_event_wait(struct net_thread_t *net_thread, int timeout)
{
    struct epoll_event ees[EPOLL_FD_MAX];
    struct conn_t *conn;
    int i, nfds;

    nfds = epoll_wait(net_thread->efd, ees, EPOLL_FD_MAX, timeout);
    for (i = 0; i < nfds; i++) {
        conn = ees[i].data.ptr;
        if (ees[i].events & (EPOLLIN | EPOLLERR | EPOLLHUP)) {
            conn_read_ready(conn, 1);
            if (!conn->flags.active) {
                list_add_tail(&conn->active_node, &net_thread->active_list);
                conn->flags.active = 1;
            }
        }
        if (ees[i].events & (EPOLLOUT | EPOLLERR | EPOLLHUP)) {
            conn_write_ready(conn, 1);
            if (!conn->flags.active) {
                list_add_tail(&conn->active_node, &net_thread->active_list);
                conn->flags.active = 1;
            }
        }
    }
    return 0;
}


static int net_thread_init(struct net_thread_t *net_thread)
{
    int fds[2];
    struct conn_t *conn;

    if (net_thread_event_init(net_thread)) {
        return -1;
    }

    if (pipe(fds)) {
        LOG(LOG_ERROR, "%s pipe error: %s\n", net_thread->name, strerror(errno));
        net_thread_event_uninit(net_thread);
        return -1;
    }

    pthread_mutex_init(&net_thread->mutex, NULL);
    INIT_LIST_HEAD(&net_thread->task_list);
    net_thread->timer_root = RB_ROOT;
    INIT_LIST_HEAD(&net_thread->active_list);

    net_thread->conns[0] = conn = mem_malloc(sizeof(struct conn_t));
    memset(conn, 0, sizeof(struct conn_t));
    conn->net_thread = net_thread;
    conn->sock = fds[0];
    conn_nonblock(conn);
    conn->handle = net_thread_pipe_read;

    net_thread->conns[1] = conn = mem_malloc(sizeof(struct conn_t));
    memset(conn, 0, sizeof(struct conn_t));
    conn->net_thread = net_thread;
    conn->sock = fds[1];
    conn_nonblock(conn);
    conn->handle = net_thread_pipe_write;

    LOG(LOG_DEBUG, "sock=%d open\n", net_thread->conns[0]->sock);
    LOG(LOG_DEBUG, "sock=%d open\n", net_thread->conns[1]->sock);
    conn_events_select(net_thread->conns[0], CONN_EVENT_READ);
    return 0;
}

static int net_thread_uninit(struct net_thread_t *net_thread)
{
    return 0;
}

static void *net_thread_loop(void *arg)
{
    struct net_thread_t *net_thread = (struct net_thread_t *)arg;
    struct conn_t *conn;
    struct rb_node *rb_node;
    struct task_t *task;
    struct list_head_t task_list;
    struct timeval tv;
    int events;
    int loop;

    pthread_setname_np(pthread_self(), net_thread->name);
    log_set_thread_name(net_thread->name);
    LOG(LOG_INFO, "%s run\n", net_thread->name);
    INIT_LIST_HEAD(&task_list);
    while (1) {
        loop = 0;
        net_thread_event_wait(net_thread, list_empty(&net_thread->active_list) ? 0 : 100);
        gettimeofday(&tv, NULL);
        net_thread->time = tv.tv_sec * 1000  + tv.tv_usec / 1000;
        while (!list_empty(&net_thread->active_list) && loop++ < 100) {
            conn = d_list_head(&net_thread->active_list, struct conn_t, active_node);
            list_del(&conn->active_node);
            conn->flags.active = 0;
            events = CONN_EVENT_NONE;
            if (conn->flags.read_ready) {
                events |= CONN_EVENT_READ;
            }
            if (conn->flags.write_ready) {
                events |= CONN_EVENT_WRITE;
            }
            conn->handle(conn, events);
        }
        pthread_mutex_lock(&net_thread->mutex);
        list_splice_init(&net_thread->task_list, &task_list);
        net_thread->notified = 1;
        pthread_mutex_unlock(&net_thread->mutex);
        while (!list_empty(&task_list)) {
            task = d_list_head(&task_list, struct task_t, node);
            list_del(&task->node);
            task->handle(task);
        }
        if (net_thread->time >= net_thread->timer_expire) {
            while ((rb_node = rb_first(&net_thread->timer_root))) {
                conn = rb_entry(rb_node, struct conn_t, timer_node);
                if (net_thread->time >= conn->timer_expire) {
                    conn_timer_del(conn);
                    conn->handle(conn, CONN_EVENT_TIMEOUT);
                } else {
                    break;
                }
            }
        }
        if (net_thread->stop) {
            break;
        }
    }
    LOG(LOG_INFO, "%s exit\n", net_thread->name);
    return NULL;
}

int net_threads_create(int num)
{
    int i;

    net_threads = (struct net_thread_t *)mem_malloc(sizeof(struct net_thread_t) * num);
    memset(net_threads, 0, sizeof(struct net_thread_t) * num);
    for (i = 0; i < num; i++) {
        snprintf(net_threads[i].name, sizeof(net_threads[i].name), "net_%d", i);
        if (net_thread_init(&net_threads[i])) {
            break;
        }
        if (pthread_create(&net_threads[i].tid, NULL, net_thread_loop, &net_threads[i])) {
            LOG(LOG_ERROR, "%s pthread_create error\n", net_threads[i].name);
            net_thread_uninit(&net_threads[i]);
            break;
        }
    }
    net_threads_num = i;
    return net_threads_num;
}

int net_threads_exit()
{
    int i;

    for (i = 0; i < net_threads_num; i++) {
        pthread_mutex_lock(&net_threads[i].mutex);
        net_threads[i].stop = 1;
        pthread_mutex_unlock(&net_threads[i].mutex);
        pthread_join(net_threads[i].tid, NULL);
        net_thread_uninit(&net_threads[i]);
    }

    mem_free(net_threads);
    net_threads = NULL;
    net_threads_num = 0;
    return 0;
}
