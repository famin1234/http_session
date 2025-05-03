#include "mem.h"
#include "task_thread.h"
#include "net_thread.h"
#include "log.h"
#include "http_session.h"

#define URL_SIZE 256
#define HOST_SIZE 256

#define HTTP_CLIENT_TIMEOUT    (1000 * 5)
#define HTTP_SERVER_TIMEOUT    (1000 * 5)

static void http_listen_task_run(struct task_t *task);
static void http_client_accept(struct conn_t *conn, int events);

struct http_listen_task_t {
    struct task_t task;
    char host[HOST_SIZE];
    unsigned short port;
    struct net_loop_t *net_loop;
};

int http_session_init()
{
    int i;

    struct http_listen_task_t *http_listen_task;
    for (i = 0; i < net_threads_num; i++) {
        http_listen_task = (struct http_listen_task_t *)mem_malloc(sizeof(struct http_listen_task_t));
        http_listen_task->task.handle = http_listen_task_run;
        http_listen_task->task.arg = http_listen_task;
        strncpy(http_listen_task->host, "0.0.0.0", sizeof(http_listen_task->host));
        http_listen_task->port = 8080;
        http_listen_task->net_loop = &net_threads[i].net_loop;
        net_loop_post(&net_threads[i].net_loop, &http_listen_task->task);
    }
    return 0;
}

int http_session_uninit()
{
    return 0;
}

static void http_listen_task_run(struct task_t *task)
{
    struct http_listen_task_t *http_listen_task = (struct http_listen_task_t *)task->arg;
    struct conn_addr_t conn_addr;
    struct conn_t *conn;

    if (conn_addr_pton(&conn_addr, http_listen_task->host, http_listen_task->port) > 0) {
        if (conn_listen(&conn, &conn_addr)) {
        } else {
            conn_nonblock(conn);
            conn->handle = http_client_accept;
            conn->net_loop = http_listen_task->net_loop;
            conn_events_add(conn, CONN_EVENT_READ);
        }
    }
    mem_free(http_listen_task);
}

static void http_client_accept(struct conn_t *conn, int events)
{
    LOG(LOG_DEBUG, "sock=%d\n", conn->sock);
}
