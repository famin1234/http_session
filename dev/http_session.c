#include <stdlib.h>
#include "mem.h"
#include "task_thread.h"
#include "net_thread.h"
#include "log.h"
#include "http_header.h"
#include "http_session.h"

#define PAGE_SIZE 4096
#define URL_SIZE 256
#define HOST_SIZE 256

#define HTTP_CLIENT_TIMEOUT    (1000 * 5)
#define HTTP_SERVER_TIMEOUT    (1000 * 5)
#define HTTP_ACCEPT_TIMEOUT    (1000 * 5)

enum http_client_state_t {
    HTTP_CLIENT_HEADER_READ,
    HTTP_CLIENT_BODY_READ,
    HTTP_CLIENT_HEADER_WRITE,
    HTTP_CLIENT_BODY_WRITE,
    HTTP_CLIENT_DONE,
};

struct http_listen_task_t {
    struct task_t task;
    struct net_loop_t *net_loop;
    struct conn_addr_t conn_addr;
};

struct buffer_t {
    size_t len;
    size_t size;
    char buf[0];
};

struct http_client_t {
    struct conn_t *conn;
    struct http_parser http_parser;
    struct http_header_t http_header;
    size_t header_len;
    int64_t post_end;
    struct buffer_t *pipeline;

    enum http_client_state_t state;
    struct {
        int transparent:1;
        int keepalive:1;
    } flags;
};

static void http_listen_task_run(struct task_t *task);
static int http_client_accept(struct conn_t *conn_listen);
static int http_client_accept_timeout(struct conn_t *conn_listen);
static void http_client_create(struct conn_t *conn);
static int http_client_header_read(struct conn_t *conn);
static int http_client_timeout(struct conn_t *conn);
static int http_client_close(struct conn_t *conn, int err);

int http_session_init()
{
    int i;
    struct conn_addr_t conn_addr;
    struct http_listen_task_t *http_listen_task;

    if (conn_addr_pton(&conn_addr, "0.0.0.0", 8080) > 0) {
        for (i = 0; i < net_threads_num; i++) {
            http_listen_task = (struct http_listen_task_t *)mem_malloc(sizeof(struct http_listen_task_t));
            http_listen_task->task.handle = http_listen_task_run;
            http_listen_task->task.arg = http_listen_task;
            http_listen_task->conn_addr = conn_addr;
            http_listen_task->net_loop = &net_threads[i].net_loop;
            net_loop_post(&net_threads[i].net_loop, &http_listen_task->task);
        }
    }
    return 0;
}

int http_client_uninit()
{
    return 0;
}

static void http_listen_task_run(struct task_t *task)
{
    struct http_listen_task_t *http_listen_task = (struct http_listen_task_t *)task->arg;
    int sock;
    struct conn_t *conn;

    sock = socket_listen(&http_listen_task->conn_addr);
    if (sock > 0) {
        conn = (struct conn_t *)mem_malloc(sizeof(struct conn_t));
        memset(conn, 0, sizeof(struct conn_t));
        conn->sock = sock;
        conn->peer_addr = http_listen_task->conn_addr;
        conn->net_loop = http_listen_task->net_loop;
        conn_nonblock(conn);
        conn->handle_read= http_client_accept;
        conn_events_add(conn, CONN_EVENT_READ);
        conn->handle_timeout= http_client_accept_timeout;
        conn_timer_add(conn, HTTP_ACCEPT_TIMEOUT);
    };
    mem_free(http_listen_task);
}

static int http_client_accept(struct conn_t *conn_listen)
{
    int sock;
    struct conn_t *conn;
    struct conn_addr_t peer_addr;
    socklen_t addrlen;
    char str[64];

    addrlen = sizeof(struct conn_addr_t);
    sock = accept(conn_listen->sock, &peer_addr.addr, &addrlen);
    if (sock > 0) {
        LOG(LOG_DEBUG, "sock=%d accept=%d %s\n", conn_listen->sock, sock, conn_addr_ntop(&peer_addr, str, sizeof(str)));
        conn_events_add(conn_listen, CONN_EVENT_READ);

        conn = (struct conn_t *)mem_malloc(sizeof(struct conn_t));
        memset(conn, 0, sizeof(struct conn_t));
        conn->sock = sock;
        conn->peer_addr = peer_addr;
        conn->net_loop = conn_listen->net_loop;
        http_client_create(conn);
    } else if(sock == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        LOG(LOG_DEBUG, "sock=%d accept=%d EAGAIN\n", conn_listen->sock, sock);
        conn_listen->flags.read_ready = 0;
        conn_events_add(conn_listen, CONN_EVENT_READ);
    } else {
        conn_events_add(conn_listen, CONN_EVENT_READ);
        LOG(LOG_ERROR, "sock=%d accept=%d error:%s\n", conn_listen->sock, sock, strerror(errno));
    }
    return 0;
}

static int http_client_accept_timeout(struct conn_t *conn_listen)
{
    LOG(LOG_ERROR, "sock=%d timeout\n", conn_listen->sock);
    conn_timer_add(conn_listen, HTTP_ACCEPT_TIMEOUT);
    return 0;
}

static void http_client_create(struct conn_t *conn)
{
    struct http_client_t *http_client;

    conn->arg = http_client = (struct http_client_t *)mem_malloc(sizeof(struct http_client_t));
    memset(http_client, 0, sizeof(struct http_client_t));
    http_client->conn = conn;
    http_header_init(&http_client->http_header);
    http_parser_init(&http_client->http_parser, HTTP_REQUEST);
    http_client->http_parser.data = &http_client->http_header;

    conn_nonblock(conn);
    conn->handle_read = http_client_header_read;
    conn_events_add(conn, CONN_EVENT_READ);
    conn->handle_timeout= http_client_timeout;
    conn_timer_add(conn, HTTP_CLIENT_TIMEOUT);
}

static int http_client_header_read(struct conn_t *conn)
{
    struct http_client_t *http_client = conn->arg;
    char buf[PAGE_SIZE];
    ssize_t n;
    size_t nparse;
    char *url;
    const char *value;

    n = recv(conn->sock, buf, sizeof(buf), 0);
    if (n > 0) {
        LOG(LOG_DEBUG, "url=%s sock=%d recv=%zd\n", http_client->http_header.url, conn->sock, n);
    } else if (n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        LOG(LOG_DEBUG, "url=%s sock=%d recv=%zd EAGIN\n", http_client->http_header.url, conn->sock, n);
        conn->flags.read_ready = 0;
        conn_events_add(conn, CONN_EVENT_READ);
        return 0;
    } else {
        LOG(LOG_ERROR, "url=%s sock=%d recv=%zd error:%s\n", http_client->http_header.url, conn->sock, n, strerror(errno));
        conn_timer_del(conn);
        return http_client_close(conn, -1);
    }
    nparse = http_parser_execute(&http_client->http_parser, &http_header_parser_settings, buf, n);
    if (nparse > 0) {
        http_client->header_len += nparse;
        LOG(LOG_DEBUG, "url=%s sock=%d recv=%zd nparse=%zu header_len=%zu\n",
                http_client->http_header.url, conn->sock, n, nparse, http_client->header_len);
        if (http_client->http_parser.http_errno == HPE_CB_message_complete) {
            if (http_client->http_header.url[0] == '/') {
                http_client->flags.transparent = 1;
                value = http_header_find(&http_client->http_header, "Host");
                if (value) {
                    url = mem_malloc(strlen("http://") + strlen(value) + strlen(http_client->http_header.url) + 1);
                    strcpy(url, "http://");
                    strcat(url, value);
                    strcat(url, http_client->http_header.url);
                    mem_free(http_client->http_header.url);
                    http_client->http_header.url = url;
                }
            }
            if (http_client->http_header.method == HTTP_POST || http_client->http_header.method == HTTP_PUT) {
                value = http_header_find(&http_client->http_header, "Content-Length");
                if (value) {
                    http_client->post_end = atoll(value);
                    if (http_client->post_end < 0) {
                        http_client->post_end = 0;
                    }
                }
            } else if (http_client->http_header.method == HTTP_CONNECT) {
                http_client->post_end = INT64_MAX;
            }
            if (http_client->http_header.http_major >= 1 && http_client->http_header.http_minor >= 1) {
                http_client->flags.keepalive = 1;
            }
            value = http_header_find(&http_client->http_header, "Proxy-Connection");
            if (!value) {
                value = http_header_find(&http_client->http_header, "Connection");
            }
            if (value) {
                if (strcasecmp(value, "Keep-Alive") == 0) {
                    http_client->flags.keepalive = 1;
                } else {
                    http_client->flags.keepalive = 0;
                }
            }
            LOG(LOG_DEBUG, "url=%s sock=%d keepalive=%d\n", http_client->http_header.url, conn->sock, http_client->flags.keepalive ? 1 : 0);
        }
    } else {
    }
    return 0;
}

static int http_client_timeout(struct conn_t *conn)
{
    return 0;
}

static int http_client_close(struct conn_t *conn, int err)
{
    return 0;
}

