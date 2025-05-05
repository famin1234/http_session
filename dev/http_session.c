#include <stdlib.h>
#include "mem.h"
#include "task_thread.h"
#include "net_thread.h"
#include "log.h"
#include "http_parser.h"
#include "http_session.h"

#define PAGE_SIZE 4096
#define URL_SIZE 256
#define HOST_SIZE 256

#define HTTP_CLIENT_TIMEOUT    (1000 * 5)
#define HTTP_SERVER_TIMEOUT    (1000 * 5)
#define HTTP_ACCEPT_TIMEOUT    (1000 * 5)

#define CR '\r'
#define LF '\n'

struct http_header_entry_t {
    char *field;
    char *value;
    struct list_head_t node;
};

struct http_header_t {
    char *url;
    union {
        unsigned short method;
        unsigned short status_code;
    };
    unsigned short http_major;
    unsigned short http_minor;
    struct list_head_t list;
};

struct http_content_range_t {
    int64_t start;
    int64_t end;
    int64_t content_length;
};

enum {
    CHUNKED_OK,
    CHUNKED_AGAIN,
    CHUNKED_DONE,
    CHUNKED_ERROR,
};

struct http_chunked_t {
    int      state;
    int64_t  size;
    int64_t  length;
};

enum {
    HTTP_ERROR_NONE,
    HTTP_ERROR_RECV,
    HTTP_ERROR_SEND,
    HTTP_ERROR_TIMEOUT,
};

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

static int on_message_begin(http_parser *http_parser);
static int on_url(http_parser *http_parser, const char *buf, size_t len);
static int on_header_field(http_parser *http_parser, const char *buf, size_t len);
static int on_header_value(http_parser *http_parser, const char *buf, size_t len);
static int on_headers_complete(http_parser *http_parser);
static int on_body(http_parser *http_parser, const char *buf, size_t len);
static int on_message_complete(http_parser *http_parser);
static void http_header_init(struct http_header_t *header);
static void http_header_add(struct http_header_t *header, const char *field, const char *value);
static void http_header_del(struct http_header_t *header, const char *field);
static const char* http_header_find(struct http_header_t *header, const char *field);
static void http_header_sprintf(struct http_header_t *header, enum http_parser_type type, struct string_t *string);
static void http_header_uninit(struct http_header_t *header);
static int http_content_range_parse(struct http_content_range_t *content_range, const char *value);
static int http_chunked_parse(struct http_chunked_t *chunked, const char *buf, size_t buf_len, size_t *buf_pos);
static void http_listen_task_run(struct task_t *task);
static void http_client_accept(struct conn_t *conn_listen, int events);
static void http_client_create(struct conn_t *conn);
static void http_client_events_handle(struct conn_t *conn, int events);
static int http_client_header_read(struct http_client_t *http_client);
static void http_client_close(struct http_client_t *http_client, int err);

static http_parser_settings http_header_parser_settings = {
    .on_message_begin = on_message_begin,
    .on_url = on_url,
    .on_status = NULL,
    .on_header_field = on_header_field,
    .on_header_value = on_header_value,
    .on_headers_complete = on_headers_complete,
    .on_body = on_body,
    .on_message_complete = on_message_complete
};

static int on_message_begin(http_parser *http_parser)
{
    return 0;
}

static int on_url(http_parser *http_parser, const char *buf, size_t len)
{
    struct http_header_t *header = http_parser->data;
    size_t old_len = 0;

    if (header->url) {
        old_len = strlen(header->url);
        header->url = mem_realloc(header->url, old_len + len + 1);
    } else {
        header->url = mem_malloc(len + 1);
    }
    memcpy(header->url + old_len, buf, len);
    header->url[old_len + len] = '\0';
    return 0;
}

static int on_header_field(http_parser *http_parser, const char *buf, size_t len)
{
    struct http_header_t *header = http_parser->data;
    struct http_header_entry_t *entry;
    size_t old_len = 0;

    if (list_empty(&header->list)) {
        entry = mem_malloc(sizeof(struct http_header_entry_t));
        entry->field = NULL;
        entry->value = NULL;
        list_add_tail(&entry->node, &header->list);
    } else {
        entry = d_list_tail(&header->list, struct http_header_entry_t, node);
        if (entry->value) {
            entry = mem_malloc(sizeof(struct http_header_entry_t));
            entry->field = NULL;
            entry->value = NULL;
            list_add_tail(&entry->node, &header->list);
        }
    }
    if (entry->field) {
        old_len = strlen(entry->field);
        entry->field = mem_realloc(entry->field, old_len + len + 1);
    } else {
        entry->field = mem_malloc(len + 1);
    }
    memcpy(entry->field + old_len, buf, len);
    entry->field[old_len + len] = '\0';
    return 0;
}

static int on_header_value(http_parser *http_parser, const char *buf, size_t len)
{
    struct http_header_t *header = http_parser->data;
    struct http_header_entry_t *entry;
    size_t old_len = 0;

    assert(!list_empty(&header->list));
    entry = d_list_tail(&header->list, struct http_header_entry_t, node);
    if (entry->value) {
        old_len = strlen(entry->value);
        entry->value = mem_realloc(entry->value, old_len + len + 1);
    } else {
        entry->value = mem_malloc(len + 1);
    }
    memcpy(entry->value + old_len, buf, len);
    entry->value[old_len + len] = '\0';
    return 0;
}

static int on_headers_complete(http_parser *http_parser)
{
    struct http_header_t *header = http_parser->data;

    if (http_parser->type == HTTP_REQUEST) {
        header->method = http_parser->method;
    } else if (http_parser->type == HTTP_RESPONSE) {
        header->status_code = http_parser->status_code;
    }
    header->http_major = http_parser->http_major;
    header->http_minor = http_parser->http_minor;
    return 1;
}

static int on_body(http_parser *http_parser, const char *buf, size_t len)
{
    return 0;
}

static int on_message_complete(http_parser *http_parser)
{
    return 1;
}


static void http_header_init(struct http_header_t *header)
{
    INIT_LIST_HEAD(&header->list);
}

static void http_header_add(struct http_header_t *header, const char *field, const char *value)
{
    //struct http_header_entry_t *entry;
}

static void http_header_del(struct http_header_t *header, const char *field)
{
    struct http_header_entry_t *entry;
    struct http_header_entry_t *entry_tmp;
    list_for_each_entry_safe(entry, entry_tmp, &header->list, node) {
        if (strcasecmp(entry->field, field) == 0) {
            list_del(&entry->node);
            mem_free(entry->field);
            mem_free(entry->value);
            mem_free(entry);
        }
    }
}

static const char* http_header_find(struct http_header_t *header, const char *field)
{
    struct http_header_entry_t *entry;
    list_for_each_entry(entry, &header->list, node) {
        if (strcasecmp(entry->field, field) == 0) {
            return entry->value;
        }
    }
    return NULL;
}

static void http_header_sprintf(struct http_header_t *header, enum http_parser_type type, struct string_t *string)
{
    struct http_header_entry_t *entry;

    if (type == HTTP_REQUEST) {
        string_sprintf(string, "%s %s HTTP/%d.%d\r\n", http_method_str(header->method), header->url, header->http_major, header->http_minor);
    } else if (type == HTTP_RESPONSE) {
        string_sprintf(string, "HTTP/%d.%d %d %s\r\n", header->http_major, header->http_minor, header->status_code, http_status_str(header->status_code));
    }
    list_for_each_entry(entry, &header->list, node) {
        string_sprintf(string, "%s: %s\r\n", entry->field, entry->value);
    }
    string_strcat(string, "\r\n");
}

static void http_header_uninit(struct http_header_t *header)
{
    struct http_header_entry_t *entry;
    while (!list_empty(&header->list)) {
        entry = d_list_head(&header->list, struct http_header_entry_t, node);
        list_del(&entry->node);
        mem_free(entry->field);
        mem_free(entry->value);
        mem_free(entry);
    }
    if (header->url) {
        mem_free(header->url);
    }
}

static int http_content_range_parse(struct http_content_range_t *content_range, const char *value)
{
    const char *p = value;
    int64_t start = 0;
    int64_t end = 0;
    int64_t content_length = 0;
    if (strncasecmp(p, "bytes ", 6)) {
        return -1;
    }
    p += 6;
    while (*p == ' ') p++;
    if (*p < '0' || *p > '9') {
        return -1;
    }
    while (*p >= '0' && *p <= '9') {
        start = start * 10 + (*p++ - '0');
    }
    while (*p == ' ') p++;
    if (*p++ != '-') {
        return -1;
    }
    while (*p == ' ') p++;
    while (*p >= '0' && *p <= '9') {
        end = end * 10 + (*p++ - '0');
    }
    end++;
    while (*p == ' ') p++;
    if (*p++ != '/') {
        return -1;
    }
    while (*p == ' ') p++;
    if (*p < '0' || *p > '9') {
        return -1;
    }
    while (*p >= '0' && *p <= '9') {
        content_length = content_length * 10 + (*p++ - '0');
    }
    content_range->start = start;
    content_range->end = end;
    content_range->content_length = content_length;
    return 0;
}

static int http_chunked_parse(struct http_chunked_t *chunked, const char *buf, size_t buf_len, size_t *buf_pos)
{
    const char *pos;
    char ch, c;
    int   rc;
    *buf_pos = 0;
    enum {
        sw_chunk_start = 0,
        sw_chunk_size,
        sw_chunk_extension,
        sw_chunk_extension_almost_done,
        sw_chunk_data,
        sw_after_data,
        sw_after_data_almost_done,
        sw_last_chunk_extension,
        sw_last_chunk_extension_almost_done,
        sw_trailer,
        sw_trailer_almost_done,
        sw_trailer_header,
        sw_trailer_header_almost_done
    } state;

    state = chunked->state;

    if (state == sw_chunk_data && chunked->size == 0) {
        state = sw_after_data;
    }

    rc = CHUNKED_AGAIN;

    for (pos = buf; pos < buf + buf_len; pos++) {

        ch = *pos;

        //LOG("http chunked byte: %02Xd s:%d\n", ch, state);

        switch (state) {

            case sw_chunk_start:
                if (ch >= '0' && ch <= '9') {
                    state = sw_chunk_size;
                    chunked->size = ch - '0';
                    break;
                }

                c = ch | 0x20;

                if (c >= 'a' && c <= 'f') {
                    state = sw_chunk_size;
                    chunked->size = c - 'a' + 10;
                    break;
                }

                goto invalid;

            case sw_chunk_size:
                if (chunked->size > INT64_MAX / 16) {
                    goto invalid;
                }

                if (ch >= '0' && ch <= '9') {
                    chunked->size = chunked->size * 16 + (ch - '0');
                    break;
                }

                c = ch | 0x20;

                if (c >= 'a' && c <= 'f') {
                    chunked->size = chunked->size * 16 + (c - 'a' + 10);
                    break;
                }

                if (chunked->size == 0) {

                    switch (ch) {
                        case CR:
                            state = sw_last_chunk_extension_almost_done;
                            break;
                        case LF:
                            state = sw_trailer;
                            break;
                        case ';':
                        case ' ':
                        case '\t':
                            state = sw_last_chunk_extension;
                            break;
                        default:
                            goto invalid;
                    }

                    break;
                }

                switch (ch) {
                    case CR:
                        state = sw_chunk_extension_almost_done;
                        break;
                    case LF:
                        state = sw_chunk_data;
                        break;
                    case ';':
                    case ' ':
                    case '\t':
                        state = sw_chunk_extension;
                        break;
                    default:
                        goto invalid;
                }

                break;

            case sw_chunk_extension:
                switch (ch) {
                    case CR:
                        state = sw_chunk_extension_almost_done;
                        break;
                    case LF:
                        state = sw_chunk_data;
                }
                break;

            case sw_chunk_extension_almost_done:
                if (ch == LF) {
                    state = sw_chunk_data;
                    break;
                }
                goto invalid;

            case sw_chunk_data:
                rc = CHUNKED_OK;
                goto data;

            case sw_after_data:
                switch (ch) {
                    case CR:
                        state = sw_after_data_almost_done;
                        break;
                    case LF:
                        state = sw_chunk_start;
                }
                break;

            case sw_after_data_almost_done:
                if (ch == LF) {
                    state = sw_chunk_start;
                    break;
                }
                goto invalid;

            case sw_last_chunk_extension:
                switch (ch) {
                    case CR:
                        state = sw_last_chunk_extension_almost_done;
                        break;
                    case LF:
                        state = sw_trailer;
                }
                break;

            case sw_last_chunk_extension_almost_done:
                if (ch == LF) {
                    state = sw_trailer;
                    break;
                }
                goto invalid;

            case sw_trailer:
                switch (ch) {
                    case CR:
                        state = sw_trailer_almost_done;
                        break;
                    case LF:
                        goto done;
                    default:
                        state = sw_trailer_header;
                }
                break;

            case sw_trailer_almost_done:
                if (ch == LF) {
                    goto done;
                }
                goto invalid;

            case sw_trailer_header:
                switch (ch) {
                    case CR:
                        state = sw_trailer_header_almost_done;
                        break;
                    case LF:
                        state = sw_trailer;
                }
                break;

            case sw_trailer_header_almost_done:
                if (ch == LF) {
                    state = sw_trailer;
                    break;
                }
                goto invalid;

        }
    }

data:

    chunked->state = state;
    *buf_pos = pos - buf;

    if (chunked->size > INT64_MAX - 5) {
        goto invalid;
    }

    switch (state) {

        case sw_chunk_start:
            chunked->length = 3 /* "0" LF LF */;
            break;
        case sw_chunk_size:
            chunked->length = 1 /* LF */
                + (chunked->size ? chunked->size + 4 /* LF "0" LF LF */
                        : 1 /* LF */);
            break;
        case sw_chunk_extension:
        case sw_chunk_extension_almost_done:
            chunked->length = 1 /* LF */ + chunked->size + 4 /* LF "0" LF LF */;
            break;
        case sw_chunk_data:
            chunked->length = chunked->size + 4 /* LF "0" LF LF */;
            break;
        case sw_after_data:
        case sw_after_data_almost_done:
            chunked->length = 4 /* LF "0" LF LF */;
            break;
        case sw_last_chunk_extension:
        case sw_last_chunk_extension_almost_done:
            chunked->length = 2 /* LF LF */;
            break;
        case sw_trailer:
        case sw_trailer_almost_done:
            chunked->length = 1 /* LF */;
            break;
        case sw_trailer_header:
        case sw_trailer_header_almost_done:
            chunked->length = 2 /* LF LF */;
            break;

    }

    return rc;

done:

    chunked->state = 0;
    *buf_pos = pos - buf + 1;

    return CHUNKED_DONE;

invalid:

    return CHUNKED_ERROR;
}

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
        conn->handle = http_client_accept;
        conn_nonblock(conn);
        conn_events_add(conn, CONN_EVENT_READ);
        conn_timer_add(conn, HTTP_ACCEPT_TIMEOUT);
    };
    mem_free(http_listen_task);
}

static void http_client_accept(struct conn_t *conn_listen, int events)
{
    int sock;
    struct conn_t *conn;
    struct conn_addr_t peer_addr;
    socklen_t addrlen;
    char str[64];

    if (events & CONN_EVENT_READ) {
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
    } else if (events & CONN_EVENT_TIMEOUT) {
        LOG(LOG_ERROR, "sock=%d timeout\n", conn_listen->sock);
        conn_timer_add(conn_listen, HTTP_ACCEPT_TIMEOUT);
    }
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
    conn->handle = http_client_events_handle;
    conn_events_add(conn, CONN_EVENT_READ);
    conn_timer_add(conn, HTTP_CLIENT_TIMEOUT);
}

static void http_client_events_handle(struct conn_t *conn, int events)
{
    struct http_client_t *http_client = (struct http_client_t *)conn->arg;

    if (events & CONN_EVENT_READ) {
        switch (http_client->state) {
            case HTTP_CLIENT_HEADER_READ:
                if (http_client_header_read(http_client)) {
                    return;
                }
                break;
            default:
                break;
        }

    }
    if (events & CONN_EVENT_WRITE) {
    }
    if (events & CONN_EVENT_TIMEOUT) {
    }
}

static int http_client_header_read(struct http_client_t *http_client)
{
    struct conn_t *conn = http_client->conn;
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
        http_client_close(http_client, -1);
        return -1;
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

static void http_client_close(struct http_client_t *http_client, int err)
{
    http_header_uninit(&http_client->http_header);
}
