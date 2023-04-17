#include "mem.h"
#include "net.h"
#include "aio.h"
#include "dns.h"
#include "log.h"
#include "http_header.h"
#include "http_session.h"

#define URL_LEN 256

#define FIFO_SIZE        16
#define PAGE_SHIFT       12
#define PAGE_SIZE        (1 << (PAGE_SHIFT))
#define PAGE_SIZE_N(n)   ((n) << (PAGE_SHIFT))
#define PAGE_INDEX(off)  ((off) >> (PAGE_SHIFT))
#define PAGE_OFFSET(off) ((off) & (PAGE_SIZE - 1))

#define HOST_MAX 256
#define RETRY_MAX 3

#define HTTP_CLIENT_TIMEOUT    (1000 * 5)
#define HTTP_SERVER_TIMEOUT    (1000 * 5)

enum {
    ERR_OK,
    ERR_CONN_ABORT,
    ERR_CONN_INIT,
    ERR_CONN_READ,
    ERR_CONN_CONNECT,
    ERR_CONN_WRITE,
    ERR_CONN_TIMEOUT,
    ERR_HTTP_URL,
    ERR_HTTP_RANGE,
    ERR_HTTP_BODY,
    ERR_HTTP_DNS,
    ERR_HTTP_HEADER,
};

enum http_type_t {
    HTTP_CLIENT_ACCEPT,
    HTTP_CLIENT_KEEPALIVE,
    HTTP_CLIENT_PIPELINE,
    HTTP_SERVER_ORIGIN,
    HTTP_SERVER_IMS,
    HTTP_SERVER_RANGE,
};

enum cache_status_t {
    CACHE_STATUS_NONE,
    CACHE_STATUS_MISS,
    CACHE_STATUS_HIT,
    CACHE_STATUS_EXPIRE,
    CACHE_STATUS_REFRESH_MISS,
    CACHE_STATUS_REFRESH_HIT,
};

struct page_t {
    char buf[PAGE_SIZE];
};

struct http_server_t {
    int type;
    struct conn_t *conn;
    struct {
        int proxy:1;
        int chunked:1;
        int keepalive:1;
    } flags;
    struct http_parser_url url_parser;
    struct http_header_t header;
    size_t header_recv;
    struct http_chunked_t chunked;
    int64_t body_start;
    int64_t body_end;
    int64_t post_send;
    struct string_t request;
    size_t request_send;
};

struct http_session_t {
    int64_t content_length;
    struct conn_t *conn;
    struct string_t url;
    struct {
        int transparent:1;
        int keepalive:1;
    } flags;
    struct http_header_t header;
    struct http_header_parser_t header_parser;
    size_t header_recv;
    struct fifo_t post;
    int64_t post_low;
    int64_t post_high;
    int64_t post_end;
    struct fifo_t body;
    int64_t body_high;
    int64_t body_low;
    int64_t body_start;
    int64_t body_send;
    int64_t body_end;
    struct string_t response;
    size_t response_send;
    struct aio_t aio;
    struct http_server_t *http_server;
};

static void http_session_accept(struct conn_t *conn_listen);
static void http_session_create(struct conn_t *conn, int type);

static void http_client_header_read(struct conn_t *conn);
static void http_client_header_process(struct http_session_t *http_session, const char *buf, size_t len);
static void http_client_post_read(struct conn_t *conn);
static void http_client_build_response(struct http_session_t *http_session, int http_code, int cache_status);
static void http_client_header_write(struct conn_t *conn);
static void http_client_body_write(struct conn_t *conn);
static void http_client_timeout(struct conn_t *conn);
static void http_client_keepalive_read(struct conn_t *conn);
static void http_client_keepalive_timeout(struct conn_t *conn);
static void http_client_keepalive(struct http_session_t *http_session);
static void http_client_close(struct http_session_t *http_session, int err);

static void http_server_create(struct http_session_t *http_session, int type);
static void http_server_dns_callback(struct aio_t *aio);
static void http_server_connect(struct http_session_t *http_session, union conn_addr_t *conn_addr);
static void http_server_connect_check(struct conn_t *conn);
static void http_server_connect_done(struct http_session_t *http_session, int err);
static void http_server_build_request(struct http_session_t *http_session);
static void http_server_header_write(struct conn_t *conn);
static void http_server_post_write(struct conn_t *conn);
static void http_server_header_read(struct conn_t *conn);
static void http_server_header_process(struct http_session_t *http_session, const char *buf, size_t len);
static void http_server_body_read(struct conn_t *conn);
static void http_server_body_process(struct http_session_t *http_session, const char *buf, size_t len);
static void http_server_timeout(struct conn_t *conn);
static void http_server_keepalive_timeout(struct conn_t *conn);
static void http_server_keepalive_read(struct conn_t *conn);
static void http_server_keepalive(struct http_session_t *http_session);
static void http_server_close(struct http_session_t *http_session, int err);

static void http_session_close(struct http_session_t *http_session);

int http_session_init()
{
    net_listen_list_add("0.0.0.0", 8080, http_session_accept);
    net_listen_list_add("::", 8080, http_session_accept);
    return 0;
}

void http_session_clean()
{
}

static void http_session_accept(struct conn_t *conn_listen)
{
    net_socket_t sock;
    struct conn_t *conn;
    union conn_addr_t conn_addr;
    socklen_t addrlen;
    char str[64];

    addrlen = sizeof(union conn_addr_t);
    sock = accept(conn_listen->sock, &conn_addr.addr, &addrlen);
    if (sock > 0) {
        conn_enable(conn_listen, CONN_READ);
        LOG(LOG_INFO, "sock=%d accept=%d %s\n", conn_listen->sock, sock, conn_addr_ntop(&conn_addr, str, sizeof(str)));
        conn = conn_alloc();
        conn->sock = sock;
        conn->peer_addr = conn_addr;
        conn->net_loop = conn_listen->net_loop;
        conn_nonblock(conn);
        http_session_create(conn, HTTP_CLIENT_ACCEPT);
    } else if(sock == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        LOG(LOG_DEBUG, "sock=%d accept=%d EAGAIN\n", conn_listen->sock, sock);
        conn_ready_unset(conn_listen, CONN_READ);
        conn_enable(conn_listen, CONN_READ);
    } else {
        conn_enable(conn_listen, CONN_READ);
        LOG(LOG_ERROR, "sock=%d accept=%d error:%s\n", conn_listen->sock, sock, strerror(errno));
    }
}

static void http_session_create(struct conn_t *conn, int type)
{
    struct http_session_t *http_session;

    http_session = mem_malloc(sizeof(struct http_session_t));
    memset(http_session, 0, sizeof(struct http_session_t));
    http_session->aio.net_loop = conn->net_loop;
    http_session->aio.data = http_session;
    http_session->conn = conn;
    string_init(&http_session->url, URL_LEN);
    http_header_init(&http_session->header);
    http_session->header.request.url = &http_session->url;
    http_header_parser_init(&http_session->header_parser, HTTP_REQUEST);
    http_session->header_parser.http_parser.data = &http_session->header;
    fifo_init(&http_session->post, FIFO_SIZE);
    fifo_init(&http_session->body, FIFO_SIZE);
    conn->handle_read = http_client_header_read;
    conn->handle_write = http_client_header_write;
    conn->handle_timeout = http_client_timeout;
    conn->data = http_session;
    conn_timer_set(conn, HTTP_CLIENT_TIMEOUT);
    conn_ready_set(conn, CONN_WRITE);
    if (type == HTTP_CLIENT_ACCEPT) {
        conn_enable(conn, CONN_READ);
    }
}

static void http_client_header_read(struct conn_t *conn)
{
    struct http_session_t *http_session = conn->data;
    char buf[PAGE_SIZE];
    ssize_t n;

    n = recv(conn->sock, buf, sizeof(buf), 0);
    if (n > 0) {
        LOG(LOG_DEBUG, "url=%s sock=%d recv=%zd\n", string_buf(&http_session->url), conn->sock, n);
        conn_timer_set(conn, HTTP_CLIENT_TIMEOUT);
        http_client_header_process(http_session, buf, n);
    } else if(n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        conn_ready_unset(conn, CONN_READ);
        conn_enable(conn, CONN_READ);
    } else {
        LOG(LOG_ERROR, "url=%s sock=%d recv=%zd error:%s\n", string_buf(&http_session->url), conn->sock, n, strerror(errno));
        http_client_close(http_session, ERR_CONN_READ);
    }
}

static void http_client_header_process(struct http_session_t *http_session, const char *buf, size_t len)
{
    struct conn_t *conn = http_session->conn;
    struct string_t request;
    struct string_t url;
    const char *value;
    size_t nparse;
    struct page_t *page;
    size_t post_len;
    size_t copy_len;
    size_t n;

    if (http_session->header_parser.http_parser.http_errno == HPE_CB_message_complete) {
        LOG(LOG_DEBUG, "url=%s sock=%d drop len=%zu\n", string_buf(&http_session->url), conn->sock, len);
        conn_enable(conn, CONN_READ);
        return;
    }
    nparse = http_header_parser_execute(&http_session->header_parser, buf, len);
    http_session->header_recv += nparse;
    if (http_session->header_parser.http_parser.http_errno == HPE_CB_message_complete) {
        string_init(&request, PAGE_SIZE);
        http_header_print(&http_session->header, HTTP_REQUEST, &request);
        if (string_buf(&http_session->url)[0] == '/') {
            http_session->flags.transparent = 1;
            value = http_header_find(&http_session->header, "Host");
            if (value) {
                string_init(&url, URL_LEN);
                string_strcat(&url, "http://");
                string_strcat(&url, value);
                string_strncat(&url, string_buf(&http_session->url), string_len(&http_session->url));
                string_clean(&http_session->url);
                http_session->url = url;
            }
        }
        LOG(LOG_INFO, "url=%s sock=%d len=%zu nparse=%zu header_recv=%zu\n%s\n",
                string_buf(&http_session->url), conn->sock, len, nparse, http_session->header_recv, string_buf(&request));
        string_clean(&request);
        if (http_session->header.request.method == HTTP_POST || http_session->header.request.method == HTTP_PUT) {
            value = http_header_find(&http_session->header, "Content-Length");
            if (value) {
                http_session->post_end = atoll(value);
                if (http_session->post_end < 0) {
                    http_session->post_end = 0;
                }
            }
        } else if (http_session->header.request.method == HTTP_CONNECT) {
            http_session->post_end = INT64_MAX;
        }
        if (http_session->header.http_major >= 1 && http_session->header.http_minor >= 1) {
            http_session->flags.keepalive = 1;
        }
        value = http_header_find(&http_session->header, "Proxy-Connection");
        if (!value) {
            value = http_header_find(&http_session->header, "Connection");
        }
        if (value) {
            if (strcasecmp(value, "Keep-Alive") == 0) {
                http_session->flags.keepalive = 1;
            } else {
                http_session->flags.keepalive = 0;
            }
        }
        LOG(LOG_DEBUG, "url=%s sock=%d keepalive=%d\n", string_buf(&http_session->url), conn->sock, http_session->flags.keepalive ? 1 : 0);
    } else if (http_session->header_parser.http_parser.http_errno == HPE_OK) {
        LOG(LOG_DEBUG, "url=%s sock=%d len=%zu nparse=%zu header_recv=%zu continue\n", string_buf(&http_session->url), conn->sock, len, nparse, http_session->header_recv);
        assert(nparse == len);
        conn_enable(conn, CONN_READ);
        return;
    } else {
        LOG(LOG_ERROR, "url=%s sock=%d len=%zu nparse=%zu header_recv=%zu error\n", string_buf(&http_session->url), conn->sock, len, nparse, http_session->header_recv);
        http_client_build_response(http_session, HTTP_STATUS_BAD_REQUEST, CACHE_STATUS_NONE);
        conn_enable(conn, CONN_READ | CONN_WRITE);
        return;
    }
    if (nparse < len ) {
        if (http_session->post_end > 0) {
            post_len = len - nparse;
            if (http_session->post_end - http_session->post_high < post_len) {
                post_len = http_session->post_end - http_session->post_low;
            }
            copy_len = 0;
            while (copy_len < post_len) {
                page = fifo_get(&http_session->post, PAGE_INDEX(http_session->post_high - http_session->post_low));
                if (!page) {
                    page = mem_malloc(sizeof(struct page_t));
                    fifo_push_tail(&http_session->post, page);
                }
                n = PAGE_SIZE - PAGE_OFFSET(http_session->post_high);
                if (post_len - copy_len < n) {
                    n = post_len - copy_len;
                }
                LOG(LOG_DEBUG, "url=%s sock=%d copy=%zu\n", string_buf(&http_session->url), conn->sock, n);
                memcpy(page->buf + PAGE_OFFSET(http_session->post_high), buf + nparse + copy_len, n);
                http_session->post_high += n;
                copy_len += n;
            }
        }
    }
    if (http_session->post_high < http_session->post_end) {
        conn->handle_read = http_client_post_read;
    }
    conn_enable(conn, CONN_READ);
    http_server_create(http_session, HTTP_SERVER_ORIGIN);
}

static void http_client_post_read(struct conn_t *conn)
{
    struct http_session_t *http_session = conn->data;
    struct http_server_t *http_server = http_session->http_server;
    struct page_t *page;
    char *buf;
    size_t len;
    ssize_t n;

    page = fifo_get(&http_session->post, PAGE_INDEX(http_session->post_high - http_session->post_low));
    if (!page) {
        page = mem_malloc(PAGE_SIZE);
        fifo_push_tail(&http_session->post, page);
    }
    buf = page->buf + PAGE_OFFSET(http_session->post_high);
    len = PAGE_SIZE - PAGE_OFFSET(http_session->post_high);
    if (http_session->post_end - http_session->post_high < len) {
        len = http_session->post_end - http_session->post_high;
    }
    assert(len > 0);
    n = recv(conn->sock, buf, len, 0);
    if (n > 0) {
        LOG(LOG_DEBUG, "url=%s sock=%d recv=%zd\n", string_buf(&http_session->url), conn->sock, n);
        conn_timer_set(conn, HTTP_CLIENT_TIMEOUT);
        http_session->post_high += n;
        if (http_server && http_server->post_send < http_session->post_high) {
            if (http_server->conn) {
                conn_enable(http_server->conn, CONN_WRITE);
            }
        }
        if (http_session->post_high < http_session->post_end) {
            if (http_session->post_high - http_session->post_low < PAGE_SIZE_N(fifo_size(&http_session->post))) {
                conn_enable(conn, CONN_READ);
            } else {
                conn_disable(conn, CONN_READ);
            }
        } else {
            LOG(LOG_DEBUG, "url=%s sock=%d recv done\n", string_buf(&http_session->url), conn->sock);
            conn->handle_read = http_client_header_read;
            conn_enable(conn, CONN_READ);
        }
    } else if(n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        conn_ready_unset(conn, CONN_READ);
        conn_enable(conn, CONN_READ);
    } else {
        LOG(LOG_ERROR, "url=%s sock=%d recv=%zd error:%s\n", string_buf(&http_session->url), conn->sock, n, strerror(errno));
        http_client_close(http_session, ERR_CONN_READ);
    }
}

static void http_client_build_response(struct http_session_t *http_session, int http_code, int cache_status)
{
    struct conn_t *conn = http_session->conn;
    struct http_server_t *http_server = http_session->http_server;
    struct http_header_t *header;
    struct http_header_entry_t *entry;

    assert(string_size(&http_session->response) == 0);
    string_init(&http_session->response, PAGE_SIZE);
    switch (cache_status) {
        case CACHE_STATUS_NONE:
            string_sprint(&http_session->response, "HTTP/%d.%d %d %s\r\n", 1, 1, http_code, http_status_str(http_code));
            string_strcat(&http_session->response, "Content-Length: 0\r\n");
            break;
        case CACHE_STATUS_MISS:
        case CACHE_STATUS_REFRESH_MISS:
            if (http_session->header.request.method == HTTP_CONNECT) {
                string_sprint(&http_session->response, "HTTP/%d.%d %d Connection established\r\n", 1, 1, http_code);
            } else {
                header = &http_server->header;
                string_sprint(&http_session->response, "HTTP/%d.%d %d %s\r\n", header->http_major, header->http_minor,
                        header->response.status_code, http_status_str(header->response.status_code));
                list_for_each_entry(entry, &header->list, node) {
                    if (!strcasecmp(entry->field, "Proxy-Connection") ||
                            !strcasecmp(entry->field, "Connection")) {
                        continue;
                    }
                    string_strcat(&http_session->response, entry->field);
                    string_strcat(&http_session->response, ": ");
                    string_strcat(&http_session->response, entry->value);
                    string_strcat(&http_session->response, "\r\n");
                }
            }
            http_session->body_start = http_server->body_start;
            http_session->body_end = http_server->body_end;
            http_session->body_send = http_server->body_start;
            break;
        case CACHE_STATUS_HIT:
        case CACHE_STATUS_REFRESH_HIT:
            break;
        default:
            LOG(LOG_ERROR, "url=%s http_code=%d cache_status=%d\n", string_buf(&http_session->url), http_code, cache_status);
            string_sprint(&http_session->response, "HTTP/%d.%d %d %s\r\n", 1, 1, http_code, http_status_str(http_code));
            assert(0);
            break;
    }
    if (http_session->flags.keepalive) {
        if (http_session->flags.transparent) {
            string_strcat(&http_session->response, "Connection: keep-alive\r\n");
        } else {
            string_strcat(&http_session->response, "Proxy-Connection: keep-alive\r\n");
        }
    } else {
        if (http_session->flags.transparent) {
            string_strcat(&http_session->response, "Connection: close\r\n");
        } else {
            string_strcat(&http_session->response, "Proxy-Connection: close\r\n");
        }
    }
    string_strcat(&http_session->response, "Via: http_cache\r\n");
    string_strcat(&http_session->response, "\r\n");
    LOG(LOG_INFO, "url=%s sock=%d response=\n%s\n", string_buf(&http_session->url), conn?conn->sock:-1, string_buf(&http_session->response));
}

static void http_client_header_write(struct conn_t *conn)
{
    struct http_session_t *http_session = conn->data;
    char *buf;
    size_t len;
    ssize_t n;

    buf = string_buf(&http_session->response) + http_session->response_send;
    len = string_len(&http_session->response) - http_session->response_send;
    n = send(conn->sock, buf, len, 0);
    if (n > 0) {
        LOG(LOG_DEBUG, "url=%s sock=%d send=%zd\n", string_buf(&http_session->url), conn->sock, n);
        conn_timer_set(conn, HTTP_CLIENT_TIMEOUT);
        http_session->response_send += n;
        if (http_session->response_send < string_len(&http_session->response)) {
            conn_enable(conn, CONN_WRITE);
        } else {
            if (http_session->body_send < http_session->body_end) {
                conn->handle_write = http_client_body_write;
                if (http_session->body_send < http_session->body_high && http_session->body_send >= http_session->body_low) {
                    conn_enable(conn, CONN_WRITE);
                } else {
                    conn_disable(conn, CONN_WRITE);
                }
            } else {
                LOG(LOG_DEBUG, "url=%s sock=%d send done\n", string_buf(&http_session->url), conn->sock);
                http_client_close(http_session, ERR_OK);
            }
        }
    } else if(n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        conn_ready_unset(conn, CONN_WRITE);
        conn_enable(conn, CONN_WRITE);
    } else {
        LOG(LOG_ERROR, "url=%s sock=%d send=%zd error:%s\n", string_buf(&http_session->url), conn->sock, n, strerror(errno));
        http_client_close(http_session, ERR_CONN_WRITE);
    }
}

static void http_client_body_write(struct conn_t *conn)
{
    struct http_session_t *http_session = conn->data;
    struct http_server_t *http_server = http_session->http_server;
    struct page_t *page;
    char *buf;
    size_t len;
    ssize_t n;

    page = fifo_get(&http_session->body, PAGE_INDEX(http_session->body_send - http_session->body_low));
    assert(page != NULL);
    buf = page->buf + PAGE_OFFSET(http_session->body_send);
    len = PAGE_SIZE - PAGE_OFFSET(http_session->body_send);
    if (http_session->body_high - http_session->body_send < len) {
        len = http_session->body_high - http_session->body_send;
    }
    if (http_session->body_end - http_session->body_send < len) {
        len = http_session->body_end - http_session->body_send;
    }
    assert(len > 0);
    n = send(conn->sock, buf, len, 0);
    if (n > 0) {
        LOG(LOG_DEBUG, "url=%s sock=%d send=%zd\n", string_buf(&http_session->url), conn->sock, n);
        conn_timer_set(conn, HTTP_CLIENT_TIMEOUT);
        http_session->body_send += n;
        while (http_session->body_send - http_session->body_low >= PAGE_SIZE) {
            page = fifo_head(&http_session->body);
            fifo_pop_head(&http_session->body);
            mem_free(page);
            http_session->body_low += PAGE_SIZE;
            if (http_server) {
                assert(http_server->conn != NULL);
                conn_enable(http_server->conn, CONN_READ);
            }
        }
        if (http_session->body_send < http_session->body_end) {
            conn->handle_write = http_client_body_write;
            if (http_session->body_send < http_session->body_high) {
                assert(http_session->body_send >= http_session->body_low);
                conn_enable(conn, CONN_WRITE);
            } else {
                conn_disable(conn, CONN_WRITE);
                if (http_server) {
                } else if (http_session->content_length > 0) {
                    http_server_create(http_session, HTTP_SERVER_RANGE);
                } else {
                    http_client_close(http_session, ERR_CONN_ABORT);
                }
            }
        } else {
            LOG(LOG_DEBUG, "url=%s sock=%d send done\n", string_buf(&http_session->url), conn->sock);
            http_client_close(http_session, ERR_OK);
        }
    } else if(n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        conn_ready_unset(conn, CONN_WRITE);
        conn_enable(conn, CONN_WRITE);
    } else {
        LOG(LOG_ERROR, "url=%s sock=%d send=%zd error:%s\n", string_buf(&http_session->url), conn->sock, n, strerror(errno));
        http_client_close(http_session, ERR_CONN_WRITE);
    }
}

static void http_client_timeout(struct conn_t *conn)
{
    struct http_session_t *http_session = conn->data;
    LOG(LOG_ERROR, "url=%s sock=%d timeout\n", string_buf(&http_session->url), conn->sock);
    http_client_close(http_session, ERR_CONN_TIMEOUT);
}

static void http_client_keepalive_read(struct conn_t *conn)
{
    char buf[PAGE_SIZE];
    ssize_t n;

    n = recv(conn->sock, buf, sizeof(buf), 0);
    if (n > 0) {
        LOG(LOG_DEBUG, "sock=%d recv=%zd\n", conn->sock, n);
        http_session_create(conn, HTTP_CLIENT_KEEPALIVE);
        http_client_header_process(conn->data, buf, n);
    } else if(n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        conn_ready_unset(conn, CONN_READ);
        conn_enable(conn, CONN_READ);
    } else {
        LOG(LOG_ERROR, "sock=%d recv=%zd error:%s\n", conn->sock, n, strerror(errno));
        conn_close(conn);
    }
}

static void http_client_keepalive_timeout(struct conn_t *conn)
{
    LOG(LOG_ERROR, "sock=%d timeout\n", conn->sock);
    conn_close(conn);
}

static void http_client_keepalive(struct http_session_t *http_session)
{
    struct conn_t *conn = http_session->conn;

    LOG(LOG_DEBUG, "url=%s sock=%d keepalive set\n", string_buf(&http_session->url), conn->sock);
    conn->data = NULL;
    conn->handle_read = http_client_keepalive_read;
    conn->handle_write = NULL;
    conn->handle_timeout = http_client_keepalive_timeout;
    conn_timer_set(conn, HTTP_CLIENT_TIMEOUT);
    conn_enable(conn, CONN_READ);
    conn_disable(conn, CONN_WRITE);
}

static void http_client_close(struct http_session_t *http_session, int err)
{
    struct conn_t *conn = http_session->conn;
    LOG(LOG_INFO, "url=%s sock=%d body_size=%"PRId64" err=%d\n",
            string_buf(&http_session->url), conn->sock, http_session->body_send - http_session->body_start, err);
    if (!err && http_session->flags.keepalive) {
        http_client_keepalive(http_session);
    } else {
        conn_close(conn);
    }
    http_session->conn = NULL;
    if (http_session->http_server) {
        http_server_close(http_session, ERR_CONN_ABORT);
    } else {
        http_session_close(http_session);
    }
}

static void http_server_create(struct http_session_t *http_session, int type)
{
    struct http_server_t *http_server;
    union conn_addr_t peer_addr;
    char host[HOST_MAX];

    http_session->http_server = http_server = mem_malloc(sizeof(struct http_server_t));
    memset(http_server, 0, sizeof(struct http_server_t));
    http_server->type = type;
    http_header_init(&http_server->header);
    http_header_parser_init(&http_session->header_parser, HTTP_RESPONSE);
    http_session->header_parser.http_parser.data = &http_server->header;
    http_parser_url_init(&http_server->url_parser);
    if (http_parser_parse_url(string_buf(&http_session->url), string_len(&http_session->url),
                http_session->header.request.method == HTTP_CONNECT, &http_server->url_parser)) {
        LOG(LOG_ERROR, "url=%s parse error\n", string_buf(&http_session->url));
        http_server_close(http_session, ERR_HTTP_URL);
        return;
    }
    if (http_server->url_parser.field_set & (1 << UF_HOST)) {
        if (http_server->url_parser.field_data[UF_HOST].len < sizeof(host)) {
            memcpy(host, string_buf(&http_session->url) + http_server->url_parser.field_data[UF_HOST].off, http_server->url_parser.field_data[UF_HOST].len);
            host[http_server->url_parser.field_data[UF_HOST].len] = '\0';
        } else {
            LOG(LOG_ERROR, "url=%s host too long\n", string_buf(&http_session->url));
            http_server_close(http_session, ERR_HTTP_URL);
            return;
        }
    } else {
        LOG(LOG_ERROR, "url=%s without host\n", string_buf(&http_session->url));
        http_server_close(http_session, ERR_HTTP_URL);
        return;
    }
    if (http_server->url_parser.field_set & (1 << UF_PORT)) {
    } else {
        http_server->url_parser.port = 80;
    }
    if (conn_addr_pton(&peer_addr, host, http_server->url_parser.port) > 0) {
        http_server_connect(http_session, &peer_addr);
    } else {
        assert(!aio_busy(&http_session->aio));
        http_session->aio.exec = http_server_dns_callback;
        dns_cache_table_query(&http_session->aio, host);
    }
}

static void http_server_dns_callback(struct aio_t *aio)
{
    struct http_session_t *http_session = aio->data;
    struct http_server_t *http_server = http_session->http_server;
    union conn_addr_t peer_addr;
    struct dns_cache_t *dns_cache = aio->extra;
    struct dns_addr_t *dns_addr;

    LOG(LOG_DEBUG, "url=%s query done\n", string_buf(&http_session->url));
    peer_addr.addr.sa_family = AF_UNSPEC;
    if (dns_cache) {
        if (!list_empty(&dns_cache->addr_list)) {
            dns_addr = d_list_head(&dns_cache->addr_list, struct dns_addr_t, node);
            if (dns_addr->af == AF_INET) {
                peer_addr.in.sin_family = AF_INET;
                peer_addr.in.sin_port = htons(http_server->url_parser.port);
                peer_addr.in.sin_addr = dns_addr->in_addr;
            } else if (dns_addr->af == AF_INET6) {
                peer_addr.in6.sin6_family = AF_INET6;
                peer_addr.in6.sin6_port = htons(http_server->url_parser.port);
                peer_addr.in6.sin6_flowinfo = 0;
                peer_addr.in6.sin6_addr = dns_addr->in6_addr;
                peer_addr.in6.sin6_scope_id = 0;
            }
            dns_cache_table_unquery(&http_session->aio);
        }
    }
    if (!http_server) {
        assert(http_session->conn == NULL);
        http_session_close(http_session);
    } else {
        if (peer_addr.addr.sa_family != AF_UNSPEC) {
            http_server_connect(http_session, &peer_addr);
        } else {
            LOG(LOG_ERROR, "url=%s conn_addr is empty\n", string_buf(&http_session->url));
            http_server_close(http_session, ERR_HTTP_DNS);
        }
    }
}

static void http_server_connect(struct http_session_t *http_session, union conn_addr_t *conn_addr)
{
    struct http_server_t *http_server = http_session->http_server;
    struct conn_t *conn;
    int sock;
    char str[64];

    http_server->conn = conn = conn_keepalive_get(http_session->aio.net_loop, conn_addr);
    if (conn) {
        LOG(LOG_INFO, "url=%s sock=%d %s reuse\n", string_buf(&http_session->url), conn->sock, conn_addr_ntop(&conn->peer_addr, str, sizeof(str)));
        http_server_connect_done(http_session, ERR_OK);
        return;
    }
    sock = socket(conn_addr->addr.sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        LOG(LOG_ERROR, "url=%s socket error: %s\n", string_buf(&http_session->url), strerror(errno));
        http_server_close(http_session, ERR_CONN_INIT);
        return;
    }
    http_server->conn = conn = conn_alloc();
    conn->sock = sock;
    conn->peer_addr = *conn_addr;
    conn->net_loop = http_session->aio.net_loop;
    conn_nonblock(conn);
    conn->handle_read = http_server_header_read;
    conn->handle_write = http_server_connect_check;
    conn->handle_timeout = http_server_timeout;
    conn->data = http_session;
    LOG(LOG_DEBUG, "url=%s sock=%d connect %s\n", string_buf(&http_session->url), conn->sock, conn_addr_ntop(&conn->peer_addr, str, sizeof(str)));
    conn_timer_set(conn, HTTP_SERVER_TIMEOUT);
    if (connect(conn->sock, &conn->peer_addr.addr, sizeof(union conn_addr_t)) == 0) {
        http_server_connect_done(http_session, ERR_OK);
    } else if (errno == EINPROGRESS) {
        conn_enable(conn, CONN_WRITE);
    } else {
        http_server_connect_done(http_session, ERR_CONN_CONNECT);
    }
}

static void http_server_connect_check(struct conn_t *conn)
{
    struct http_session_t *http_session = conn->data;
    int err;
    socklen_t len;

    len = sizeof(err);
    if (getsockopt(conn->sock, SOL_SOCKET, SO_ERROR, &err, &len) || err) {
        http_server_connect_done(http_session, ERR_CONN_CONNECT);
    } else {
        http_server_connect_done(http_session, ERR_OK);
    }
}

static void http_server_connect_done(struct http_session_t *http_session, int err)
{
    struct http_server_t *http_server = http_session->http_server;
    struct conn_t *conn = http_server->conn;
    char str[64];

    if (err) {
        LOG(LOG_ERROR, "url=%s sock=%d connect %s error\n", string_buf(&http_session->url), conn->sock, conn_addr_ntop(&conn->peer_addr, str, sizeof(str)));
        http_server_close(http_session, err);
    } else {
        LOG(LOG_DEBUG, "url=%s sock=%d connect %s ok\n", string_buf(&http_session->url), conn->sock, conn_addr_ntop(&conn->peer_addr, str, sizeof(str)));
        if (http_session->header.request.method == HTTP_CONNECT) {
            http_server->body_end = INT64_MAX;
            http_client_build_response(http_session, HTTP_STATUS_OK, CACHE_STATUS_MISS);
            if (http_session->conn) {
                conn_enable(http_session->conn, CONN_WRITE);
            }
            conn->handle_read = http_server_body_read;
            conn->handle_write = http_server_post_write;
            conn->handle_timeout = http_server_timeout;
            conn->data = http_session;
            conn_timer_set(conn, HTTP_SERVER_TIMEOUT);
            conn_ready_set(conn, CONN_WRITE);
            conn_enable(conn, CONN_READ);
            if (http_server->post_send < http_session->post_end) {
                if (http_server->post_send < http_session->post_high) {
                    assert(http_server->post_send >= http_session->post_low);
                    conn_enable(conn, CONN_WRITE);
                } else {
                    conn_disable(conn, CONN_WRITE);
                }
            } else {
                LOG(LOG_DEBUG, "url=%s sock=%d send done\n", string_buf(&http_session->url), conn->sock);
                conn_disable(conn, CONN_WRITE);
            }
        } else {
            http_server_build_request(http_session);
            conn->handle_read = http_server_header_read;
            conn->handle_write = http_server_header_write;
            conn->handle_timeout = http_server_timeout;
            conn->data = http_session;
            conn_timer_set(conn, HTTP_SERVER_TIMEOUT);
            conn_ready_set(conn, CONN_WRITE);
            conn_enable(conn, CONN_READ);
            conn_enable(conn, CONN_WRITE);
        }
    }
}

static void http_server_build_request(struct http_session_t *http_session)
{
    struct http_server_t *http_server = http_session->http_server;
    struct http_header_entry_t *entry;
    char *uri;

    assert(string_size(&http_server->request) == 0);
    string_init(&http_server->request, PAGE_SIZE);
    if (http_server->flags.proxy) {
        uri = string_buf(&http_session->url);
    } else {
        uri = string_buf(&http_session->url) + http_server->url_parser.field_data[UF_PATH].off;
    }
    string_sprint(&http_server->request, "%s %s HTTP/%d.%d\r\n",
            http_method_str(http_session->header.request.method), uri, http_session->header.http_major, http_session->header.http_minor);
    list_for_each_entry(entry, &http_session->header.list, node) {
        if (!strcasecmp(entry->field, "Proxy-Connection") || !strcasecmp(entry->field, "Connection")) {
            continue;
        }
        if (!strcasecmp(entry->field, "Range") && http_server->type == HTTP_SERVER_RANGE) {
            continue;
        }
        string_strcat(&http_server->request, entry->field);
        string_strcat(&http_server->request, ": ");
        string_strcat(&http_server->request, entry->value);
        string_strcat(&http_server->request, "\r\n");
    }
    if (http_server->type == HTTP_SERVER_RANGE) {
        string_sprint(&http_server->request, "Range: bytes=%"PRId64"-%"PRId64"\r\n", http_session->body_high, http_session->body_end - 1);
    }
    if (1) {
        if (http_server->flags.proxy) {
            string_strcat(&http_server->request, "Proxy-Connection: keep-alive\r\n");
        } else {
            string_strcat(&http_server->request, "Connection: keep-alive\r\n");
        }
    } else {
        if (http_server->flags.proxy) {
            string_strcat(&http_server->request, "Proxy-Connection: close\r\n");
        } else {
            string_strcat(&http_server->request, "Connection: close\r\n");
        }
    }
    string_strcat(&http_server->request, "\r\n");
    LOG(LOG_INFO, "url=%s sock=%d request=\n%s\n", string_buf(&http_session->url), http_server->conn->sock, string_buf(&http_server->request));
}

static void http_server_header_write(struct conn_t *conn)
{
    struct http_session_t *http_session = conn->data;
    struct http_server_t *http_server = http_session->http_server;
    char *buf;
    size_t len;
    ssize_t n;

    buf = string_buf(&http_server->request) + http_server->request_send;
    len = string_len(&http_server->request) - http_server->request_send;
    n = send(conn->sock, buf, len, 0);
    if (n > 0) {
        LOG(LOG_DEBUG, "url=%s sock=%d send=%zd\n", string_buf(&http_session->url), conn->sock, n);
        conn_timer_set(conn, HTTP_SERVER_TIMEOUT);
        http_server->request_send += n;
        if (http_server->request_send >= string_len(&http_server->request)) {
            if (http_server->post_send < http_session->post_end) {
                conn->handle_write = http_server_post_write;
                if (http_server->post_send < http_session->post_high) {
                    conn_enable(conn, CONN_WRITE);
                } else {
                    conn_disable(conn, CONN_WRITE);
                }
            } else {
                LOG(LOG_DEBUG, "url=%s sock=%d send done\n", string_buf(&http_session->url), conn->sock);
                conn_disable(conn, CONN_WRITE);
            }
        } else {
            conn_enable(conn, CONN_WRITE);
        }
    } else if(n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        conn_ready_unset(conn, CONN_WRITE);
        conn_enable(conn, CONN_WRITE);
    } else {
        LOG(LOG_ERROR, "url=%s sock=%d send=%zd error:%s\n", string_buf(&http_session->url), conn->sock, n, strerror(errno));
        http_server_close(http_session, ERR_CONN_WRITE);
    }
}

static void http_server_post_write(struct conn_t *conn)
{
    struct http_session_t *http_session = conn->data;
    struct http_server_t *http_server = http_session->http_server;
    struct page_t *page;
    char *buf;
    size_t len;
    ssize_t n;

    page = fifo_get(&http_session->post, PAGE_INDEX(http_server->post_send - http_session->post_low));
    assert(page != NULL);
    buf = page->buf + PAGE_OFFSET(http_server->post_send);
    len = PAGE_SIZE - PAGE_OFFSET(http_server->post_send);
    if (http_session->post_high - http_server->post_send < len) {
        len = http_session->post_high - http_server->post_send;
    }
    if (http_session->post_end - http_server->post_send < len) {
        len = http_session->post_end - http_server->post_send;
    }
    assert(len > 0);
    n = send(conn->sock, buf, len, 0);
    if (n > 0) {
        LOG(LOG_DEBUG, "url=%s sock=%d send=%zd\n", string_buf(&http_session->url), conn->sock, n);
        conn_timer_set(conn, HTTP_SERVER_TIMEOUT);
        http_server->post_send += n;
        while (http_server->post_send - http_session->post_low >= PAGE_SIZE) {
            page = fifo_head(&http_session->post);
            fifo_pop_head(&http_session->post);
            mem_free(page);
            http_session->post_low += PAGE_SIZE;
            if (http_session->conn && http_session->post_high < http_session->post_end) {
                conn_enable(http_session->conn, CONN_READ);
            }
        }
        if (http_server->post_send < http_session->post_end) {
            if (http_server->post_send < http_session->post_high) {
                assert(http_server->post_send >= http_session->post_low);
                conn_enable(conn, CONN_WRITE);
            } else {
                conn_disable(conn, CONN_WRITE);
            }
        } else {
            LOG(LOG_DEBUG, "url=%s sock=%d send done\n", string_buf(&http_session->url), conn->sock);
            conn_disable(conn, CONN_WRITE);
        }
    } else if(n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        conn_ready_unset(conn, CONN_WRITE);
        conn_enable(conn, CONN_WRITE);
    } else {
        LOG(LOG_ERROR, "url=%s sock=%d send=%zd error:%s\n", string_buf(&http_session->url), conn->sock, n, strerror(errno));
        http_server_close(http_session, ERR_CONN_WRITE);
    }
}

static void http_server_header_read(struct conn_t *conn)
{
    struct http_session_t *http_session = conn->data;
    char buf[PAGE_SIZE];
    ssize_t n;

    n = recv(conn->sock, buf, sizeof(buf), 0);
    if (n > 0) {
        LOG(LOG_DEBUG, "url=%s sock=%d recv=%zd\n", string_buf(&http_session->url), conn->sock, n);
        conn_timer_set(conn, HTTP_SERVER_TIMEOUT);
        http_server_header_process(http_session, buf, n);
    } else if(n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        conn_ready_unset(conn, CONN_READ);
        conn_enable(conn, CONN_READ);
    } else {
        LOG(LOG_ERROR, "url=%s sock=%d recv=%zd error:%s\n", string_buf(&http_session->url), conn->sock, n, strerror(errno));
        http_server_close(http_session, ERR_CONN_READ);
        return;
    }
}

static void http_server_header_process(struct http_session_t *http_session, const char *buf, size_t len)
{
    struct http_server_t *http_server = http_session->http_server;
    struct conn_t *conn = http_server->conn;
    struct http_content_range_t content_range;
    int64_t content_length = -1;
    struct string_t response;
    struct page_t *page;
    const char *value;
    size_t nparse;
    size_t body_len;
    size_t copy_len;
    size_t n;

    nparse = http_header_parser_execute(&http_session->header_parser, buf, len);
    http_server->header_recv += nparse;
    if (http_session->header_parser.http_parser.http_errno == HPE_CB_message_complete) {
        string_init(&response, PAGE_SIZE);
        http_header_print(&http_server->header, HTTP_RESPONSE, &response);
        LOG(LOG_INFO, "url=%s sock=%d len=%zu nparse=%zu header_recv=%zu\n%s\n",
                string_buf(&http_session->url), conn->sock, len, nparse, http_server->header_recv, string_buf(&response));
        string_clean(&response);
        value = http_header_find(&http_server->header, "Content-Length");
        if (value) {
            http_server->body_end = atoll(value);
            if (http_server->body_end < 0) {
                LOG(LOG_ERROR, "url=%s sock=%d body_end=%"PRId64" error\n", string_buf(&http_session->url), conn->sock, http_server->body_end);
                http_server->body_end = 0;
                http_server_close(http_session, ERR_HTTP_HEADER);
            }
        } else {
            http_server->body_end = INT64_MAX;
        }
        if (http_server->header.http_major >= 1 && http_server->header.http_minor >= 1) {
            http_server->flags.keepalive = 1;
        }
        value = http_header_find(&http_server->header, "Proxy-Connection");
        if (!value) {
            value = http_header_find(&http_server->header, "Connection");
        }
        if (value) {
            if (strcasecmp(value, "Keep-Alive") == 0) {
                http_server->flags.keepalive = 1;
            } else {
                http_server->flags.keepalive = 0;
            }
        }
        LOG(LOG_DEBUG, "url=%s sock=%d keepalive=%d\n", string_buf(&http_session->url), conn->sock, http_server->flags.keepalive ? 1 : 0);
    } else if (http_session->header_parser.http_parser.http_errno == HPE_OK) {
        LOG(LOG_DEBUG, "url=%s sock=%d len=%zu nparse=%zu header_recv=%zu continue\n", string_buf(&http_session->url), conn->sock, len, nparse, http_server->header_recv);
        assert(nparse == len);
        conn_enable(conn, CONN_READ);
        return;
    } else {
        LOG(LOG_ERROR, "url=%s sock=%d len=%zu nparse=%zu header_recv=%zu error\n", string_buf(&http_session->url), conn->sock, len, nparse, http_server->header_recv);
        http_server_close(http_session, ERR_HTTP_HEADER);
        return;
    }
    value = http_header_find(&http_server->header, "Transfer-Encoding");
    if (value && strcmp(value, "chunked") == 0) {
        http_server->flags.chunked = 1;
        http_server->body_end = INT64_MAX;
    } else {
        if (http_server->header.response.status_code == HTTP_STATUS_PARTIAL_CONTENT) {
            value = http_header_find(&http_server->header, "Content-Range");
            if (value && http_content_range_parse(&content_range, value) == 0) {
                http_server->body_start = content_range.start;
                http_server->body_end = content_range.end;
                content_length = content_range.content_length;
                LOG(LOG_DEBUG, "url=%s sock=%d Content-Range: %s\n", string_buf(&http_session->url), conn->sock, value);
            } else {
                LOG(LOG_ERROR, "url=%s sock=%d Content-Range: %s parse error\n", string_buf(&http_session->url), conn->sock, value);
                http_server_close(http_session, ERR_HTTP_RANGE);
                return;
            }
        } else {
            value = http_header_find(&http_server->header, "Content-Length");
            if (value) {
                content_length = atoll(value);
                http_server->body_end = content_length;
                LOG(LOG_DEBUG, "url=%s sock=%d Content-Length=%"PRId64"\n", string_buf(&http_session->url), conn->sock, content_length);
            }
        }
    }
    if (http_session->header.request.method == HTTP_HEAD ||
            http_server->header.response.status_code == HTTP_STATUS_NO_CONTENT ||
            http_server->header.response.status_code == HTTP_STATUS_NOT_MODIFIED) {
        http_server->body_start = 0;
        http_server->body_end = 0;
    }
    if (http_server->type == HTTP_SERVER_ORIGIN || http_server->type == HTTP_SERVER_IMS) {
        assert(http_session->body_low == 0);
        assert(http_session->body_high == 0);
        assert(fifo_len(&http_session->body) == 0);
        http_session->body_low = http_server->body_start - PAGE_OFFSET(http_server->body_start);
        http_session->body_high = http_server->body_start;
        if (http_server->type == HTTP_SERVER_IMS) {
            if (http_server->header.response.status_code == HTTP_STATUS_NOT_MODIFIED) {
                http_client_build_response(http_session, http_server->header.response.status_code, CACHE_STATUS_REFRESH_HIT);
            } else {
                http_session->content_length = content_length;
                http_client_build_response(http_session, http_server->header.response.status_code, CACHE_STATUS_REFRESH_MISS);
            }
        } else {
            http_session->content_length = content_length;
            http_client_build_response(http_session, http_server->header.response.status_code, CACHE_STATUS_MISS);
        }
        if (http_session->conn) {
            conn_enable(http_session->conn, CONN_WRITE);
        }
    } else if (http_server->body_start != http_session->body_high) {
        LOG(LOG_ERROR, "url=%s sock=%d body_start=%"PRId64" diff body_high=%"PRId64"\n",
                string_buf(&http_session->url), conn->sock, http_server->body_start, http_session->body_high);
        http_server_close(http_session, ERR_HTTP_RANGE);
        return;
    }
    copy_len = 0;
    body_len = len - nparse;
    while (copy_len < body_len) {
        page = fifo_get(&http_session->body, PAGE_INDEX(http_session->body_high - http_session->body_low));
        if (!page) {
            page = mem_malloc(sizeof(struct page_t));
            fifo_push_tail(&http_session->body, page);
        }
        n = PAGE_SIZE - PAGE_OFFSET(http_session->body_high);
        if (body_len - copy_len < n) {
            n = body_len - copy_len;
        }
        LOG(LOG_DEBUG, "url=%s sock=%d copy=%zu\n", string_buf(&http_session->url), conn->sock, n);
        memcpy(page->buf + PAGE_OFFSET(http_session->body_high), buf + nparse + copy_len, n);
        http_session->body_high += n;
        copy_len += n;
    }
    conn->handle_read = http_server_body_read;
    http_server_body_process(http_session, buf + nparse, copy_len);
}

static void http_server_body_read(struct conn_t *conn)
{
    struct http_session_t *http_session = conn->data;
    //struct http_server_t *http_server = http_session->http_server;
    struct page_t *page;
    char *buf;
    size_t len;
    ssize_t n;

    page = fifo_get(&http_session->body, PAGE_INDEX(http_session->body_high - http_session->body_low));
    if (!page) {
        page = mem_malloc(sizeof(struct page_t));
        fifo_push_tail(&http_session->body, page);
    }
    buf = page->buf + PAGE_OFFSET(http_session->body_high);
    len = PAGE_SIZE - PAGE_OFFSET(http_session->body_high);
    n = recv(conn->sock, buf, len, 0);
    if (n > 0) {
        LOG(LOG_DEBUG, "url=%s sock=%d recv=%zd\n", string_buf(&http_session->url), conn->sock, n);
        conn_timer_set(conn, HTTP_SERVER_TIMEOUT);
        http_session->body_high += n;
        http_server_body_process(http_session, buf, n);
    } else if(n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        conn_ready_unset(conn, CONN_READ);
        conn_enable(conn, CONN_READ);
    } else {
        LOG(LOG_ERROR, "url=%s sock=%d recv=%zd error:%s\n", string_buf(&http_session->url), conn->sock, n, strerror(errno));
        http_server_close(http_session, ERR_CONN_READ);
    }
}

static void http_server_body_process(struct http_session_t *http_session, const char *buf, size_t len)
{
    struct http_server_t *http_server = http_session->http_server;
    int r;
    size_t chunked_len;
    size_t pos;
    size_t parse;

    if (http_server->flags.chunked) {
        parse = 0;
        do {
            chunked_len = len - parse;
            r = http_chunked_parse(&http_server->chunked, buf + parse, chunked_len, &pos);
            parse += pos;
            if (r == CHUNKED_OK) {
                //LOG(LOG_DEBUG, "url=%s sock=%d chunked=%"PRId64"\n", string_buf(&http_session->url), http_server->conn->sock, http_server->chunked.size);
                if (chunked_len - pos >= http_server->chunked.size) {
                    parse += http_server->chunked.size;
                    http_server->chunked.size = 0;
                    continue;
                }
                http_server->chunked.size -= chunked_len - pos;
                parse += chunked_len - pos;
                continue;
            }
        } while (r == CHUNKED_OK);
        if (r == CHUNKED_DONE) {
            //LOG(LOG_DEBUG, "url=%s sock=%d chunked=%"PRId64"\n", string_buf(&http_session->url), http_server->conn->sock, http_server->chunked.size);
            http_session->body_end = http_server->body_end = http_session->body_high - len + parse;
        } else if (r == CHUNKED_AGAIN) {
            //LOG(LOG_DEBUG, "url=%s sock=%d chunked again\n", string_buf(&http_session->url), http_server->conn->sock);
        } else if (r == CHUNKED_ERROR) {
            LOG(LOG_ERROR, "url=%s sock=%d chunked error\n", string_buf(&http_session->url), http_server->conn->sock);
            http_server_close(http_session, ERR_HTTP_BODY);
            return;
        }
    }
    if (http_session->conn && http_session->body_send < http_session->body_high && http_session->body_send >= http_session->body_low) {
        conn_enable(http_session->conn, CONN_WRITE);
    }
    if (http_session->body_high < http_server->body_end) {
        if (http_session->body_high - http_session->body_low < PAGE_SIZE_N(fifo_size(&http_session->body))) {
            conn_enable(http_server->conn, CONN_READ);
        } else {
            conn_disable(http_server->conn, CONN_READ);
        }
    } else {
        LOG(LOG_DEBUG, "url=%s sock=%d recv done\n", string_buf(&http_session->url), http_server->conn->sock);
        http_server_close(http_session, ERR_OK);
    }
}

static void http_server_timeout(struct conn_t *conn)
{
    struct http_session_t *http_session = conn->data;
    LOG(LOG_INFO, "url=%s sock=%d timeout\n", string_buf(&http_session->url), conn->sock);
    http_server_close(http_session, ERR_CONN_TIMEOUT);
}

static void http_server_keepalive_timeout(struct conn_t *conn)
{
    LOG(LOG_ERROR, "sock=%d timeout\n", conn->sock);
    conn_keepalive_unset(conn);
    conn_close(conn);
}

static void http_server_keepalive_read(struct conn_t *conn)
{
    char buf[PAGE_SIZE];
    ssize_t n;

    n = read(conn->sock, buf, sizeof(buf));
    if (n > 0) {
        LOG(LOG_DEBUG, "sock=%d read=%zd\n", conn->sock, n);
        conn_keepalive_unset(conn);
        conn_close(conn);
    } else if(n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        conn_ready_unset(conn, CONN_READ);
        conn_enable(conn, CONN_READ);
    } else {
        LOG(LOG_ERROR, "sock=%d read=%zd error:%s\n", conn->sock, n, strerror(errno));
        conn_keepalive_unset(conn);
        conn_close(conn);
    }
}

static void http_server_keepalive(struct http_session_t *http_session)
{
    struct http_server_t *http_server = http_session->http_server;
    struct conn_t *conn = http_server->conn;
    char str[64];
    char buf[PAGE_SIZE];
    ssize_t n;

    n = read(conn->sock, buf, sizeof(buf));
    if (n > 0) {
        LOG(LOG_ERROR, "url=%s sock=%d read=%zd\n", string_buf(&http_session->url), conn->sock, n);
        conn_close(conn);
    } else if(n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        conn_ready_unset(conn, CONN_READ);
        LOG(LOG_DEBUG, "url=%s sock=%d %s keepalive set\n", string_buf(&http_session->url), conn->sock, conn_addr_ntop(&conn->peer_addr, str, sizeof(str)));
        if (conn_keepalive_set(conn)) {
            conn_close(conn);
        } else {
            conn->data = NULL;
            conn->handle_read = http_server_keepalive_read;
            conn->handle_write = NULL;
            conn->handle_timeout = http_server_keepalive_timeout;
            conn_timer_set(conn, HTTP_SERVER_TIMEOUT);
            conn_disable(conn, CONN_WRITE);
            conn_enable(conn, CONN_READ);
        }
    } else {
        LOG(LOG_ERROR, "url=%s sock=%d read=%zd error:%s\n", string_buf(&http_session->url), conn->sock, n, strerror(errno));
        conn_close(conn);
    }
}

static void http_server_close(struct http_session_t *http_session, int err)
{
    struct http_server_t *http_server = http_session->http_server;
    struct conn_t *conn = http_server->conn;
    LOG(LOG_INFO, "url=%s sock=%d body_size=%"PRId64" err=%d\n",
            string_buf(&http_session->url), conn?conn->sock:-1, http_session->body_high - http_server->body_start, err);
    if (conn) {
        if (!err && http_server->flags.keepalive) {
            http_server_keepalive(http_session);
        } else {
            conn_close(conn);
        }
        http_server->conn = NULL;
    }
    http_header_clean(&http_server->header);
    string_clean(&http_server->request);
    http_session->http_server = NULL;
    mem_free(http_server);
    if (err) {
        if (http_session->conn) {
            if (string_len(&http_session->response) == 0) {
                if (err == ERR_CONN_TIMEOUT) {
                    http_client_build_response(http_session, HTTP_STATUS_GATEWAY_TIMEOUT, CACHE_STATUS_NONE);
                } else {
                    http_client_build_response(http_session, HTTP_STATUS_SERVICE_UNAVAILABLE, CACHE_STATUS_NONE);
                }
                conn_enable(http_session->conn, CONN_WRITE);
            } else if (http_session->body_send < http_session->body_high) {
                conn_enable(http_session->conn, CONN_WRITE);
            } else {
                http_client_close(http_session, ERR_CONN_ABORT);
            }
        } else {
            http_session_close(http_session);
        }
    } else {
        if (http_session->conn) {
        } else {
            http_session_close(http_session);
        }
    }
}

static void http_session_close(struct http_session_t *http_session)
{
    struct page_t *page = NULL;

    assert(http_session->conn == NULL && http_session->http_server == NULL);
    if (aio_busy(&http_session->aio)) {
        LOG(LOG_DEBUG, "url=%s busy\n", string_buf(&http_session->url));
        return;
    }
    LOG(LOG_INFO, "url=%s close\n", string_buf(&http_session->url));
    string_clean(&http_session->url);
    http_header_clean(&http_session->header);
    while ((page = fifo_head(&http_session->post))) {
        fifo_pop_head(&http_session->post);
        mem_free(page);
    }
    while ((page = fifo_head(&http_session->body))) {
        fifo_pop_head(&http_session->body);
        mem_free(page);
    }
    fifo_clean(&http_session->post);
    fifo_clean(&http_session->body);
    string_clean(&http_session->response);
    mem_free(http_session);
}
