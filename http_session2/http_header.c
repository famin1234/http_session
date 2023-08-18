#include "os.h"
#include "mem.h"
#include "http_parser.h"
#include "http_header.h"

#define CR '\r'
#define LF '\n'

static int on_message_begin(http_parser *http_parser);
static int on_url(http_parser *http_parser, const char *buf, size_t len);
static int on_header_field(http_parser *http_parser, const char *buf, size_t len);
static int on_header_value(http_parser *http_parser, const char *buf, size_t len);
static int on_headers_complete(http_parser *http_parser);
static int on_body(http_parser *http_parser, const char *buf, size_t len);
static int on_message_complete(http_parser *http_parser);

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

void http_header_init(struct http_header_t *header)
{
    INIT_LIST_HEAD(&header->list);
}

struct http_header_entry_t *http_header_entry_alloc()
{
    struct http_header_entry_t *entry;
    entry = mem_malloc(sizeof(struct http_header_entry_t));
    entry->field = NULL;
    entry->value = NULL;
    return entry;
}

void http_header_entry_free(struct http_header_entry_t *entry)
{
    mem_free(entry->field);
    mem_free(entry->value);
    mem_free(entry);
}

void http_header_add(struct http_header_t *header, const char *field, const char *value)
{
    //struct http_header_entry_t *entry;
}

void http_header_del(struct http_header_t *header, const char *field)
{
    struct http_header_entry_t *entry;
    struct http_header_entry_t *entry_tmp;
    list_for_each_entry_safe(entry, entry_tmp, &header->list, node) {
        if (strcasecmp(entry->field, field) == 0) {
            list_del(&entry->node);
            http_header_entry_free(entry);
        }
    }
}

const char* http_header_find(struct http_header_t *header, const char *field)
{
    struct http_header_entry_t *entry;
    list_for_each_entry(entry, &header->list, node) {
        if (strcasecmp(entry->field, field) == 0) {
            return entry->value;
        }
    }
    return NULL;
}

void http_header_print(struct http_header_t *header, enum http_parser_type type, struct string_t *string)
{
    struct http_header_entry_t *entry;

    if (type == HTTP_REQUEST) {
        string_sprint(string, "%s %s HTTP/%d.%d\r\n", http_method_str(header->request.method), string_buf(header->request.url), header->http_major, header->http_minor);
    } else if (type == HTTP_RESPONSE) {
        string_sprint(string, "HTTP/%d.%d %d %s\r\n", header->http_major, header->http_minor, header->response.status_code, http_status_str(header->response.status_code));
    }
    list_for_each_entry(entry, &header->list, node) {
        string_sprint(string, "%s: %s\r\n", entry->field, entry->value);
    }
    string_strcat(string, "\r\n");
}

void http_header_clean(struct http_header_t *header)
{
    struct http_header_entry_t *entry;
    while (!list_empty(&header->list)) {
        entry = d_list_head(&header->list, struct http_header_entry_t, node);
        list_del(&entry->node);
        http_header_entry_free(entry);
    }
}

int http_content_range_parse(struct http_content_range_t *content_range, const char *value)
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

static int on_message_begin(http_parser *http_parser)
{
    return 0;
}

static int on_url(http_parser *http_parser, const char *buf, size_t len)
{
    struct http_header_t *header = http_parser->data;

    assert(http_parser->type == HTTP_REQUEST);
    string_strncat(header->request.url, buf, len);
    return 0;
}

static int on_header_field(http_parser *http_parser, const char *buf, size_t len)
{
    struct http_header_t *header = http_parser->data;
    struct http_header_entry_t *entry;
    size_t old_len = 0;

    if (list_empty(&header->list)) {
        entry = http_header_entry_alloc();
        list_add_tail(&entry->node, &header->list);
    } else {
        entry = d_list_tail(&header->list, struct http_header_entry_t, node);
        if (entry->value) {
            entry = http_header_entry_alloc();
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
        header->request.method = http_parser->method;
    } else if (http_parser->type == HTTP_RESPONSE) {
        header->response.status_code = http_parser->status_code;
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

void http_header_parser_init(struct http_header_parser_t *http_header_parser, enum http_parser_type type)
{
    http_parser_init(&http_header_parser->http_parser, type);
}

size_t http_header_parser_execute(struct http_header_parser_t *http_header_parser, const char *data, size_t len)
{
    return http_parser_execute(&http_header_parser->http_parser, &http_header_parser_settings, data, len);
}

int http_chunked_parse(struct http_chunked_t *chunked, const char *buf, size_t buf_len, size_t *buf_pos)
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
