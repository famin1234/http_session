#ifndef HTTP_HEADER_H
#define HTTP_HEADER_H

#include "os.h"
#include "http_parser.h"

struct http_header_entry_t {
    char *field;
    char *value;
    struct list_head_t node;
};

struct http_header_t {
    union {
        struct {
            unsigned short method;
            struct string_t *url;
        } request;
        struct {
            unsigned short status_code;
        } response;
    };
    unsigned short http_major;
    unsigned short http_minor;
    struct list_head_t list;
};

struct http_header_parser_t {
    struct http_parser http_parser;
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

#define CHUNKED_MAX INT64_MAX

struct http_chunked_t {
    int      state;
    int64_t  size;
    int64_t  length;
};

void http_header_init(struct http_header_t *header);
void http_header_add(struct http_header_t *header, const char *field, const char *value);
void http_header_del(struct http_header_t *header, const char *field);
const char* http_header_find(struct http_header_t *header, const char *field);
void http_header_print(struct http_header_t *header, enum http_parser_type type, struct string_t *string);
void http_header_clean(struct http_header_t *header);

void http_header_parser_init(struct http_header_parser_t *http_header_parser, enum http_parser_type type);
size_t http_header_parser_execute(struct http_header_parser_t *http_header_parser, const char *data, size_t len);
int http_content_range_parse(struct http_content_range_t *content_range, const char *value);

int http_chunked_parse(struct http_chunked_t *chunked, const char *buf, size_t buf_len, size_t *buf_pos);

#endif
