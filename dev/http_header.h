#ifndef HTTP_HEADER_H
#define HTTP_HEADER_H

#include "list.h"
#include "http_parser.h"

#define CHUNKED_MAX INT64_MAX

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

struct http_chunked_t {
    int      state;
    int64_t  size;
    int64_t  length;
};

void http_header_init(struct http_header_t *header);
void http_header_add(struct http_header_t *header, const char *field, const char *value);
void http_header_del(struct http_header_t *header, const char *field);
const char* http_header_find(struct http_header_t *header, const char *field);
void http_header_sprintf(struct http_header_t *header, enum http_parser_type type, struct string_t *string);
void http_header_uninit(struct http_header_t *header);

int http_content_range_parse(struct http_content_range_t *content_range, const char *value);
int http_chunked_parse(struct http_chunked_t *chunked, const char *buf, size_t buf_len, size_t *buf_pos);

extern http_parser_settings http_header_parser_settings;

#endif
