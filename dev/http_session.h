#ifndef HTTP_SESSION_H
#define HTTP_SESSION_H

#include <stdint.h>

int http_session_init(const char *host, uint16_t port);
int http_session_uninit();

#endif
