#ifndef MD5_H
#define MD5_H

#include <stdio.h>
#include <stdint.h>

struct md5_t {
  uint64_t  bytes;
  uint32_t  a, b, c, d;
  uint8_t    buffer[64];
};


void md5_init(struct md5_t *ctx);
void md5_update(struct md5_t *ctx, const void *data, size_t size);
void md5_final(uint8_t result[16], struct md5_t *ctx);

#endif
