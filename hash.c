#include "os.h"
#include "hash.h"

unsigned int hash_string(const void *data)
{
    const char *s = data;
    unsigned int n = 0;
    unsigned int j = 0;
    unsigned int i = 0;
    while (*s) {
        j++;
        n ^= 271 * (unsigned) *s++;
    }
    i = n ^ (j * 271);
    return i;
}

unsigned int hash4(const void *data)
{
    const char *key = data;
    size_t loop;
    unsigned int h;
    size_t len;

#define HASH4a   h = (h << 5) - h + *key++;
#define HASH4b   h = (h << 5) + h + *key++;
#define HASH4 HASH4b

    h = 0;
    len = strlen(key);
    loop = len >> 3;
    switch (len & (8 - 1)) {
        case 0:
            break;
        case 7:
            HASH4;
            /* FALLTHROUGH */
        case 6:
            HASH4;
            /* FALLTHROUGH */
        case 5:
            HASH4;
            /* FALLTHROUGH */
        case 4:
            HASH4;
            /* FALLTHROUGH */
        case 3:
            HASH4;
            /* FALLTHROUGH */
        case 2:
            HASH4;
            /* FALLTHROUGH */
        case 1:
            HASH4;
    }
    while (loop--) {
        HASH4;
        HASH4;
        HASH4;
        HASH4;
        HASH4;
        HASH4;
        HASH4;
        HASH4;
    }
    return h;
}
