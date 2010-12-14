#include <stdlib.h>
#include <string.h>
#include "md5.h"

#define LEFT_ROTATE(x,c)    (((x) << (c)) | ((x) >> (32-(c))))

uint8_t r[] = {
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
};

uint32_t k[] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

int md5(uint8_t *in, uint32_t len, uint8_t *out) {
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xEFCDAB89;
    uint32_t h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476;

    uint8_t *message;
    uint32_t message_len;
    uint32_t offset;

    if ((len + 1) % 64 <= 48) {
        message_len = ((len + 1)/64) * 64 + 64;
    } else {
        message_len = ((len + 1)/64) * 64 + 128;
    }

    message = (uint8_t *)malloc(message_len);
    memcpy(message, in, len);
    message[len] = 0x80;
    memset(message + len + 1, '\0', message_len - len - 9);

    *((uint64_t *)(message + message_len - 8)) = len * 8L;

    for (offset=0; offset<message_len; offset+=64) {
        uint32_t w[16];
        uint32_t i;
        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;

        for (i=0; i<16; i++) {
            w[i] = *((uint32_t *)(message + offset + i*4));
        }

        for (i=0; i<64; i++) {
            uint32_t f, g;
            uint32_t tmp;
            if (0 <= i && i <= 15) {
                f = (b & c) | (~b & d);
                g = i;
            } else if (16 <= i && i <= 31) {
                f = (d & b) | (~d & c);
                g = (5*i + 1) % 16;
            } else if (32 <= i && i <= 47) {
                f = b ^ c ^ d;
                g = (3*i + 5) % 16;
            } else {
                f = c ^ (b | ~d);
                g = (7*i) % 16;
            }
            
            tmp = d;
            d = c;
            c = b;
            b = b + LEFT_ROTATE(a + f + k[i] + w[g], r[i]);
            a = tmp;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
    }

    *((uint32_t *)(out)) = h0;
    *((uint32_t *)(out + 4)) = h1;
    *((uint32_t *)(out + 8)) = h2;
    *((uint32_t *)(out + 12)) = h3;
    
    free(message);

    return 0;
}
