#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "arc4.h"

int main(int argc, char **argv) {
    arc4_t s;
    unsigned char *key, *in, *out;
    unsigned int klen, len;
    
    unsigned int i;

    if (argc < 3) {
        fprintf(stderr, "usage: %s key plaintext", argv[0]);
        return 1;
    }

    key = argv[1];
    klen = strlen(key);
    in = argv[2];
    len = strlen(in);

    out = (unsigned char *)malloc(len);

    arc4_init(&s, key, klen);
    arc4_encrypt(&s, in, out, len);

    for (i=0; i<len; i++) {
        printf("%02x", out[i]);
    }
    printf("\n");
}
