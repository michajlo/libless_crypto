#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "md5.h"

int main() {
    uint8_t *in = "";
    uint8_t out[16];
    uint32_t i;

    md5(in, strlen(in), out);

    for (i=0; i<16; i++) {
        printf("%02x", out[i]);
    }
    printf("\n");
}
