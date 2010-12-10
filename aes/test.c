#include <stdio.h>

#include "aes.h"

int main() {
    aes_t aes;
    int i;
    aes_init(&aes, AES_128, "Hello world12345", 16);
    for (i=0; i<aes.expanded_key_len; i++) {
        printf("%02x", aes.expanded_key[i]);
    }
    printf("\n");
}
