#ifndef __AES_H__
#define __AES_H__

#include <stdint.h>

#define AES_128 16
#define AES_192 24
#define AES_256 32

typedef struct {
    uint32_t key_size;
    uint32_t expanded_key_len;
    uint32_t num_rounds;
    uint32_t ;
    uint8_t state[16];
    uint8_t *expanded_key;
} aes_t;

#define AES_CIPHERTEXT_SIZE(l) ((((l + 15)/16) * 16)

int aes_init(aes_t *aes, uint32_t aes_type, uint8_t *key, uint8_t key_len);
int aes_destroy(aes_t *aes);

int aes_encrypt_block(aes_t *aes, uint8_t *in, uint8_t *out);
int aes_decrypt_block(aes_t *aes, uint8_t *in, uint8_t *out);

int aes_encrypt(aes_t *aes, uint8_t *in, uint32_t in_len, uint8_t *out);
int aes_decrypt(aes_t *aes, uint8_t *in, uint32_t in_len, uint8_t *out);
#endif
