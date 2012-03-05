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
    uint8_t state[16];
    uint8_t *expanded_key;
} aes_t;

#define AES_CIPHERTEXT_SIZE(l) ((((l + 15)/16) * 16)

int aes_init(aes_t *aes, uint32_t aes_type, uint8_t *key, uint8_t key_len);
int aes_destroy(aes_t *aes);

int aes_encrypt(aes_t *aes, uint8_t *in, uint32_t in_len, uint8_t *out);
int aes_decrypt(aes_t *aes, uint8_t *in, uint32_t in_len, uint8_t *out);

#ifdef UNDER_TEST
void sub_bytes(aes_t *aes);
void sub_bytes_inv(aes_t *aes);
void add_round_key(aes_t *aes, uint32_t round);
void shift_rows(aes_t *aes);
void shift_rows_inv(aes_t *aes);
void mix_columns(aes_t *aes);
void mix_columns_inv(aes_t *aes);
void encrypt_block(aes_t *aes);
void decrypt_block(aes_t *aes);
#endif

#endif
