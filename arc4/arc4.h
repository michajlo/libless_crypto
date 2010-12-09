#ifndef __ARC4_H__
#define __ARC4_H__

typedef struct {
    unsigned int i, j;
    unsigned char S[256];
} arc4_t;

int arc4_init(arc4_t *state, const unsigned char *key, unsigned int klen);
int arc4(arc4_t *state, const unsigned char *in, unsigned char *out, unsigned int len);

#define arc4_encrypt(s,i,o,l)  arc4_process((s),(i),(o),(l))
#define arc4_decrypt(s,i,o,l)  arc4_process((s),(i),(o),(l))

#endif
