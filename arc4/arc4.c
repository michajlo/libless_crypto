#include "arc4.h"

static void swap(unsigned char *S, unsigned int i, unsigned int j) {
    unsigned char tmp = S[i];
    S[i] = S[j];
    S[j] = tmp;
}

int arc4_init(arc4_t *state, const unsigned char *key, unsigned int klen) {
    int i, j;
    unsigned char *S = state->S;
    for (i=0; i<256; i++) {
        S[i] = i;
    }

    j = 0;
    for (i=0; i<256; i++) {
        j = (j + S[i] + key[i%klen]) % 256;
        swap(S, i, j);
    }

    state->i = 0;
    state->j = 0;

    return 0;
}

int arc4_process(arc4_t *state, const unsigned char *in, unsigned char *out, unsigned int len) {
    int idx;
    unsigned char *S = state->S;
    for (idx=0; idx<len; idx++) {
        state->i = (state->i + 1) % 256;
        state->j = (state->j + S[state->i]) % 256;
        swap(S, state->i, state->j);
        out[idx] = in[idx] ^ S[(S[state->i] + S[state->j]) % 256];
    }
    return 0;
}
