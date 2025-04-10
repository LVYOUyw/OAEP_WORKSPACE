
#ifndef NTRUOAEPKEM_H
#define NTRUOAEPKEM_H

#include "params.h"
#define OAEP_EMBEDDED_PT_BYTES 84
#define OAEP_EMBEDDED_BYTES (OAEP_EMBEDDED_PT_BYTES / 7) * 8


int crypto_pkem_encap(unsigned char *c,
    unsigned int *clen,
    unsigned char *k,
    const unsigned char *m,
    int mlen,
    const unsigned char *pk);
    


int crypto_hybrid_enc(unsigned char *c, const unsigned char *m, const int l, const unsigned char *pk);

int crypto_hybrid_dec(unsigned char *m, const unsigned char *c, const int cl, const unsigned char *sk);

#endif
