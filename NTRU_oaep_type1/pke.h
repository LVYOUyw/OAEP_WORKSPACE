#ifndef PKE_H
#define PKE_H

#include "params.h"

int crypto_encrypt_keypair(unsigned char *pk,
                           unsigned char *sk);

int crypto_encrypt(unsigned char *c,
                   unsigned long long *clen,
                   const unsigned char *m,
                   int mlen,
                   const unsigned char *pk);

int crypto_encrypt_open(unsigned char *m,
                        const unsigned char *c,
                        const unsigned char *sk);

int crypto_encap(unsigned char *c,
    unsigned long long *clen,
    unsigned char *ss,
    const unsigned char *pk);

int crypto_encap_open(unsigned char *ss,
    const unsigned char *c,
    const unsigned char *sk);

#endif
