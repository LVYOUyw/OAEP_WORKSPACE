
#ifndef NTRUOAEPKEM_H
#define NTRUOAEPKEM_H

#include "params.h"
#define OAEP_EMBEDDED_PT_BYTES 84
#define OAEP_EMBEDDED_BYTES (OAEP_EMBEDDED_PT_BYTES / 7) * 8

#define crypto_pkem_enc CRYPTO_NAMESPACE(oaeppkemenc)
int crypto_pkem_enc(unsigned char *c, unsigned char *k, const unsigned char *m, const unsigned char *pk);

#define crypto_pkem_dec CRYPTO_NAMESPACE(oaeppkemdec)
int crypto_pkem_dec(unsigned char *m, unsigned char *k, const unsigned char *c, const unsigned char *sk);

#define crypto_hybrid_enc CRYPTO_NAMESPACE(hybridenc)
int crypto_hybrid_enc(unsigned char *c, const unsigned char *m, const int l, const unsigned char *pk);

#define crypto_hybrid_dec CRYPTO_NAMESPACE(hybriddec)
int crypto_hybrid_dec(unsigned char *m, const unsigned char *c, const int cl, const unsigned char *sk);

#endif
