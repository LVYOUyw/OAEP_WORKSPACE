#ifndef API_H
#define API_H

#include "params.h"

#define CRYPTO_SECRETKEYBYTES  NTRUOAEP_SECRETKEYBYTES
#define CRYPTO_PUBLICKEYBYTES  NTRUOAEP_PUBLICKEYBYTES
#define CRYPTO_CIPHERTEXTBYTES NTRUOAEP_CIPHERTEXTBYTES
#define CRYPTO_MAXPLAINTEXT    NTRUOAEP_MAXPLAINTEXT
#define CRYPTO_BYTES           NTRUOAEP_SYMBYTES

#define CRYPTO_ALGNAME "NTRUOAEP648"

int crypto_encrypt_keypair(unsigned char *pk,
                           unsigned char *sk);

int crypto_encrypt(unsigned char *c,
                   unsigned long long *clen,
                   const unsigned char *m,
                   unsigned long long mlen,
                   const unsigned char *pk);

int crypto_encrypt_open(unsigned char *m,
                        const unsigned char *c,
                        const unsigned char *sk);

#endif
