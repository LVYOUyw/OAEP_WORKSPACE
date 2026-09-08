#include "hybrid.h"

#include "aes128gcm.h"
#include <stdio.h>

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "poly.h"
#include "api.h"
#include "randombytes.h"


int crypto_hybrid_enc(unsigned char *c, const unsigned char *m, const int l, const unsigned char *pk)
{
  int coutlen;
  unsigned long long cpkelen[5];
  int klen = 32;
  unsigned char k[32];

  randombytes(k, 32);

  int fail = crypto_encrypt(c, cpkelen, k, klen, pk);
  randombytes(c + CRYPTO_CIPHERTEXTBYTES, GCM_IV_BYTES);
  aes_gcm_encrypt(c + CRYPTO_CIPHERTEXTBYTES + GCM_IV_BYTES + 16,c + CRYPTO_CIPHERTEXTBYTES + GCM_IV_BYTES,&coutlen,k,c+CRYPTO_CIPHERTEXTBYTES, m, l);
  return fail;
}



int crypto_hybrid_dec(unsigned char *m, const unsigned char *c, const int cl, const unsigned char *sk)
{
  unsigned char k[32];
  int fail,mlen;
  unsigned long long klen[5]; 

  fail = crypto_encrypt_open(k, klen, c, NTRUPLUS_CIPHERTEXTBYTES, sk);
  if (fail!=0)
  {
    puts("Early Quit");
    return 0;
  }
  else fail = aes_gcm_decrypt(m,&mlen,k,c + CRYPTO_CIPHERTEXTBYTES + GCM_IV_BYTES + 16,cl- CRYPTO_CIPHERTEXTBYTES  -GCM_IV_BYTES - 16, c + CRYPTO_CIPHERTEXTBYTES +GCM_IV_BYTES,c+CRYPTO_CIPHERTEXTBYTES)==1?0:1;
  return fail;

  
}
