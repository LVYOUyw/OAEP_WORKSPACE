#include "hybrid.h"

#include "aes128gcm.h"
#include <stdio.h>

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "api.h"
#include "randombytes.h"


int crypto_hybrid_enc(unsigned char *c, const unsigned char *m, const int l, const unsigned char *pk)
{
  
  int coutlen,ret;
  unsigned char k[CRYPTO_BYTES];

  crypto_kem_enc(c,k,pk);
  randombytes(c + CRYPTO_CIPHERTEXTBYTES, GCM_IV_BYTES);

  ret = aes_gcm_encrypt(c + CRYPTO_CIPHERTEXTBYTES + GCM_IV_BYTES + 16,c + CRYPTO_CIPHERTEXTBYTES + GCM_IV_BYTES,&coutlen,k,c+CRYPTO_CIPHERTEXTBYTES,m,l);
  return 0;
}



int crypto_hybrid_dec(unsigned char *m, const unsigned char *c, const int cl, const unsigned char *sk)
{
  unsigned char k[CRYPTO_BYTES];
  int fail,mlen;


  fail = crypto_kem_dec(k,c,sk);



  if (fail!=0)
  {
    puts("Early Quit");
    return 0;
  }
  else fail = aes_gcm_decrypt(m,&mlen,k,c + CRYPTO_CIPHERTEXTBYTES + GCM_IV_BYTES + 16,cl- CRYPTO_CIPHERTEXTBYTES  -GCM_IV_BYTES - 16, c + CRYPTO_CIPHERTEXTBYTES +GCM_IV_BYTES,c+CRYPTO_CIPHERTEXTBYTES)==1?0:1;
  return fail;

  
}
