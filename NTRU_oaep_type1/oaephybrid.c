#include "oaephybrid.h"

#include "aes128gcm.h"
#include <stdio.h>

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "poly.h"
#include "symmetric.h"
#include "api.h"
#include "randombytes.h"


int crypto_pkem_encap(unsigned char *c, unsigned int *clen, unsigned char *k, const unsigned char *m, int mlen, const unsigned char *pk)
{
  uint8_t msg[NTRUOAEP_N / 8] = {0};
  uint8_t randomness[NTRUOAEP_N / 4] = {0};
  uint8_t sigma[KeyConfirmation_BYTES]; 
  uint8_t buff[NTRUOAEP_SYMBYTES + NTRUOAEP_N / 2];
  int8_t fail = 0;

  poly p_c, p_h, p_s, p_t;
  
  randombytes(randomness, NTRUOAEP_N / 4);


  for (int i = 0; i < mlen; i++) msg[i] = m[i];

  // poly_oaep(&p_s, &p_t, randomness, msg);

  poly_cbd1(&p_t, randomness);

  short_poly_to_bytes(buff + NTRUOAEP_SYMBYTES + NTRUOAEP_N / 4, &p_t);

  hash_g(randomness, buff + NTRUOAEP_SYMBYTES + NTRUOAEP_N / 4);

  poly_sotp(&p_s, msg, randomness);    

  short_poly_to_bytes(buff + NTRUOAEP_SYMBYTES, &p_s);


  poly_ntt(&p_s, &p_s);


  poly_ntt(&p_t, &p_t);


  poly_frombytes(&p_h, pk);


  hash_f(buff, pk);

  poly_basemul_add(&p_c, &p_h, &p_s, &p_t);


  poly_tobytes(c, &p_c);

  //for (int i = 0; i < NTRUOAEP_SYMBYTES; i++) buff[i] = pk[i + NTRUOAEP_POLYBYTES];

  hash_h_prime(sigma, buff);

  for (int i = NTRUOAEP_POLYBYTES; i < NTRUOAEP_PKEM_CIPHERTEXTBYTES; i++) c[i] = sigma[i - NTRUOAEP_POLYBYTES];

  for (size_t i = 0; i < 16; i++)
  {
    k[i] = sigma[32 + i];
  }
  

  *clen = NTRUOAEP_PKEM_CIPHERTEXTBYTES;

  return fail;
}


int crypto_hybrid_enc(unsigned char *c, const unsigned char *m, const int l, const unsigned char *pk)
{
  int oaepclen,coutlen;
  unsigned char k[16];
  if (l <= NTRUOAEP_MAXPLAINTEXT)
  {
    /* code */
  } else {
    crypto_pkem_encap(c,&oaepclen,k,m,NTRUOAEP_MAXPLAINTEXT,pk);

    
    randombytes(c + oaepclen, GCM_IV_BYTES);
    aes_gcm_encrypt(c + oaepclen + GCM_IV_BYTES + 16,c + oaepclen + GCM_IV_BYTES,&coutlen,k,c+oaepclen,m+NTRUOAEP_MAXPLAINTEXT,l-NTRUOAEP_MAXPLAINTEXT);

  
  }
  return 0;
}


int crypto_pkem_decap(unsigned char *m, unsigned char *k, const unsigned char *c, const unsigned char *sk)
{
  uint8_t r[NTRUOAEP_N / 4];
  uint8_t buff[NTRUOAEP_SYMBYTES + NTRUOAEP_N / 2];
  uint8_t sigma[KeyConfirmation_BYTES];
  int8_t fail = 0;

  poly p_c, p_f, p_hinv;
  poly p_s, p_t;
  poly p_tmp;


  poly_frombytes(&p_c, c);
  poly_frombytes(&p_f, sk);
  poly_frombytes(&p_hinv, sk + NTRUOAEP_POLYBYTES);

  poly_basemul(&p_tmp, &p_c, &p_f);
  poly_invntt(&p_tmp, &p_tmp);
  poly_crepmod3(&p_t, &p_tmp);

  poly_ntt(&p_tmp, &p_t);
  poly_sub(&p_c, &p_c, &p_tmp);
  poly_basemul(&p_s, &p_c, &p_hinv);
  /*
  poly_invntt(&p_s, &p_s);
  poly_frommontgomery(&p_s, &p_s);
  */
  poly_invntt_normalized(&p_s, &p_s);

  //fail = poly_oaep_inv(&p_s, &p_t, r, m);
  for (int i = 0; i < NTRUOAEP_N; i++) fail |= (p_s.coeffs[i] > 1 || p_s.coeffs[i] < -1);

  short_poly_to_bytes(buff + NTRUOAEP_SYMBYTES + NTRUOAEP_N / 4, &p_t); 

  hash_g(r, buff + NTRUOAEP_SYMBYTES + NTRUOAEP_N / 4);

  fail |= poly_sotp_inv(m, &p_s, r);  

  for (int i = 0; i < NTRUOAEP_SYMBYTES; i++) buff[i] = sk[NTRUOAEP_POLYBYTES * 2 + i];

  short_poly_to_bytes(buff + NTRUOAEP_SYMBYTES, &p_s);

  hash_h_prime(sigma, buff);

  for (int i = NTRUOAEP_POLYBYTES; i < NTRUOAEP_PKEM_CIPHERTEXTBYTES; i++) {
  // printf("%u %u\n", c[i], sigma[i - NTRUOAEP_POLYBYTES]);
  fail |= (c[i] ^ sigma[i - NTRUOAEP_POLYBYTES]);
  }

  if (fail==0)
  {
    for (size_t i = 0; i < 16; i++)
    {
      k[i]=sigma[32+i];
    }
  }
  return fail;
}

int crypto_hybrid_dec(unsigned char *m, const unsigned char *c, const int cl, const unsigned char *sk)
{
  unsigned char k[16];
  int fail,mlen;
  if (cl==NTRUOAEP_PKEM_CIPHERTEXTBYTES)
  {
    
  } else if(cl > NTRUOAEP_PKEM_CIPHERTEXTBYTES) {
    
    memset(m,0, NTRUOAEP_MAXPLAINTEXT);
    fail = crypto_pkem_decap(m,k,c,sk);

    

    if (fail!=0)
    {
      puts("Early Quit");
      return 0;
    }
    else fail = aes_gcm_decrypt(m+NTRUOAEP_MAXPLAINTEXT,&mlen,k,c + NTRUOAEP_PKEM_CIPHERTEXTBYTES + GCM_IV_BYTES + 16,cl-NTRUOAEP_PKEM_CIPHERTEXTBYTES-GCM_IV_BYTES - 16, c + NTRUOAEP_PKEM_CIPHERTEXTBYTES +GCM_IV_BYTES,c+NTRUOAEP_PKEM_CIPHERTEXTBYTES)==1?0:1;
    return fail;

  }
  
}
