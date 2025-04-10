#include "oaephybrid.h"

#include "api.h"
#include "cmov.h"
#include "crypto_hash_sha3256.h"
#include "owcpa.h"
#include "params.h"
#include "randombytes.h"
#include "sample.h"
#include "aes128gcm.h"
#include <stdio.h>

#include <string.h>



int b128encode(unsigned char *outs,const unsigned char *ins, const int l)
{

  if (l%7!=0) return 0; 
  for (size_t i = 0; 7 * i < l; i++)
  {
    outs[i * 8 + 0] = ins[7 * i] & 0x7f;  
    outs[i * 8 + 1] = (ins[7 * i]     >> 7) | ((ins[7 * i + 1] & 0x3f) <<1);
    outs[i * 8 + 2] = (ins[7 * i + 1] >> 6) | ((ins[7 * i + 2] & 0x1f) <<2);
    outs[i * 8 + 3] = (ins[7 * i + 2] >> 5) | ((ins[7 * i + 3] & 0x0f) <<3);
    outs[i * 8 + 4] = (ins[7 * i + 3] >> 4) | ((ins[7 * i + 4] & 0x07) <<4);
    outs[i * 8 + 5] = (ins[7 * i + 4] >> 3) | ((ins[7 * i + 5] & 0x03) <<5);
    outs[i * 8 + 6] = (ins[7 * i + 5] >> 2) | ((ins[7 * i + 6] & 0x01) <<6);
    outs[i * 8 + 7] =  ins[7 * i + 6] >> 1;
  }
  return 1;

}


int b128decode(unsigned char *outs,const unsigned char *ins, const int l)
{

  if (l%8!=0) return 0; 
  for (size_t i = 0; 8 * i < l; i++)
  {
    outs[i * 7 + 0] = ins[8 * i]     | ((ins[8 * i + 1] & 0x01) << 7);
    outs[i * 7 + 1] = (ins[8 * i + 1] >> 1) | ((ins[8 * i + 2] & 0x03) << 6);
    outs[i * 7 + 2] = (ins[8 * i + 2] >> 2) | ((ins[8 * i + 3] & 0x07) << 5);
    outs[i * 7 + 3] = (ins[8 * i + 3] >> 3) | ((ins[8 * i + 4] & 0x0f) << 4);
    outs[i * 7 + 4] = (ins[8 * i + 4] >> 4) | ((ins[8 * i + 5] & 0x1f) << 3);
    outs[i * 7 + 5] = (ins[8 * i + 5] >> 5) | ((ins[8 * i + 6] & 0x3f) << 2);
    outs[i * 7 + 6] = (ins[8 * i + 6] >> 6) | ((ins[8 * i + 7] & 0x7f) << 1);
  }
  return 1;
  
}

int crypto_pkem_enc(unsigned char *c, unsigned char *k, const unsigned char *m, const unsigned char *pk)
{
  poly r, x2, pm;
  unsigned char rm[NTRU_OWCPA_MSGBYTES + 32];
  unsigned char x2_seed[NTRU_SAMPLE_FT_BYTES];
  unsigned char pack_x2[NTRU_PACK_TRINARY_BYTES];
  unsigned char r_seed[NTRU_SAMPLE_IID_BYTES];
  unsigned char sigma[64];
  
  

  poly_S3_frombytes(&pm, m);

  randombytes(x2_seed, NTRU_SAMPLE_FT_BYTES);

  //sample_rm(&r, &m, rm_seed);

  sample_fixed_type(&x2, x2_seed); // x2 <- phi_2 
  poly_S3_tobytes(pack_x2, &x2);

  crypto_hash_shake256(r_seed, NTRU_SAMPLE_IID_BYTES, pack_x2, NTRU_PACK_TRINARY_BYTES);
  sample_iid(&r, r_seed); // r<- G(x2)

  for(int i=0; i < NTRU_N; i++)
    r.coeffs[i] = mod3(r.coeffs[i] + pm.coeffs[i]); // we use m as input 'm' here

  poly_S3_tobytes(rm, &r);
  poly_S3_tobytes(rm+NTRU_PACK_TRINARY_BYTES, &x2);

  crypto_hash_sha3256(rm+NTRU_PACK_TRINARY_BYTES+NTRU_PACK_TRINARY_BYTES, pk, NTRU_PUBLICKEYBYTES); 
  // rm = r \Vert m \Vert SHA3256(pk) //this r is already r + pm

  crypto_hash_sha3512(sigma, rm, NTRU_OWCPA_MSGBYTES + 32);
  memcpy(c + NTRU_OWCPA_BYTES, sigma, 32);
  memcpy(k , sigma + 32, 32);
//   crypto_hash_sha3256(c + NTRU_OWCPA_BYTES, rm, NTRU_OWCPA_MSGBYTES + 32);
  poly_Z3_to_Zq(&r);
  owcpa_enc(c, &r, &x2, pk);// m<- DPKE.Encrypt(h=pk,(r,m))

  return 0;
}

int crypto_pkem_dec(unsigned char *m, unsigned char *k, const unsigned char *c, const unsigned char *sk)
{
  poly r,x2, pm;
  int i, fail;
  unsigned char rx2[NTRU_OWCPA_MSGBYTES + 32];
  unsigned char buf[NTRU_PRFKEYBYTES+NTRU_CIPHERTEXTBYTES];
  unsigned char sigma[64];

  fail = owcpa_dec(rx2, c, sk);
  /* If fail = 0 then c = Enc(h, rm). There is no need to re-encapsulate. */
  /* See comment in owcpa_dec for details.                                */

  poly_S3_frombytes(&r,  rx2);
  poly_S3_frombytes(&x2, rx2 + NTRU_PACK_TRINARY_BYTES);

  unsigned char r_seed[NTRU_SAMPLE_IID_BYTES];

  crypto_hash_shake256(r_seed, NTRU_SAMPLE_IID_BYTES, rx2 + NTRU_PACK_TRINARY_BYTES, NTRU_PACK_TRINARY_BYTES); // 

  // G(m) = sample_iid(SHA256(m))


  poly tmp_r;

  sample_iid(&pm, r_seed); // r <- sample_iid(r_seed)

  for (int i = 0; i < NTRU_N; i++) 
    r.coeffs[i] = mod3(3+r.coeffs[i] - pm.coeffs[i]); 

  poly_S3_tobytes(m, &r);

  memcpy(rx2 + NTRU_OWCPA_MSGBYTES,sk + NTRU_OWCPA_SECRETKEYBYTES,32);
  
//   crypto_hash_sha3256(sigma,rx2,NTRU_OWCPA_MSGBYTES+32);

  crypto_hash_sha3512(sigma,rx2,NTRU_OWCPA_MSGBYTES+32);
  memcpy(k, sigma + 32, 32);  


  fail |= memcmp(sigma, c+NTRU_OWCPA_BYTES,32);

  return fail;
}


int crypto_hybrid_enc(unsigned char *c, const unsigned char *m, const int l, const unsigned char *pk)
{
  unsigned char k[32];
  unsigned char embedded_m[NTRU_PACK_TRINARY_BYTES];
  int clen=0;
  memset(embedded_m, 0, NTRU_PACK_TRINARY_BYTES);

  if ( l<= OAEP_EMBEDDED_PT_BYTES)
  {
    /* code */
    b128encode(embedded_m,m,OAEP_EMBEDDED_PT_BYTES);


    
    /** TODO: Implement with plain oaep-pke*/
  } else {
    
    b128encode(embedded_m,m,OAEP_EMBEDDED_PT_BYTES);

    /** TODO: change k into 128 bits*/


    crypto_pkem_enc(c,k,embedded_m,pk);


    

    /*Temporarily choosing randomly for evaluation*/
    randombytes(c + NTRU_CIPHERTEXTBYTES, GCM_IV_BYTES);
    aes_gcm_encrypt(c + NTRU_CIPHERTEXTBYTES + GCM_IV_BYTES + 16, c + NTRU_CIPHERTEXTBYTES + GCM_IV_BYTES, &clen, k, c + NTRU_CIPHERTEXTBYTES, m+OAEP_EMBEDDED_PT_BYTES, l-OAEP_EMBEDDED_PT_BYTES);
  
  }
  

}


int crypto_hybrid_dec(unsigned char *m, const unsigned char *c, const int cl, const unsigned char *sk)
{
  unsigned char k[32];

  unsigned char embedded_m[NTRU_PACK_TRINARY_BYTES];
  int symmlen=0;
  int fail=0;
  memset(embedded_m, 0, NTRU_PACK_TRINARY_BYTES);

  if (cl == NTRU_CIPHERTEXTBYTES)
  {
    /** TODO: */
  } else {
    // assert(cl > NTRU_CIPHERTEXTBYTES + GCM_IV_BYTES + 16);
    fail = crypto_pkem_dec(embedded_m,k,c,sk);
    b128decode(m,embedded_m,OAEP_EMBEDDED_BYTES);

    if (fail!=0)
    {
      return 0;
    }
    else return aes_gcm_decrypt(m + OAEP_EMBEDDED_PT_BYTES, &symmlen, k, c + NTRU_CIPHERTEXTBYTES + GCM_IV_BYTES + 16, cl - NTRU_CIPHERTEXTBYTES - GCM_IV_BYTES - 16, c + NTRU_CIPHERTEXTBYTES + GCM_IV_BYTES, c + NTRU_CIPHERTEXTBYTES);
  }
}
