#include "api.h"
#include "cmov.h"
#include "crypto_hash_sha3256.h"
#include "kem.h"
#include "owcpa.h"
#include "params.h"
#include "randombytes.h"
#include "sample.h"
#include <string.h>
#include <stdio.h>

static uint16_t mod3(uint16_t a)
{
  uint16_t r;
  int16_t t, c;

  r = (a >> 8) + (a & 0xff); // r mod 255 == a mod 255
  r = (r >> 4) + (r & 0xf); // r' mod 15 == r mod 15
  r = (r >> 2) + (r & 0x3); // r' mod 3 == r mod 3
  r = (r >> 2) + (r & 0x3); // r' mod 3 == r mod 3

  t = r - 3;
  c = t >> 15;

  return (c&r) ^ (~c&t);
}


// API FUNCTIONS 
int crypto_kem_keypair(unsigned char *pk, unsigned char *sk)
{
  unsigned char seed[NTRU_SAMPLE_FG_BYTES];

  randombytes(seed, NTRU_SAMPLE_FG_BYTES);
  owcpa_keypair(pk, sk, seed);

//  randombytes(sk+NTRU_OWCPA_SECRETKEYBYTES, NTRU_PRFKEYBYTES);

  // Pad H(pk) into sk for decryption use.
  crypto_hash_sha3256(sk+NTRU_OWCPA_SECRETKEYBYTES, pk, NTRU_PUBLICKEYBYTES);

  return 0;
}

int crypto_kem_enc(unsigned char *c, unsigned char *k, const unsigned char *pk)
{
  poly r, m;
  unsigned char rm[NTRU_OWCPA_MSGBYTES];
  unsigned char rm_seed[NTRU_SAMPLE_RM_BYTES];

  randombytes(rm_seed, NTRU_SAMPLE_RM_BYTES);

  sample_rm(&r, &m, rm_seed);

  poly_S3_tobytes(rm, &r);
  poly_S3_tobytes(rm+NTRU_PACK_TRINARY_BYTES, &m);
  crypto_hash_sha3256(k, rm, NTRU_OWCPA_MSGBYTES);

  poly_Z3_to_Zq(&r);
  owcpa_enc(c, &r, &m, pk);

  return 0;
}

int crypto_kem_dec(unsigned char *k, const unsigned char *c, const unsigned char *sk)
{
  int i, fail;
  unsigned char rm[NTRU_OWCPA_MSGBYTES];
  unsigned char buf[NTRU_PRFKEYBYTES+NTRU_CIPHERTEXTBYTES];

  fail = owcpa_dec(rm, c, sk);
  /* If fail = 0 then c = Enc(h, rm). There is no need to re-encapsulate. */
  /* See comment in owcpa_dec for details.                                */

  crypto_hash_sha3256(k, rm, NTRU_OWCPA_MSGBYTES);

  /* shake(secret PRF key || input ciphertext) */
  for(i=0;i<NTRU_PRFKEYBYTES;i++)
    buf[i] = sk[i+NTRU_OWCPA_SECRETKEYBYTES];
  for(i=0;i<NTRU_CIPHERTEXTBYTES;i++)
    buf[NTRU_PRFKEYBYTES + i] = c[i];
  crypto_hash_sha3256(rm, buf, NTRU_PRFKEYBYTES+NTRU_CIPHERTEXTBYTES);

  cmov(k, rm, NTRU_SHAREDKEYBYTES, (unsigned char) fail);

  return 0;
}


int crypto_rkem_enc(unsigned char *c, unsigned char *k, const unsigned char *m, const unsigned char *pk)
{
  poly r, x2, pm;
  unsigned char rm[NTRU_OWCPA_MSGBYTES + 32];
  unsigned char x2_seed[NTRU_SAMPLE_FT_BYTES];
  unsigned char pack_x2[NTRU_PACK_TRINARY_BYTES];
  unsigned char r_seed[NTRU_SAMPLE_IID_BYTES];

  poly_S3_fromMessage(&pm, m);

  randombytes(x2_seed, NTRU_SAMPLE_FT_BYTES);


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

  crypto_hash_sha3256(c + NTRU_OWCPA_BYTES, rm, NTRU_OWCPA_MSGBYTES + 32);

  crypto_hash_sha3256(k, rm, NTRU_OWCPA_MSGBYTES + 32);
  poly_Z3_to_Zq(&r);
  owcpa_enc(c, &r, &x2, pk);

  return 0;
}

int crypto_rkem_dec(unsigned char *k, unsigned char *m, const unsigned char *c, const unsigned char *sk)
{
  poly r,x2, pm;
  int fail = 0;
  unsigned char rx2[NTRU_OWCPA_MSGBYTES + 32];
  unsigned char sigma[32];

  fail = owcpa_dec(rx2, c, sk);
  /* If fail = 0 then c = Enc(h, rm). There is no need to re-encapsulate. */
  /* See comment in owcpa_dec for details.                                */


  poly_S3_frombytes(&r,  rx2);
  poly_S3_frombytes(&x2, rx2 + NTRU_PACK_TRINARY_BYTES);

  unsigned char r_seed[NTRU_SAMPLE_IID_BYTES];

  crypto_hash_shake256(r_seed, NTRU_SAMPLE_IID_BYTES, rx2 + NTRU_PACK_TRINARY_BYTES, NTRU_PACK_TRINARY_BYTES); // 

  // G(m) = sample_iid(SHA256(m))



  sample_iid(&pm, r_seed); // r <- sample_iid(r_seed)

  for (int i = 0; i < NTRU_N; i++) 
    r.coeffs[i] = mod3(3+r.coeffs[i] - pm.coeffs[i]); 


  poly_S3_toMessage(m, &r);


  memcpy(rx2 + NTRU_OWCPA_MSGBYTES,sk + NTRU_OWCPA_SECRETKEYBYTES,32);
  
  crypto_hash_sha3256(sigma,rx2,NTRU_OWCPA_MSGBYTES + 32);

  crypto_hash_sha3256(k, rx2, NTRU_OWCPA_MSGBYTES + 32);

  fail |= memcmp(sigma, c+NTRU_OWCPA_BYTES, 32);


  return fail;
}
