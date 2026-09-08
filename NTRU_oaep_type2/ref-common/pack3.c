#include "poly.h"
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

void poly_S3_tobytes(unsigned char msg[NTRU_PACK_TRINARY_BYTES], const poly *a)
{
  int i;
  unsigned char c;
#if NTRU_PACK_DEG > (NTRU_PACK_DEG / 5) * 5  // if 5 does not divide NTRU_N-1
  int j;
#endif

  for(i=0; i<NTRU_PACK_DEG/5; i++)
  {
    c =        a->coeffs[5*i+4] & 255;
    c = (3*c + a->coeffs[5*i+3]) & 255;
    c = (3*c + a->coeffs[5*i+2]) & 255;
    c = (3*c + a->coeffs[5*i+1]) & 255;
    c = (3*c + a->coeffs[5*i+0]) & 255;
    msg[i] = c;
  }
#if NTRU_PACK_DEG > (NTRU_PACK_DEG / 5) * 5  // if 5 does not divide NTRU_N-1
  i = NTRU_PACK_DEG/5;
  c = 0;
  for(j = NTRU_PACK_DEG - (5*i) - 1; j>=0; j--)
    c = (3*c + a->coeffs[5*i+j]) & 255;
  msg[i] = c;
#endif
}

void poly_S3_frombytes(poly *r, const unsigned char msg[NTRU_PACK_TRINARY_BYTES])
{
  int i;
  unsigned char c;
#if NTRU_PACK_DEG > (NTRU_PACK_DEG / 5) * 5  // if 5 does not divide NTRU_N-1
  int j;
#endif

  for(i=0; i<NTRU_PACK_DEG/5; i++)
  {
    c = msg[i];
    r->coeffs[5*i+0] = c;
    r->coeffs[5*i+1] = c * 171 >> 9;  // this is division by 3
    r->coeffs[5*i+2] = c * 57 >> 9;  // division by 3^2
    r->coeffs[5*i+3] = c * 19 >> 9;  // division by 3^3
    r->coeffs[5*i+4] = c * 203 >> 14;  // etc.
  }
#if NTRU_PACK_DEG > (NTRU_PACK_DEG / 5) * 5  // if 5 does not divide NTRU_N-1
  i = NTRU_PACK_DEG/5;
  c = msg[i];
  for(j=0; (5*i+j)<NTRU_PACK_DEG; j++)
  {
    r->coeffs[5*i+j] = c;
    c = c * 171 >> 9;
  }
#endif
  r->coeffs[NTRU_N-1] = 0;
  poly_mod_3_Phi_n(r);
}


void poly_S3_fromMessage(poly *r, const unsigned char msg[NTRU_MSG_BYTES]) 
{
  int total_bits = NTRU_MSG_BYTES * 8;
  int out_index = 0; 
  int bit_pos = 0;

  while (bit_pos < total_bits) {
    uint16_t val = 0;
    for (int i = 0; i < 11; i++) {
      int byte_idx = (bit_pos + i) / 8;
      int bit_in_byte = 7 - (bit_pos + i) % 8;
      if ((msg[byte_idx] >> bit_in_byte) & 1) 
        val |= (1 << i);      
    }


    for (int i = 0; i < 7; i++) {
      r->coeffs[out_index + i] = mod3(val);
      val /= 3;
    }

    bit_pos += 11;
    out_index += 7;
  }

  for (int i = out_index; i < NTRU_N; i++) r->coeffs[i] = 0;

}

void poly_S3_toMessage(unsigned char msg[NTRU_MSG_BYTES], const poly *a) 
{
  int total_element = (NTRU_N / 7) * 7;   
  int bit_pos = 0;
  int cur_pos = 0;


  for (int i = 0; i < NTRU_MSG_BYTES; i++) msg[i] = 0;

  while (cur_pos < total_element) {
    uint16_t val = 0;
    for (int i = 6; i >= 0; i--) 
      val = val * 3 + a->coeffs[cur_pos + i];

    for (int i = 0; i < 11; i++) {
      int byte_idx = (bit_pos + i) / 8;
      int bit_in_byte = 7 - (bit_pos + i) % 8;
      if ((val >> i) & 1) msg[byte_idx] |= (1 << bit_in_byte);
    }

    bit_pos += 11;
    cur_pos += 7;
  }

}



















