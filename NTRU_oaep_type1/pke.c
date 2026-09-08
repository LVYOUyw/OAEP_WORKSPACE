#include <stddef.h>
#include <stdint.h>
#include "pke.h"
#include "params.h"
#include "symmetric.h"
#include "poly.h"
#include "verify.h"
#include "fips202.h"
#include "randombytes.h"

#include <stdio.h>

/*************************************************
* Name:        crypto_encrypt_keypair
*
* Description: Generates public and private key for NTRU+PKE
*
* Arguments:   - unsigned char *pk: pointer to output public key
*                (an already allocated array of CRYPTO_PUBLICKEYBYTES bytes)
*              - unsigned char *sk: pointer to output private key
*                (an already allocated array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_encrypt_keypair(unsigned char *pk, unsigned char *sk)
{
	uint8_t buf[NTRUOAEP_N / 4];
	
	poly f, finv;
	poly g;
	poly h, hinv;

	do {
		randombytes(buf, 32);
		shake256(buf, NTRUOAEP_N / 4, buf, 32);
		
		poly_cbd1(&f, buf);
		poly_triple(&f, &f);
		f.coeffs[0] += 1;
		poly_ntt(&f, &f);
	} while(poly_baseinv(&finv, &f));

	do {
		randombytes(buf, 32);
		shake256(buf, NTRUOAEP_N / 4, buf, 32);

		poly_cbd1(&g, buf); 
		poly_triple(&g, &g);
		poly_ntt(&g, &g);
		poly_basemul(&h, &g, &finv);
	} while(poly_baseinv(&hinv, &h));


    //pk
    poly_tobytes(pk, &h);

    //sk
    poly_tobytes(sk, &f);
    poly_tobytes(sk + NTRUOAEP_POLYBYTES, &hinv);   
    hash_f(sk + 2 * NTRUOAEP_POLYBYTES, pk); 

	
	return 0;
}

/*************************************************
* Name:        crypto_encrypt
*
* Description: Generates ciphertext for given plaintext and public key
*
* Arguments:   - unsigned char *c: pointer to output ciphertext
*                (an already allocated array of CRYPTO_CIPHERTEXTBYTES bytes)
*              - unsigned long long *clen: pointer to byte length of output ciphertext
*              - const unsigned char *m: pointer to input plaintext
*                (an already allocated array of CRYPTO_MAXPLAINTEXT bytes)
*              - unsigned long long mlen: byte length of input plaintext
*              - const unsigned char *pk: pointer to input public key
*                (an already allocated array of CRYPTO_PUBLICKEYBYTES bytes)
*
* Returns 0 (success) or 1 (failure)
**************************************************/
int crypto_encrypt(unsigned char *c,
                   unsigned long long *clen,
                   const unsigned char *m,
                   int mlen,
                   const unsigned char *pk)
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

    for (int i = NTRUOAEP_POLYBYTES; i < NTRUOAEP_CIPHERTEXTBYTES; i++) c[i] = sigma[i - NTRUOAEP_POLYBYTES];


    *clen = NTRUOAEP_CIPHERTEXTBYTES;

    return fail;
}
/*************************************************
* Name:        crypto_encrypt_open
*
* Description: Decrypts given ciphertext and private key
*
* Arguments:   - unsigned char *m: pointer to output plaintext
*                (an already allocated array of CRYPTO_MAXPLAINTEXT bytes)
*              - unsigned long long *mlen: pointer to byte length of output plaintext
*              - const unsigned char *c: pointer to input ciphertext
*                (an already allocated array of CRYPTO_CIPHERTEXTBYTES bytes)
*              - unsigned long long clen: byte length of input ciphertext
*              - const unsigned char *sk: pointer to input private key
*                (an already allocated array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0 (success) or 1 (failure)
*
* On failure, m will contain zeros.
**************************************************/
int crypto_encrypt_open(unsigned char *m,
                        const unsigned char *c,
                        const unsigned char *sk)
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

    for (int i = NTRUOAEP_POLYBYTES; i < NTRUOAEP_CIPHERTEXTBYTES; i++) {
       // printf("%u %u\n", c[i], sigma[i - NTRUOAEP_POLYBYTES]);
        fail |= (c[i] ^ sigma[i - NTRUOAEP_POLYBYTES]);
    }
 
    return fail;
}



int crypto_encap(unsigned char *c,
    unsigned long long *clen,
    unsigned char *ss,
    const unsigned char *pk)
{

uint8_t msg[NTRUOAEP_N / 4] = {0};
uint8_t randomness[NTRUOAEP_N / 4] = {0};
uint8_t sigma[KeyConfirmation_BYTES]; 
uint8_t buff[NTRUOAEP_SYMBYTES + NTRUOAEP_N / 2];
int8_t fail = 0;

poly p_c, p_h, p_s, p_t;

randombytes(randomness, NTRUOAEP_N / 4);


// for (int i = 0; i < mlen; i++) msg[i] = m[i];
randombytes(msg, NTRUOAEP_N / 4);
for (int i = 0; i < NTRUOAEP_SSBYTES; i++) ss[i] = msg[i];

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


for (int i = NTRUOAEP_POLYBYTES; i < NTRUOAEP_CIPHERTEXTBYTES; i++) c[i] = sigma[i - NTRUOAEP_POLYBYTES];

*clen = NTRUOAEP_CIPHERTEXTBYTES;

return (int)fail;
}


int crypto_encap_open(unsigned char *ss,
    const unsigned char *c,
    const unsigned char *sk)
{
uint8_t r[NTRUOAEP_N / 4];
uint8_t buff[NTRUOAEP_SYMBYTES + NTRUOAEP_N / 2];
uint8_t sigma[KeyConfirmation_BYTES];
uint8_t ssbuf[NTRUOAEP_N / 8];
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

fail |= poly_sotp_inv(ssbuf, &p_s, r);  


for (int i = 0; i < NTRUOAEP_SSBYTES; i++) ss[i] = ssbuf[i];
for (int i = 0; i < NTRUOAEP_SYMBYTES; i++) buff[i] = sk[NTRUOAEP_POLYBYTES * 2 + i];

short_poly_to_bytes(buff + NTRUOAEP_SYMBYTES, &p_s);

hash_h_prime(sigma, buff);

for (int i = NTRUOAEP_POLYBYTES; i < NTRUOAEP_CIPHERTEXTBYTES; i++) {
// printf("%u %u\n", c[i], sigma[i - NTRUOAEP_POLYBYTES]);
fail |= (c[i] ^ sigma[i - NTRUOAEP_POLYBYTES]);
}

return fail;
}