

#include "../api.h"
#include "../kem.h"
#include "../randombytes.h"
#include "../poly.h"
#include "../sample.h"
#include "../crypto_hash_sha3256.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/crypto.h>

#define CORRECTNESS_LOOP 1000
#define SPEED_LOOP 1000




static inline uint64_t cpucycles(void) 
{
	uint64_t result;
	
	__asm__ volatile ("rdtsc; shlq $32,%%rdx; orq %%rdx,%%rax"
	: "=a" (result) : : "%rdx");
	
	return result;
}


int test_correctness()
{
    unsigned char* pk = (unsigned char*) malloc(CRYPTO_PUBLICKEYBYTES);
    unsigned char* sk = (unsigned char*) malloc(CRYPTO_OAEP_SKBYTES);
    unsigned char* c = (unsigned char*) malloc(CRYPRO_OAEP_CTBYTES);
    int fail_count = 0;
    unsigned char* m = (unsigned char*) malloc(NTRU_PACK_TRINARY_BYTES);
    unsigned char* decm = (unsigned char*) malloc(NTRU_PACK_TRINARY_BYTES);
    
    for (size_t T = 0; T < CORRECTNESS_LOOP; T++)
    {
        randombytes(m, NTRU_PACK_TRINARY_BYTES);
        poly pm;
        unsigned char m_seed[NTRU_SAMPLE_IID_BYTES];
        crypto_hash_shake256(m_seed, NTRU_SAMPLE_IID_BYTES, m, NTRU_PACK_TRINARY_BYTES); //   
        sample_iid(&pm, m_seed); 
        poly_S3_tobytes(m,&pm);
        
    
        crypto_kem_keypair(pk,sk);
        crypto_kem_enc(c,m,pk);
        int fail = crypto_kem_dec(decm,c,sk);
        
        fail |= (int)(memcmp(m,decm,NTRU_PACK_TRINARY_BYTES));
        fail_count += fail?1:0;

    }
    

    free(pk);free(sk);
    free(c);free(m);free(decm);
    printf("====== ERROR COUNT : % 6d ======\n",fail_count);
    return fail_count;
}

int test_speed()
{
    unsigned long long kcycles=0, ecycles=0, dcycles=0;
    unsigned long long cycles1, cycles2;

    unsigned char* pk = (unsigned char*) malloc(CRYPTO_PUBLICKEYBYTES);
    unsigned char* sk = (unsigned char*) malloc(CRYPTO_OAEP_SKBYTES);
    unsigned char* c = (unsigned char*) malloc(CRYPRO_OAEP_CTBYTES);
    int rv = 0;
    unsigned char* m = (unsigned char*) malloc(NTRU_PACK_TRINARY_BYTES);
    unsigned char* decm = (unsigned char*) malloc(NTRU_PACK_TRINARY_BYTES);
    
    randombytes(m, NTRU_PACK_TRINARY_BYTES);
    poly pm;
    unsigned char m_seed[NTRU_SAMPLE_IID_BYTES];
    crypto_hash_shake256(m_seed, NTRU_SAMPLE_IID_BYTES, m, NTRU_PACK_TRINARY_BYTES); //   
    sample_iid(&pm, m_seed); 
    poly_S3_tobytes(m,&pm);
    
    for (size_t T = 0; T < SPEED_LOOP; T++)
    {
        cycles1 = cpucycles();
        crypto_kem_keypair(pk,sk);
        cycles2 = cpucycles();
        kcycles += cycles2-cycles1;
    }
    printf("  KEYGEN runs in ................. %8lld cycles", kcycles/SPEED_LOOP);
	printf("\n"); 

    for (size_t T = 0; T < SPEED_LOOP; T++)
    {
        crypto_kem_keypair(pk,sk);

        cycles1 = cpucycles();
        crypto_kem_enc(c,m,pk);
        cycles2 = cpucycles();
        ecycles += cycles2-cycles1;

        cycles1 = cpucycles();
        crypto_kem_dec(decm,c,sk);
        cycles2 = cpucycles();
        dcycles += cycles2-cycles1;
    }

    crypto_kem_enc(c,m,pk);

	printf("  ENC    runs in ................. %8lld cycles", ecycles/SPEED_LOOP);
	printf("\n"); 
	
 	printf("  DEC    runs in ................. %8lld cycles", dcycles/SPEED_LOOP);
	printf("\n\n");

    free(pk);free(sk);
    free(c);free(m);free(decm);
}

int main()
{   
    test_correctness();
    test_speed();
}