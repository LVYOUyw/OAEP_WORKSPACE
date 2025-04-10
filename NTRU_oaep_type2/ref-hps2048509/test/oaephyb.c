

#include "../api.h"
#include "../kem.h"
#include "../randombytes.h"
#include "../poly.h"
#include "../sample.h"
#include "../crypto_hash_sha3256.h"
#include "../aes128gcm.h"
#include "../oaephybrid.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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

    const int m_size = 1000;

    unsigned char* pk = (unsigned char*) malloc(CRYPTO_PUBLICKEYBYTES);
    unsigned char* sk = (unsigned char*) malloc(CRYPTO_OAEP_SKBYTES);
    unsigned char* c = (unsigned char*) malloc(CRYPRO_OAEP_CTBYTES + m_size + GCM_IV_BYTES + GCM_TAG_BYTES);
    int fail_count = 0;
    unsigned char* m = (unsigned char*) malloc(m_size);
    unsigned char* decm = (unsigned char*) malloc(m_size);
    
    for (size_t T = 0; T < CORRECTNESS_LOOP; T++)
    {
        // randombytes(m, NTRU_PACK_TRINARY_BYTES);
        // poly pm;
        // unsigned char m_seed[NTRU_SAMPLE_IID_BYTES];
        // crypto_hash_shake256(m_seed, NTRU_SAMPLE_IID_BYTES, m, NTRU_PACK_TRINARY_BYTES); //   
        // sample_iid(&pm, m_seed); 
        // poly_S3_tobytes(m,&pm);

        randombytes(m, m_size);
        
    
        crypto_kem_keypair(pk,sk);
        // crypto_kem_enc(c,m,pk);
        crypto_hybrid_enc(c,m,m_size,pk);
        int fail = crypto_hybrid_dec(decm,c, CRYPRO_OAEP_CTBYTES + m_size + GCM_IV_BYTES + GCM_TAG_BYTES - OAEP_EMBEDDED_PT_BYTES, sk)==1?0:1;
        
        fail |= (int)(memcmp(m,decm,m_size));
        fail_count += fail?1:0;

    }
    

    free(pk);free(sk);
    free(c);free(m);free(decm);
    printf("====== ERROR COUNT : % 6d ======\n",fail_count);
    return fail_count;
}


int test_speed()
{

}

int main()
{   
    test_correctness();
    test_speed();
}