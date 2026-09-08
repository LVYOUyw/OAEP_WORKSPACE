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
    unsigned char* pk = (unsigned char*) malloc(NTRU_PUBLICKEYBYTES);
    unsigned char* sk = (unsigned char*) malloc(NTRU_SECRETKEYBYTES);
    unsigned char* c = (unsigned char*) malloc(NTRU_CIPHERTEXTBYTES + 32);
    int fail_count = 0;
    unsigned char* m = (unsigned char*) malloc(NTRU_MSG_BYTES);
    unsigned char* decm = (unsigned char*) malloc(NTRU_MSG_BYTES);
    unsigned char* k = (unsigned char*) malloc(NTRU_SHAREDKEYBYTES);
    unsigned char* deck = (unsigned char*) malloc(NTRU_SHAREDKEYBYTES);
    
    for (size_t T = 0; T < CORRECTNESS_LOOP; T++)
    {
        randombytes(m, NTRU_MSG_BYTES);       

      //  freopen("1.txt", "w", stdout);
      //  for (int i = 0; i < NTRU_MSG_BYTES; i++) printf("%u\n", m[i]); 
    
        crypto_kem_keypair(pk,sk);
        crypto_rkem_enc(c, k, m, pk);
        int fail = crypto_rkem_dec(deck, decm,c, sk);
        
        fail |= (int)(memcmp(m,decm,NTRU_MSG_BYTES));
        fail_count += fail?1:0;

    }
    

    free(pk);free(sk);
    free(c);free(m);free(decm);
    free(k);free(deck);
    printf("====== ERROR COUNT : % 6d ======\n",fail_count);
    return fail_count;
}

int test_speed()
{
    unsigned long long kcycles=0, ecycles=0, dcycles=0;
    unsigned long long cycles1, cycles2;

    unsigned char* pk = (unsigned char*) malloc(CRYPTO_PUBLICKEYBYTES);
    unsigned char* sk = (unsigned char*) malloc(NTRU_SECRETKEYBYTES);
    unsigned char* c = (unsigned char*) malloc(NTRU_CIPHERTEXTBYTES + 32);
    int rv = 0;
    unsigned char* m = (unsigned char*) malloc(NTRU_MSG_BYTES);
    unsigned char* decm = (unsigned char*) malloc(NTRU_MSG_BYTES);
    unsigned char* k = (unsigned char*) malloc(NTRU_SHAREDKEYBYTES);
    unsigned char* deck = (unsigned char*) malloc(NTRU_SHAREDKEYBYTES);
    
    randombytes(m, NTRU_MSG_BYTES);  
    
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
        crypto_rkem_enc(c,k,m,pk);
        cycles2 = cpucycles();
        ecycles += cycles2-cycles1;

        cycles1 = cpucycles();
        crypto_rkem_dec(deck,decm,c,sk);
        cycles2 = cpucycles();
        dcycles += cycles2-cycles1;
    }


	printf("  ENC    runs in ................. %8lld cycles", ecycles/SPEED_LOOP);
	printf("\n"); 
	
 	printf("  DEC    runs in ................. %8lld cycles", dcycles/SPEED_LOOP);
	printf("\n\n");

    free(pk);free(sk);
    free(c);free(m);free(decm);free(k);free(deck);
}

int main()
{   
    printf("=================== PARAMETERS ===================\n");
    printf("PUBLICKEYBYTES  : %d\n", CRYPTO_PUBLICKEYBYTES);
    printf("SECRETKEYBYTES  : %d\n", CRYPTO_SECRETKEYBYTES);
    printf("CIPHERTEXTBYTES : %d\n", CRYPTO_CIPHERTEXTBYTES + 32);
    test_correctness();
    test_speed();
}