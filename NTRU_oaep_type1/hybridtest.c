#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "api.h"
#include "randombytes.h"
#include "poly.h"
#include "oaephybrid.h"
#include "aes128gcm.h"

#define TEST_LOOP1 1
#define TEST_LOOP2 100000

#define TEST_MSIZE 1000

static inline uint64_t cpucycles(void) 
{
	uint64_t result;
	
	__asm__ volatile ("rdtsc; shlq $32,%%rdx; orq %%rdx,%%rax"
	: "=a" (result) : : "%rdx");
	
	return result;
}

static void TEST_PKE()
{
	unsigned char pk[CRYPTO_PUBLICKEYBYTES];
	unsigned char sk[CRYPTO_SECRETKEYBYTES];
	unsigned char ct[TEST_MSIZE + CRYPTO_CIPHERTEXTBYTES + 128];
	unsigned char m[TEST_MSIZE];
	unsigned char dm[TEST_MSIZE];
	//unsigned long long mlen = 0;
	//unsigned long long dmlen = 0;
	unsigned long long clen = 0;
	int cnt = 0;

	printf("================ CORRECTNESS TEST ================\n");

	//Generate public and secret key
	crypto_encrypt_keypair(pk, sk);

	//Encrypt and Decrypt message
	for (int i = 0; i < TEST_LOOP1; i++)
	{		
		randombytes(m, TEST_MSIZE);


		// crypto_encrypt(ct, &clen, m, CRYPTO_MAXPLAINTEXT, pk);
        crypto_hybrid_enc(ct,m,TEST_MSIZE,pk);
    

		int fail = crypto_hybrid_dec(dm,ct, NTRUOAEP_PKEM_CIPHERTEXTBYTES + GCM_IV_BYTES + GCM_TAG_BYTES + TEST_MSIZE - NTRUOAEP_MAXPLAINTEXT, sk);

		if(memcmp(m, dm, TEST_MSIZE) != 0 || fail)
		{
            printf("%d!\n",fail);
            for (size_t i = 0; i < TEST_MSIZE; i++)
            {
                printf("(%02x||%02x)",m[i],dm[i]);
            }
            puts("");
            
			cnt++;
			continue;
		}		
	}
	printf("count: %d\n\n", cnt);
}

static void TEST_PKE_CLOCK()
{

}

int main(void)
{
	printf("=================== PARAMETERS ===================\n");
	printf("ALGORITHM_NAME  : %s\n", CRYPTO_ALGNAME);
	printf("PUBLICKEYBYTES  : %d\n", CRYPTO_PUBLICKEYBYTES);
	printf("SECRETKEYBYTES  : %d\n", CRYPTO_SECRETKEYBYTES);
	printf("CIPHERTEXTBYTES : %d\n", CRYPTO_CIPHERTEXTBYTES);
	printf("\n");

	TEST_PKE();
	TEST_PKE_CLOCK();

	return 0;	
}
