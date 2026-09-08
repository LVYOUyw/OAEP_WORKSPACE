#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "randombytes.h"
#include "poly.h"
#include "oaephybrid.h"
#include "pke.h"
#include "aes128gcm.h"

#define CRYPTO_SECRETKEYBYTES  NTRUOAEP_SECRETKEYBYTES
#define CRYPTO_PUBLICKEYBYTES  NTRUOAEP_PUBLICKEYBYTES
#define CRYPTO_CIPHERTEXTBYTES NTRUOAEP_CIPHERTEXTBYTES
#define CRYPTO_MAXPLAINTEXT    NTRUOAEP_MAXPLAINTEXT
#define CRYPTO_BYTES           NTRUOAEP_SYMBYTES

#define CRYPTO_ALGNAME "NTRUOAEP648"

#define TEST_LOOP1 1000
#define TEST_LOOP2 10000

#define TEST_MSIZE 128

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
    unsigned long long kcycles=0, ecycles=0, dcycles=0;
    unsigned long long cycles1, cycles2;

	unsigned char pk[CRYPTO_PUBLICKEYBYTES];
	unsigned char sk[CRYPTO_SECRETKEYBYTES];
	unsigned char ct[TEST_MSIZE + CRYPTO_CIPHERTEXTBYTES + 128];
	unsigned char m[TEST_MSIZE + 10];
	unsigned char ss[TEST_MSIZE + 10];
	unsigned char dm[TEST_MSIZE + 10];
	//unsigned long long mlen = 0;
	//unsigned long long dmlen = 0;
	unsigned long long clen = 0;
    int fail;

    for (size_t T = 0; T < TEST_LOOP1; T++)
    {
        cycles1 = cpucycles();
        crypto_encrypt_keypair(pk,sk);
        cycles2 = cpucycles();
        kcycles += cycles2-cycles1;
    }
    printf("  KEYGEN runs in ................. %8lld cycles", kcycles/TEST_LOOP1);
	printf("\n"); 
	randombytes(m, TEST_MSIZE);
    for (size_t T = 0; T < TEST_LOOP2; T++)
    {
        //crypto_encrypt_keypair(pk,sk);

        cycles1 = cpucycles();
        crypto_hybrid_enc(ct,m,TEST_MSIZE,pk);
        cycles2 = cpucycles();
        ecycles += cycles2-cycles1;

        cycles1 = cpucycles();
        fail = crypto_hybrid_dec(dm,ct, NTRUOAEP_PKEM_CIPHERTEXTBYTES + GCM_IV_BYTES + GCM_TAG_BYTES + TEST_MSIZE - NTRUOAEP_MAXPLAINTEXT, sk);
        cycles2 = cpucycles();
        dcycles += cycles2-cycles1;
    }

	printf(" HYBRID ENC    runs in ................. %8lld cycles", ecycles/TEST_LOOP2);
	printf("\n"); 
	
 	printf(" HYBRID DEC    runs in ................. %8lld cycles", dcycles/TEST_LOOP2);
	printf("\n\n");
	

	ecycles=dcycles=0;
	for (size_t T = 0; T < TEST_LOOP2; T++)
    {
        cycles1 = cpucycles();
        crypto_encap(ct,&clen,ss,pk);
        cycles2 = cpucycles();
        ecycles += cycles2-cycles1;

        cycles1 = cpucycles();
        fail = crypto_encap_open(ss,ct, sk);
        cycles2 = cpucycles();
        dcycles += cycles2-cycles1;
    }

	printf(" KEM ENC    runs in ................. %8lld cycles", ecycles/TEST_LOOP2);
	printf("\n"); 
	
 	printf(" KEM DEC    runs in ................. %8lld cycles", dcycles/TEST_LOOP2);
	printf("\n\n");


}

int main(void)
{
	printf("=================== PARAMETERS ===================\n");
	printf("ALGORITHM_NAME  : %s\n", CRYPTO_ALGNAME);
	printf("PUBLICKEYBYTES  : %d\n", CRYPTO_PUBLICKEYBYTES);
	printf("SECRETKEYBYTES  : %d\n", CRYPTO_SECRETKEYBYTES);
	printf("CIPHERTEXTBYTES : %d\n", CRYPTO_CIPHERTEXTBYTES + GCM_IV_BYTES + GCM_TAG_BYTES + TEST_MSIZE - NTRUOAEP_MAXPLAINTEXT);
	printf("%d %d %d %d %d\n", CRYPTO_CIPHERTEXTBYTES, GCM_IV_BYTES, GCM_TAG_BYTES, TEST_MSIZE, NTRUOAEP_MAXPLAINTEXT);
	printf("\n");

	TEST_PKE();
	TEST_PKE_CLOCK();

	return 0;	
}
