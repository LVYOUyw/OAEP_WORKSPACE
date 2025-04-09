

#include "../api.h"
#include "../kem.h"
#include "../randombytes.h"
#include "../poly.h"
#include "../sample.h"
#include "../crypto_hash_sha3256.h"
#include "../aes128gcm.h"
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

int test_aes128gcm()
{
    unsigned char pt[1000];
    randombytes(pt, 500);
}

int test_correctness()
{

}

int test_speed()
{

}

int main()
{   
    test_correctness();
    test_speed();
}