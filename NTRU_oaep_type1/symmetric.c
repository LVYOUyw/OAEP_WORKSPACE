#include "sha2.h"
#include "symmetric.h"
#include "fips202.h"

void hash_f(uint8_t *buf, const uint8_t *msg)
{
	uint8_t data[1 + NTRUOAEP_PUBLICKEYBYTES] = {0x0};

	for (int i = 0; i < NTRUOAEP_PUBLICKEYBYTES; i++)
	{
		data[i+1] = msg[i];
	}
	
	sha256(buf, data, NTRUOAEP_PUBLICKEYBYTES + 1);
}

void hash_g(uint8_t *buf, const uint8_t *msg)
{
	uint8_t data[1 + NTRUOAEP_N / 4] = {0x1};

	for (int i = 0; i < NTRUOAEP_N / 4; i++)
	{
		data[i+1] = msg[i];
	}
	
	shake256(buf, NTRUOAEP_N / 4, data, NTRUOAEP_N / 4 + 1);
}

void hash_h(uint8_t *buf, const uint8_t *msg)
{
	uint8_t data[1 + NTRUOAEP_N / 4] = {0x3};

	for (int i = 0; i < NTRUOAEP_N / 4; i++)
	{
		data[i+1] = msg[i];
	}

	shake256(buf, NTRUOAEP_N / 8, data, NTRUOAEP_N / 4 + 1);
}

void hash_h_prime(uint8_t *buf, const uint8_t *msg) 
{
	uint8_t data[1 + NTRUOAEP_N / 2 + NTRUOAEP_SYMBYTES] = {0x5};

	for (int i = 0; i < NTRUOAEP_N / 2 + NTRUOAEP_SYMBYTES; i++) 
	{
		data[i+1] = msg[i];
	}

	shake256(buf, KeyConfirmation_BYTES, data, 1 + NTRUOAEP_N / 2 + NTRUOAEP_SYMBYTES);
}


