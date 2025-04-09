/*
 * Copyright 2012-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Simple AES GCM authenticated encryption with additional data (AEAD)
 * demonstration program.
 */

 #include <stdio.h>
 #include <openssl/err.h>
 #include <openssl/bio.h>
 #include <openssl/evp.h>
 #include <openssl/core_names.h>
 #include <string.h>
 


 /* AES-GCM test data obtained from NIST public test vectors */
 
 /* AES key */
//  static const unsigned char gcm_key[] = {
//      0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66,
//      0x5f, 0x8a, 0xe6, 0xd1, 0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69,
//      0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f
//  };
 
//  /* Unique initialisation vector */
//  static const unsigned char gcm_iv[] = {
//      0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84
//  };
 
//  /* Example plaintext to encrypt */
//  static const unsigned char gcm_pt[] = {
//      0xf5, 0x6e, 0x87, 0x05, 0x5b, 0xc3, 0x2d, 0x0e, 0xeb, 0x31, 0xb2, 0xea,
//      0xcc, 0x2b, 0xf2, 0xa5
//  };
 
//  /*
//   * Example of Additional Authenticated Data (AAD), i.e. unencrypted data
//   * which can be authenticated using the generated Tag value.
//   */
//  static const unsigned char gcm_aad[] = {
//      0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b, 0xdb, 0x37, 0x0c, 0x43,
//      0x7f, 0xec, 0x78, 0xde
//  };
 
//  /* Expected ciphertext value */
//  static const unsigned char gcm_ct[] = {
//      0xf7, 0x26, 0x44, 0x13, 0xa8, 0x4c, 0x0e, 0x7c, 0xd5, 0x36, 0x86, 0x7e,
//      0xb9, 0xf2, 0x17, 0x36
//  };
 
//  /* Expected AEAD Tag value */
//  static const unsigned char gcm_tag[] = {
//      0x67, 0xba, 0x05, 0x10, 0x26, 0x2a, 0xe4, 0x87, 0xd7, 0x37, 0xee, 0x62,
//      0x98, 0xf7, 0x7e, 0x0c
//  };
 
 /*
  * A library context and property query can be used to select & filter
  * algorithm implementations. If they are NULL then the default library
  * context and properties are used.
  */
 static OSSL_LIB_CTX *libctx = NULL;
 static const char *propq = NULL;
 

 
 static const unsigned char gcm_key[] = {
    0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66,
    0x5f, 0x8a, 0xe6, 0xd1, 0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69,
    0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f
};

static const unsigned char gcm_iv[] = {
    0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84
};

 int main()
 {
    unsigned char pt[1000], ct[2000],ctag[200];
    int clen;
    // randombytes(pt, 500);
    for (size_t i = 0; i < 498; i++)
    {
        pt[i]=rand()%124;
    }
    for (size_t i = 0; i < 500; i++)
    {
        printf("0x%02x,", pt[i]);
    }
    puts("\npt ends");
    aes_gcm_encrypt(ct,ctag,&clen,gcm_key,gcm_iv,12,pt,499);
    for (size_t i = 0; i < clen; i++)
    {
        printf("0x%02x,", ct[i]);
    }
    printf("\nclen=%d\n",clen);
    // ct[0]=11;

    unsigned char decPt[2000];
    int dmlen;

    aes_gcm_decrypt(decPt,&dmlen,gcm_key,ct,clen,ctag,gcm_iv,12);
    puts("");
    for (size_t i = 0; i < dmlen; i++)
    {
        printf("0x%02x,", decPt[i]);
        if(decPt[i]!=pt[i]) puts("\n!!!!!Alert!!!!!");
    }
    printf("\n\n%d %d\n\n",dmlen,clen);

 }