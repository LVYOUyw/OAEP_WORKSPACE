
#ifndef AES128GCM_H
#define AES128GCM_H

#define GCM_IV_BYTES 12
#define GCM_TAG_BYTES 16

int aes_gcm_encrypt(unsigned char *outbuf, unsigned char *outtag, int *outlen, const unsigned char *k, const unsigned char *iv, const unsigned char *m, const int m_size);

int aes_gcm_decrypt(unsigned char *m, int *m_size, const unsigned char *k, const unsigned char *ct, const int ct_size, const unsigned char *tag, const unsigned char *iv);

#endif