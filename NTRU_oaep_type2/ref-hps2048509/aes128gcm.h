

static int aes_gcm_encrypt(unsigned char *outbuf, unsigned char *outtag, int *outlen, const unsigned char *k, const unsigned char *iv, const unsigned char *m, const int m_size);

static int aes_gcm_decrypt(unsigned char *m, int *m_size, const unsigned char *k, const unsigned char *ct, const int ct_size, const unsigned char *tag, const unsigned char *iv, const size_t iv_size);
 