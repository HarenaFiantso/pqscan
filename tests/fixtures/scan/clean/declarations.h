#ifndef EVP_PKEY_DH
#define EVP_PKEY_DH 28
#endif

#define RSA_new my_rsa_new
#define WRAP(RSA_sign) 1

RSA *RSA_new(void);
int (DSA_new)(void);
void take(int RSA_verify, int DSA_sign[4]);
enum { EVP_PKEY_RSA = 6 };

#if defined(EVP_PKEY_DSA)
int have_dsa;
#endif
