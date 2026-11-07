#define NEW_KEY RSA_new()

#define GENERATE(r) \
    RSA_generate_key_ex(r, 2048, \
                        NULL, NULL)

#define ALGORITHM EVP_PKEY_DSA
