#include <openssl/rsa.h>

RSA *make_key(void) {
    RSA *key = RSA_new();
    return key;
}
