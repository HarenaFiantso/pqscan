#define KEY_BITS 4096
#define WEAK_BITS (512 * 2)
#define ALGORITHM "RSA"

static const int GLOBAL_BITS = 1024 * 3;

void resolved(RSA *r) {
    int bits = KEY_BITS;
    RSA_generate_key_ex(r, bits, NULL, NULL);
    RSA_generate_key_ex(r, WEAK_BITS, NULL, NULL);
    RSA_generate_key_ex(r, GLOBAL_BITS, NULL, NULL);
    bits = bits * 2;
    RSA_generate_key_ex(r, bits, NULL, NULL);
    EVP_PKEY_CTX_new_from_name(NULL, ALGORITHM, NULL);
    const char *digest = "md5";
    EVP_MD_fetch(NULL, digest, NULL);
}
