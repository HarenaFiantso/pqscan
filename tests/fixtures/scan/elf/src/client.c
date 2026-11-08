/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Compiled by ../generate.sh into ELF objects. It declares what it calls instead of including
 * OpenSSL's headers, so that it builds for any target without a sysroot.
 */
typedef struct rsa_st RSA;
typedef struct evp_md_st EVP_MD;

RSA *RSA_new(void);
int RSA_generate_key_ex(RSA *rsa, int bits, void *exponent, void *callback);
const EVP_MD *EVP_sha1(void);
const EVP_MD *EVP_sha256(void);
unsigned char *MD5(const unsigned char *data, unsigned long len, unsigned char *digest);

/* Data named like a function a rule knows is not a use of it. */
int EVP_md5 = 0;

/* Defined here, as in a binary that links a copy of the library in. */
int DH_generate_key(void *dh) {
    (void)dh;
    return 1;
}

int make_key(void) {
    unsigned char digest[16];
    RSA *rsa = RSA_new();
    (void)EVP_sha1();
    (void)EVP_sha256();
    (void)MD5(digest, 0, digest);
    return RSA_generate_key_ex(rsa, 2048, 0, 0);
}
