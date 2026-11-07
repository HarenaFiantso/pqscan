void f(RSA *r, DSA *d, int bits) {
    RSA_generate_key_ex(r, 2048, NULL, NULL);
    RSA_generate_key_ex(r, 1024, NULL, NULL);
    RSA_generate_key_ex(r, bits, NULL, NULL);
    RSA_generate_key_ex(r, /* size */ (int)0x1000,
                        NULL, NULL);
    EVP_RSA_gen(3072);
    DSA_generate_parameters_ex(d, 2048, NULL, 0, NULL, NULL, NULL);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 1 << 11);
}
