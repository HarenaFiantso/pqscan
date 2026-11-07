/* One use of everything a report has to show. */
void mixed(RSA *rsa, int unknown_bits) {
    RSA_generate_key_ex(rsa, 2048, NULL, NULL);
    RSA_generate_key_ex(rsa, 1024, NULL, NULL);
    RSA_generate_key_ex(rsa, unknown_bits, NULL, NULL);
    RSA_generate_key_ex(rsa, 2048, NULL, NULL);
    ECDSA_sign(0, NULL, 0, NULL, NULL, NULL);
    DH_compute_key(NULL, NULL, NULL);
    RSA_public_encrypt(0, NULL, NULL, rsa, 0);
    EVP_aes_128_gcm();
    EVP_rc4();
    EVP_md5();
}
