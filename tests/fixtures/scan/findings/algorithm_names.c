void f(void) {
    EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    EVP_MD_fetch(NULL, "md5", NULL);
    EVP_CIPHER_fetch(NULL, "AES-128-GCM", NULL);
    EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)4096);
    EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    EVP_get_digestbyname("sha1");
    EVP_MD_fetch(NULL, "SHA2-256", NULL);
}
