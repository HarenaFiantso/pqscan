/* Archives are kept for thirty years. */
void seal_archive(RSA *rsa) { RSA_generate_key_ex(rsa, 3072, NULL, NULL); }
