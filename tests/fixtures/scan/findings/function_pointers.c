RSA *(*make_key)(void) = RSA_new;

void f(void) {
    use_digest(EVP_sha1);
}
