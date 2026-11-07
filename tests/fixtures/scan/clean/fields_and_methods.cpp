struct keys {
    int EVP_PKEY_RSA;
    RSA *(*RSA_new)(void);
};

void f(keys *pointer, keys value) {
    pointer->EVP_PKEY_RSA = 1;
    pointer->RSA_new();
    value.RSA_new();
}
