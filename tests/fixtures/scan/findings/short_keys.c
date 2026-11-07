void f(DSA *d, DH *h) {
    DSA_generate_parameters_ex(d, 1024, NULL, 0, NULL, NULL, NULL);
    DH_generate_parameters_ex(h, 1024, 2, NULL);
    EVP_RSA_gen(2047);
    EVP_RSA_gen(2048);
}
