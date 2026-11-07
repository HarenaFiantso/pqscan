void references(RSA *r) {
    int aliased = 2048;
    int &alias = aliased;
    alias = 1024;
    RSA_generate_key_ex(r, aliased, NULL, NULL);

    int passed = 2048;
    configure(passed);
    RSA_generate_key_ex(r, passed, NULL, NULL);

    constexpr int fixed = 4096;
    RSA_generate_key_ex(r, fixed, NULL, NULL);
}
