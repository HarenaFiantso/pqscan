template <class T> T make() { return DH_new(); }

void f() {
    ::RSA_new();
    ossl::DSA_new();
    auto hash = [] { return EVP_md5(); };
    auto id = ::EVP_PKEY_EC;
}
