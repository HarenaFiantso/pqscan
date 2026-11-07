#if 0
RSA *old_key = RSA_new();
This isn't C at all, and DSA_new stays disabled.
#endif

void f(void) {
#if 0
    DH_new();
#endif
}
