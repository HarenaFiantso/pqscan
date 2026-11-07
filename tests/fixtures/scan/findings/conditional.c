#ifdef USE_RSA
void a(void) { RSA_new(); }
#else
void a(void) { DSA_new(); }
#endif

#if 0
void b(void) { DH_new(); }
#else
void b(void) { ECDSA_do_sign(0, 0, 0); }
#endif
