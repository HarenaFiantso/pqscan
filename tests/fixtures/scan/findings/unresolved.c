#define MACRO_WITH_PARAMETERS(x) 2048

#ifdef FIPS
#define CONDITIONAL_BITS 3072
#else
#define CONDITIONAL_BITS 2048
#endif

#ifndef DEFAULT_BITS
#define DEFAULT_BITS 2048
#endif

#define REMOVED_BITS 2048
#undef REMOVED_BITS

int mutable_bits = 2048;

void unresolved(RSA *r, int parameter, int condition) {
    RSA_generate_key_ex(r, parameter, NULL, NULL);
    RSA_generate_key_ex(r, MACRO_WITH_PARAMETERS, NULL, NULL);
    RSA_generate_key_ex(r, CONDITIONAL_BITS, NULL, NULL);
    RSA_generate_key_ex(r, DEFAULT_BITS, NULL, NULL);
    RSA_generate_key_ex(r, REMOVED_BITS, NULL, NULL);
    RSA_generate_key_ex(r, mutable_bits, NULL, NULL);

    int branch = 2048;
    if (condition) {
        branch = 1024;
    }
    RSA_generate_key_ex(r, branch, NULL, NULL);

    int loop = 2048;
    while (condition) {
        RSA_generate_key_ex(r, loop, NULL, NULL);
        loop = 1024;
    }

    int address = 2048;
    read_bits(&address);
    RSA_generate_key_ex(r, address, NULL, NULL);
}
