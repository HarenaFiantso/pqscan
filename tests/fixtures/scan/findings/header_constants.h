/* A header's guard is no reason to distrust what it holds. */
#ifndef HEADER_CONSTANTS_H
#define HEADER_CONSTANTS_H

#define HEADER_BITS 3072

static inline void generate(RSA *r) {
    RSA_generate_key_ex(r, HEADER_BITS, NULL, NULL);
}

#endif /* HEADER_CONSTANTS_H */
