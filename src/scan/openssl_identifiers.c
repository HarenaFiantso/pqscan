/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/scan/openssl_identifiers.h"

#include "pqscan/risk/risk.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

typedef struct identifier_key {
    const char *name;
    size_t len;
} identifier_key;

/* Sorted by name for bsearch(). Phase 3 replaces this table with external rules. */
static const crypto_identifier IDENTIFIERS[] = {
    {"DES_ecb_encrypt", "DES", RISK_CLASSICALLY_WEAK},
    {"DES_ede3_cbc_encrypt", "3DES", RISK_CLASSICALLY_WEAK},
    {"DES_ncbc_encrypt", "DES", RISK_CLASSICALLY_WEAK},
    {"DES_set_key", "DES", RISK_CLASSICALLY_WEAK},
    {"DH_compute_key", "DH", RISK_QUANTUM_VULNERABLE},
    {"DH_generate_key", "DH", RISK_QUANTUM_VULNERABLE},
    {"DH_generate_parameters_ex", "DH", RISK_QUANTUM_VULNERABLE},
    {"DH_new", "DH", RISK_QUANTUM_VULNERABLE},
    {"DSA_generate_key", "DSA", RISK_QUANTUM_VULNERABLE},
    {"DSA_generate_parameters_ex", "DSA", RISK_QUANTUM_VULNERABLE},
    {"DSA_new", "DSA", RISK_QUANTUM_VULNERABLE},
    {"DSA_sign", "DSA", RISK_QUANTUM_VULNERABLE},
    {"DSA_verify", "DSA", RISK_QUANTUM_VULNERABLE},
    {"ECDH_compute_key", "ECDH", RISK_QUANTUM_VULNERABLE},
    {"ECDSA_do_sign", "ECDSA", RISK_QUANTUM_VULNERABLE},
    {"ECDSA_do_verify", "ECDSA", RISK_QUANTUM_VULNERABLE},
    {"ECDSA_sign", "ECDSA", RISK_QUANTUM_VULNERABLE},
    {"ECDSA_verify", "ECDSA", RISK_QUANTUM_VULNERABLE},
    {"EC_KEY_generate_key", "EC", RISK_QUANTUM_VULNERABLE},
    {"EC_KEY_new", "EC", RISK_QUANTUM_VULNERABLE},
    {"EC_KEY_new_by_curve_name", "EC", RISK_QUANTUM_VULNERABLE},
    {"EVP_EC_gen", "EC", RISK_QUANTUM_VULNERABLE},
    {"EVP_PKEY_CTX_set_rsa_keygen_bits", "RSA", RISK_QUANTUM_VULNERABLE},
    {"EVP_PKEY_DH", "DH", RISK_QUANTUM_VULNERABLE},
    {"EVP_PKEY_DSA", "DSA", RISK_QUANTUM_VULNERABLE},
    {"EVP_PKEY_EC", "EC", RISK_QUANTUM_VULNERABLE},
    {"EVP_PKEY_ED25519", "EdDSA", RISK_QUANTUM_VULNERABLE},
    {"EVP_PKEY_ED448", "EdDSA", RISK_QUANTUM_VULNERABLE},
    {"EVP_PKEY_RSA", "RSA", RISK_QUANTUM_VULNERABLE},
    {"EVP_PKEY_RSA_PSS", "RSA", RISK_QUANTUM_VULNERABLE},
    {"EVP_PKEY_X25519", "ECDH", RISK_QUANTUM_VULNERABLE},
    {"EVP_PKEY_X448", "ECDH", RISK_QUANTUM_VULNERABLE},
    {"EVP_RSA_gen", "RSA", RISK_QUANTUM_VULNERABLE},
    {"EVP_aes_128_cbc", "AES-128", RISK_REVIEW},
    {"EVP_aes_128_ctr", "AES-128", RISK_REVIEW},
    {"EVP_aes_128_ecb", "AES-128", RISK_REVIEW},
    {"EVP_aes_128_gcm", "AES-128", RISK_REVIEW},
    {"EVP_des_cbc", "DES", RISK_CLASSICALLY_WEAK},
    {"EVP_des_ecb", "DES", RISK_CLASSICALLY_WEAK},
    {"EVP_des_ede3_cbc", "3DES", RISK_CLASSICALLY_WEAK},
    {"EVP_des_ede3_ecb", "3DES", RISK_CLASSICALLY_WEAK},
    {"EVP_md5", "MD5", RISK_CLASSICALLY_WEAK},
    {"EVP_rc4", "RC4", RISK_CLASSICALLY_WEAK},
    {"EVP_sha1", "SHA-1", RISK_CLASSICALLY_WEAK},
    {"MD5_Final", "MD5", RISK_CLASSICALLY_WEAK},
    {"MD5_Init", "MD5", RISK_CLASSICALLY_WEAK},
    {"MD5_Update", "MD5", RISK_CLASSICALLY_WEAK},
    {"RC4_set_key", "RC4", RISK_CLASSICALLY_WEAK},
    {"RSA_generate_key", "RSA", RISK_QUANTUM_VULNERABLE},
    {"RSA_generate_key_ex", "RSA", RISK_QUANTUM_VULNERABLE},
    {"RSA_new", "RSA", RISK_QUANTUM_VULNERABLE},
    {"RSA_private_decrypt", "RSA", RISK_QUANTUM_VULNERABLE},
    {"RSA_private_encrypt", "RSA", RISK_QUANTUM_VULNERABLE},
    {"RSA_public_decrypt", "RSA", RISK_QUANTUM_VULNERABLE},
    {"RSA_public_encrypt", "RSA", RISK_QUANTUM_VULNERABLE},
    {"RSA_sign", "RSA", RISK_QUANTUM_VULNERABLE},
    {"RSA_verify", "RSA", RISK_QUANTUM_VULNERABLE},
    {"SHA1_Final", "SHA-1", RISK_CLASSICALLY_WEAK},
    {"SHA1_Init", "SHA-1", RISK_CLASSICALLY_WEAK},
    {"SHA1_Update", "SHA-1", RISK_CLASSICALLY_WEAK},
};

static const size_t IDENTIFIER_COUNT = sizeof(IDENTIFIERS) / sizeof(IDENTIFIERS[0]);

static int compare_key_to_identifier(const void *key_ptr, const void *entry_ptr) {
    const identifier_key *key = key_ptr;
    const crypto_identifier *entry = entry_ptr;
    const int order = strncmp(key->name, entry->name, key->len);
    if (order != 0) {
        return order;
    }
    /* The first len bytes are equal, so a longer entry sorts after the key. */
    return (entry->name[key->len] == '\0') ? 0 : -1;
}

const crypto_identifier *openssl_identifier_find(const char *name, size_t len) {
    const identifier_key key = {name, len};
    return bsearch(&key, IDENTIFIERS, IDENTIFIER_COUNT, sizeof(IDENTIFIERS[0]),
                   compare_key_to_identifier);
}

const crypto_identifier *openssl_identifier_table(size_t *count) {
    *count = IDENTIFIER_COUNT;
    return IDENTIFIERS;
}
