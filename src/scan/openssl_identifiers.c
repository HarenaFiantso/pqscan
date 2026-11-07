/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/scan/openssl_identifiers.h"

#include "pqscan/risk/risk.h"

#include <ctype.h>
#include <stdbool.h>
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

/* Sorted by name for bsearch(). */
static const crypto_identifier CALL_ONLY_IDENTIFIERS[] = {
    {"MD5", "MD5", RISK_CLASSICALLY_WEAK},
    {"SHA1", "SHA-1", RISK_CLASSICALLY_WEAK},
};

/* Sorted by name for bsearch(). */
static const call_signature CALLS[] = {
    {"DH_generate_parameters_ex", 1, CALL_NO_ARGUMENT},
    {"DSA_generate_parameters_ex", 1, CALL_NO_ARGUMENT},
    {"EVP_ASYM_CIPHER_fetch", CALL_NO_ARGUMENT, 1},
    {"EVP_CIPHER_fetch", CALL_NO_ARGUMENT, 1},
    {"EVP_KEYEXCH_fetch", CALL_NO_ARGUMENT, 1},
    {"EVP_KEYMGMT_fetch", CALL_NO_ARGUMENT, 1},
    {"EVP_MD_fetch", CALL_NO_ARGUMENT, 1},
    {"EVP_PKEY_CTX_new_from_name", CALL_NO_ARGUMENT, 1},
    {"EVP_PKEY_CTX_set_rsa_keygen_bits", 1, CALL_NO_ARGUMENT},
    {"EVP_PKEY_Q_keygen", 3, 2},
    {"EVP_RSA_gen", 0, CALL_NO_ARGUMENT},
    {"EVP_SIGNATURE_fetch", CALL_NO_ARGUMENT, 1},
    {"EVP_get_cipherbyname", CALL_NO_ARGUMENT, 0},
    {"EVP_get_digestbyname", CALL_NO_ARGUMENT, 0},
    {"RSA_generate_key", 0, CALL_NO_ARGUMENT},
    {"RSA_generate_key_ex", 1, CALL_NO_ARGUMENT},
};

/* The names OpenSSL accepts are case-insensitive, so this table has no useful order. */
static const crypto_identifier ALGORITHM_NAMES[] = {
    {"3DES", "3DES", RISK_CLASSICALLY_WEAK},
    {"AES-128-CBC", "AES-128", RISK_REVIEW},
    {"AES-128-CTR", "AES-128", RISK_REVIEW},
    {"AES-128-ECB", "AES-128", RISK_REVIEW},
    {"AES-128-GCM", "AES-128", RISK_REVIEW},
    {"DES-CBC", "DES", RISK_CLASSICALLY_WEAK},
    {"DES-ECB", "DES", RISK_CLASSICALLY_WEAK},
    {"DES-EDE3-CBC", "3DES", RISK_CLASSICALLY_WEAK},
    {"DES-EDE3-ECB", "3DES", RISK_CLASSICALLY_WEAK},
    {"DH", "DH", RISK_QUANTUM_VULNERABLE},
    {"DHX", "DH", RISK_QUANTUM_VULNERABLE},
    {"DSA", "DSA", RISK_QUANTUM_VULNERABLE},
    {"EC", "EC", RISK_QUANTUM_VULNERABLE},
    {"ECDH", "ECDH", RISK_QUANTUM_VULNERABLE},
    {"ECDSA", "ECDSA", RISK_QUANTUM_VULNERABLE},
    {"ED25519", "EdDSA", RISK_QUANTUM_VULNERABLE},
    {"ED448", "EdDSA", RISK_QUANTUM_VULNERABLE},
    {"MD5", "MD5", RISK_CLASSICALLY_WEAK},
    {"RC4", "RC4", RISK_CLASSICALLY_WEAK},
    {"RSA", "RSA", RISK_QUANTUM_VULNERABLE},
    {"RSA-PSS", "RSA", RISK_QUANTUM_VULNERABLE},
    {"RSASSA-PSS", "RSA", RISK_QUANTUM_VULNERABLE},
    {"SHA-1", "SHA-1", RISK_CLASSICALLY_WEAK},
    {"SHA1", "SHA-1", RISK_CLASSICALLY_WEAK},
    {"X25519", "ECDH", RISK_QUANTUM_VULNERABLE},
    {"X448", "ECDH", RISK_QUANTUM_VULNERABLE},
};

static const size_t IDENTIFIER_COUNT = sizeof(IDENTIFIERS) / sizeof(IDENTIFIERS[0]);
static const size_t CALL_ONLY_COUNT =
    sizeof(CALL_ONLY_IDENTIFIERS) / sizeof(CALL_ONLY_IDENTIFIERS[0]);
static const size_t CALL_COUNT = sizeof(CALLS) / sizeof(CALLS[0]);
static const size_t ALGORITHM_NAME_COUNT = sizeof(ALGORITHM_NAMES) / sizeof(ALGORITHM_NAMES[0]);

static int compare_key_to_name(const identifier_key *key, const char *name) {
    const int order = strncmp(key->name, name, key->len);
    if (order != 0) {
        return order;
    }
    /* The first len bytes are equal, so a longer name sorts after the key. */
    return (name[key->len] == '\0') ? 0 : -1;
}

static int compare_key_to_identifier(const void *key_ptr, const void *entry_ptr) {
    const crypto_identifier *entry = entry_ptr;
    return compare_key_to_name(key_ptr, entry->name);
}

static int compare_key_to_call(const void *key_ptr, const void *entry_ptr) {
    const call_signature *entry = entry_ptr;
    return compare_key_to_name(key_ptr, entry->name);
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

const crypto_identifier *openssl_call_only_find(const char *name, size_t len) {
    const identifier_key key = {name, len};
    return bsearch(&key, CALL_ONLY_IDENTIFIERS, CALL_ONLY_COUNT, sizeof(CALL_ONLY_IDENTIFIERS[0]),
                   compare_key_to_identifier);
}

const crypto_identifier *openssl_call_only_table(size_t *count) {
    *count = CALL_ONLY_COUNT;
    return CALL_ONLY_IDENTIFIERS;
}

const call_signature *openssl_call_find(const char *name, size_t len) {
    const identifier_key key = {name, len};
    return bsearch(&key, CALLS, CALL_COUNT, sizeof(CALLS[0]), compare_key_to_call);
}

const call_signature *openssl_call_table(size_t *count) {
    *count = CALL_COUNT;
    return CALLS;
}

static bool equals_ignoring_case(const char *text, size_t len, const char *name) {
    for (size_t i = 0; i < len; i++) {
        if (name[i] == '\0' || tolower((unsigned char)text[i]) != tolower((unsigned char)name[i])) {
            return false;
        }
    }
    return name[len] == '\0';
}

const crypto_identifier *openssl_algorithm_name_find(const char *name, size_t len) {
    for (size_t i = 0; i < ALGORITHM_NAME_COUNT; i++) {
        if (equals_ignoring_case(name, len, ALGORITHM_NAMES[i].name)) {
            return &ALGORITHM_NAMES[i];
        }
    }
    return NULL;
}
