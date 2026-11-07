/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_SCAN_OPENSSL_IDENTIFIERS_H
#define PQSCAN_SCAN_OPENSSL_IDENTIFIERS_H

#include "pqscan/risk/risk.h"

#include <stddef.h>

/** What a known OpenSSL identifier means. All strings have static storage duration. */
typedef struct crypto_identifier {
    const char *name;
    const char *algorithm;
    risk_level risk;
} crypto_identifier;

/** Marks a call that has no argument of this kind. */
enum { CALL_NO_ARGUMENT = -1 };

/** Which arguments of a known call are worth reading. */
typedef struct call_signature {
    const char *name;
    int key_bits_argument;  /**< Index of the key size, or CALL_NO_ARGUMENT. */
    int algorithm_argument; /**< Index of a string naming an algorithm, or CALL_NO_ARGUMENT. */
} call_signature;

/**
 * @brief Look up an identifier.
 *
 * @param name The start of the identifier. It need not be NUL-terminated.
 * @param len The length of the identifier.
 * @return The entry, which has static storage duration, or NULL if it is not known.
 */
const crypto_identifier *openssl_identifier_find(const char *name, size_t len);

/**
 * @brief Get every known identifier, sorted by name.
 *
 * @param count Out: the number of entries.
 * @return The table, which has static storage duration.
 */
const crypto_identifier *openssl_identifier_table(size_t *count);

/**
 * @brief Look up the signature of a call.
 *
 * @param name The start of the function name. It need not be NUL-terminated.
 * @param len The length of the name.
 * @return The entry, which has static storage duration, or NULL if it is not known.
 */
const call_signature *openssl_call_find(const char *name, size_t len);

/**
 * @brief Get every known call signature, sorted by name.
 *
 * @param count Out: the number of entries.
 * @return The table, which has static storage duration.
 */
const call_signature *openssl_call_table(size_t *count);

/**
 * @brief Look up an algorithm by the name OpenSSL knows it under, ignoring case.
 *
 * @param name The start of the name. It need not be NUL-terminated.
 * @param len The length of the name.
 * @return The entry, which has static storage duration, or NULL if it is not known.
 */
const crypto_identifier *openssl_algorithm_name_find(const char *name, size_t len);

#endif /* PQSCAN_SCAN_OPENSSL_IDENTIFIERS_H */
