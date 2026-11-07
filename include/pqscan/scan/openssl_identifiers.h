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

#endif /* PQSCAN_SCAN_OPENSSL_IDENTIFIERS_H */
