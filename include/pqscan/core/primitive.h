/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_CORE_PRIMITIVE_H
#define PQSCAN_CORE_PRIMITIVE_H

#include <stdbool.h>

/** What a use of cryptography does. */
typedef enum crypto_primitive {
    PRIMITIVE_UNSPECIFIED = 0, /**< The code does not say, as with RSA_new(). */
    PRIMITIVE_SIGNATURE,
    PRIMITIVE_KEY_EXCHANGE,
    PRIMITIVE_ENCRYPTION,
    PRIMITIVE_HASH,
} crypto_primitive;

/**
 * @brief Name a primitive as it appears in rule files.
 *
 * @param primitive The primitive.
 * @return The name, such as "key_exchange". Never NULL. The string has static storage
 *         duration: the caller must not modify or free it.
 */
const char *crypto_primitive_name(crypto_primitive primitive);

/**
 * @brief Find the primitive with a given name.
 *
 * @param name The name, such as "signature". Case-sensitive.
 * @param out On success, the primitive. Untouched on failure.
 * @return true on success, false if no primitive has this name.
 */
bool crypto_primitive_parse(const char *name, crypto_primitive *out);

#endif /* PQSCAN_CORE_PRIMITIVE_H */
