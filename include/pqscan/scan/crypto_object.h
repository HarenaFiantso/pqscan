/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_SCAN_CRYPTO_OBJECT_H
#define PQSCAN_SCAN_CRYPTO_OBJECT_H

#include "pqscan/core/key_size.h"
#include "pqscan/core/primitive.h"
#include "pqscan/core/status.h"
#include "pqscan/core/utc_time.h"
#include "pqscan/scan/pem_blocks.h"

#include <stdbool.h>
#include <stddef.h>

/**
 * What a certificate, key or request says about one use of an algorithm. It knows nothing
 * of rules: the caller looks type_name up. Everything is borrowed for the visit only.
 */
typedef struct key_use {
    const char *type_name; /**< OpenSSL's short name of the key or digest type, such as
                                "rsaEncryption", "id-ecPublicKey" or "SHA1". */
    const char *symbol;    /**< What to record as matched, such as "sha256WithRSAEncryption",
                                with static storage. NULL to take the rule's pattern. */
    key_size size;
    bool has_usage;         /**< Whether usage says what the key is for. */
    crypto_primitive usage; /**< From a certificate's key usage, or "signature" for a signature. */
    utc_time expires;       /**< When the certificate stops being valid, if it is one. */
} key_use;

/**
 * @brief Be told about one use.
 *
 * @param use The use.
 * @param context What the sink carries.
 * @return PQSCAN_OK to go on, anything else to stop with that status.
 */
typedef pqscan_status (*key_use_visitor)(const key_use *use, void *context);

/** Where uses go. */
typedef struct key_use_sink {
    key_use_visitor visit;
    void *context;
} key_use_sink;

/**
 * @brief Prepare OpenSSL, once per process, without reading any configuration.
 *
 * OpenSSL would otherwise read the file OPENSSL_CONF names, which can load modules: the
 * scan would then depend on its environment, and could run code it was never asked to.
 * Calling it again does nothing.
 *
 * @return PQSCAN_OK, or PQSCAN_ERR_NOMEM if OpenSSL cannot start, which only allocation
 *         failure causes.
 */
pqscan_status crypto_object_init(void);

/**
 * @brief Report what one PEM block holds.
 *
 * It reads certificates, certificate requests, public and private keys, and DH, DSA and EC
 * parameters. A certificate gives its key, with its key usage and expiry, and its signature
 * algorithm, with the digest the signature uses. Blocks of other kinds, such as CRLs, give
 * nothing. A private key is never decrypted: no passphrase is ever asked for.
 *
 * @param block The block, as pem_finder_next() found it.
 * @param sink Where uses go.
 * @return PQSCAN_OK; PQSCAN_ERR_ENCRYPTED for a PKCS#8 key whose algorithm is hidden;
 *         PQSCAN_ERR_MALFORMED if the block cannot be decoded; PQSCAN_ERR_NOMEM; or the
 *         first status other than PQSCAN_OK that the visitor returned.
 */
pqscan_status crypto_object_read_pem(const pem_block *block, const key_use_sink *sink);

/**
 * @brief Report what a DER file holds.
 *
 * It tries each kind crypto_object_read_pem() reads, and takes the first that decodes the
 * whole input.
 *
 * @param data The bytes.
 * @param len How many there are.
 * @param sink Where uses go.
 * @return As crypto_object_read_pem(), with PQSCAN_ERR_MALFORMED when no kind fits.
 */
pqscan_status crypto_object_read_der(const unsigned char *data, size_t len,
                                     const key_use_sink *sink);

#endif /* PQSCAN_SCAN_CRYPTO_OBJECT_H */
