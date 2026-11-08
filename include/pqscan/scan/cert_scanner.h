/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_SCAN_CERT_SCANNER_H
#define PQSCAN_SCAN_CERT_SCANNER_H

#include "pqscan/scan/scanner.h"

/**
 * A scanner for certificates, certificate requests, keys and DH parameters, in PEM or DER,
 * decoded by OpenSSL's libcrypto.
 *
 * Each key type and digest is looked up in the rules' key types. A certificate gives a
 * finding for its key, with the key's size, what its key usage says it does, and when the
 * certificate expires, and findings for the algorithm and digest of its signature. In PEM
 * files, every block is read, and findings name the line of its BEGIN marker. Findings of a
 * DER file are about the whole file, with line 0.
 *
 * A file that holds an encrypted PKCS#8 key gives PQSCAN_ERR_ENCRYPTED, and one with a block
 * that cannot be decoded, or that is no certificate or key at all, gives
 * PQSCAN_ERR_MALFORMED. Findings of the other blocks of the file remain in both cases.
 */
extern const scanner cert_scanner;

#endif /* PQSCAN_SCAN_CERT_SCANNER_H */
