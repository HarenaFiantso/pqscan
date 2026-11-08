/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_SCAN_CONFIG_SCANNER_H
#define PQSCAN_SCAN_CONFIG_SCANNER_H

#include "pqscan/scan/scanner.h"

/**
 * A scanner for the TLS and SSH settings of OpenSSL, nginx, Apache and OpenSSH files.
 *
 * It reads the settings that list algorithms: cipher strings, groups and signature
 * algorithms (CipherString, ssl_ciphers, SSLCipherSuite, ssl_conf_command, SSLOpenSSLConfCmd
 * and the like), OpenSSH's KexAlgorithms, HostKeyAlgorithms, Ciphers, MACs and the like, and
 * default_md and default_bits from openssl.cnf. Each name in those lists is looked up in the
 * rules' config tokens. Names a setting takes away, such as !RSA or -ssh-rsa, are not
 * reported, and neither is one name twice on one line of one setting.
 *
 * Aliases such as DEFAULT or HIGH are not expanded, as what they mean depends on the OpenSSL
 * build that reads them. Files containing a NUL byte are skipped with PQSCAN_ERR_BINARY.
 */
extern const scanner config_scanner;

#endif /* PQSCAN_SCAN_CONFIG_SCANNER_H */
