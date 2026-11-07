/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_SCAN_SOURCE_SCANNER_H
#define PQSCAN_SCAN_SOURCE_SCANNER_H

#include "pqscan/scan/scanner.h"

/**
 * A naive text scanner for C and C++ source. It matches whole identifiers, but has no
 * notion of syntax, so it also reports identifiers inside comments and strings. Files
 * containing a NUL byte are skipped with PQSCAN_ERR_BINARY.
 */
extern const scanner source_scanner;

#endif /* PQSCAN_SCAN_SOURCE_SCANNER_H */
