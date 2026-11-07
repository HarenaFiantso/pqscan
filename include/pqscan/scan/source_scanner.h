/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_SCAN_SOURCE_SCANNER_H
#define PQSCAN_SCAN_SOURCE_SCANNER_H

#include "pqscan/scan/scanner.h"

/**
 * A syntax-aware scanner for C and C++ source, built on Tree-sitter.
 *
 * It reports uses of known identifiers, including inside macro bodies, and reads literal key
 * sizes and algorithm names from the arguments of known calls. It ignores comments, strings
 * outside those arguments, declarations of a name, struct fields, methods, and code under
 * a literal #if 0. Syntax errors are tolerated, so broken code is still scanned.
 *
 * Files containing a NUL byte are skipped with PQSCAN_ERR_BINARY. A file that takes longer
 * than its time budget stops with PQSCAN_ERR_PARSE, and any findings already added remain.
 */
extern const scanner source_scanner;

#endif /* PQSCAN_SCAN_SOURCE_SCANNER_H */
