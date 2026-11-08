/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_SCAN_ELF_SCANNER_H
#define PQSCAN_SCAN_ELF_SCANNER_H

#include "pqscan/scan/scanner.h"

/**
 * A scanner for ELF64 executables, shared libraries and object files, recognized by their
 * first bytes whatever their name.
 *
 * Each function symbol, whether the file defines it or needs it from a library, is looked up
 * in the rules' function names. So is an untyped symbol the file needs, which is how an object
 * file refers to what it calls. Data symbols never count. A binary has no lines, so findings
 * are about the whole file, with line 0, and each rule gives at most one finding per file,
 * even when a symbol is in both the symbol table and the dynamic one. A binary does not keep
 * the arguments of a call either, so when the rules say a call takes a key size, that size is
 * unknown.
 *
 * Only what the symbols show can be found: crypto compiled into a stripped static executable
 * leaves no trace there, so such a file gives PQSCAN_ERR_ELF_NO_SYMBOLS. A 32-bit file gives
 * PQSCAN_ERR_ELF_UNSUPPORTED, and a damaged one PQSCAN_ERR_ELF_MALFORMED, after the findings
 * of whatever could still be read.
 */
extern const scanner elf_scanner;

#endif /* PQSCAN_SCAN_ELF_SCANNER_H */
