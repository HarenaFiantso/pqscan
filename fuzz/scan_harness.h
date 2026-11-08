/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_FUZZ_SCAN_HARNESS_H
#define PQSCAN_FUZZ_SCAN_HARNESS_H

#include "pqscan/scan/scanner.h"

#include <stddef.h>
#include <stdint.h>

/** What to scan an input as. */
typedef struct fuzz_scan_case {
    const scanner *active; /**< The scanner. It must accept the path. */
    const char *path;      /**< The path the scanner sees, which picks the language or format. */
} fuzz_scan_case;

/**
 * @brief Scan one input as if it were a file with a given path, with the built-in rules, and
 *        abort if a finding breaks what reporters rely on.
 *
 * The rules are loaded on the first call and kept until the process exits, as a fuzzer calls
 * this millions of times.
 *
 * @param scan_case The scanner and the path.
 * @param data The input. Not modified.
 * @param size How many bytes it has.
 */
void fuzz_scan(const fuzz_scan_case *scan_case, const uint8_t *data, size_t size);

#endif /* PQSCAN_FUZZ_SCAN_HARNESS_H */
