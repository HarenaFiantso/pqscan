/* SPDX-License-Identifier: Apache-2.0 */
#include "fuzz_target.h"
#include "scan_harness.h"

#include "pqscan/scan/source_scanner.h"

#include <stddef.h>
#include <stdint.h>

/* Each input is read as C and as C++, as the two grammars disagree on much of the same text. */
static const fuzz_scan_case AS_C = {&source_scanner, "fuzz.c"};
static const fuzz_scan_case AS_CPP = {&source_scanner, "fuzz.cpp"};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    fuzz_scan(&AS_C, data, size);
    fuzz_scan(&AS_CPP, data, size);
    return 0;
}
