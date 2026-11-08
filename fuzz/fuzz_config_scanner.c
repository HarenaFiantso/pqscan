/* SPDX-License-Identifier: Apache-2.0 */
#include "fuzz_target.h"
#include "scan_harness.h"

#include "pqscan/scan/config_scanner.h"

#include <stddef.h>
#include <stdint.h>

/* One lexer and one table of directives serve every dialect, so one path covers them all. */
static const fuzz_scan_case AS_CONFIG = {&config_scanner, "fuzz.conf"};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    fuzz_scan(&AS_CONFIG, data, size);
    return 0;
}
