/* SPDX-License-Identifier: Apache-2.0 */
#include "fuzz_target.h"
#include "scan_harness.h"

#include "pqscan/scan/cert_scanner.h"

#include <stddef.h>
#include <stdint.h>

/* The scanner tells PEM from DER by the content, so the extension does not matter. */
static const fuzz_scan_case AS_PEM = {&cert_scanner, "fuzz.pem"};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    fuzz_scan(&AS_PEM, data, size);
    return 0;
}
