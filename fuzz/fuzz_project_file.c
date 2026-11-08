/* SPDX-License-Identifier: Apache-2.0 */
#include "fuzz_target.h"

#include "pqscan/core/json_fields.h"
#include "pqscan/core/status.h"
#include "pqscan/risk/priority.h"
#include "pqscan/risk/project_file.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/* A loaded project must give every path years in range, since priorities add them up. */
static void check_lifetime(const project *target) {
    const data_lifetime lifetime = project_lifetime_of(target, "src/payments/a.c");
    if (lifetime.secrecy_years < 0 || lifetime.secrecy_years > PRIORITY_MAX_SPAN_YEARS ||
        lifetime.migration_years < 0 || lifetime.migration_years > PRIORITY_MAX_SPAN_YEARS) {
        abort();
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const project_source source = {(const char *)data, size};
    project *target = NULL;
    json_error error;
    const pqscan_status status = project_load(&source, &target, &error);
    if ((status == PQSCAN_OK) != (target != NULL) ||
        (status == PQSCAN_ERR_PROJECT && error.message[0] == '\0') ||
        (status != PQSCAN_OK && status != PQSCAN_ERR_PROJECT)) {
        abort();
    }
    if (target != NULL) {
        check_lifetime(target);
    }
    project_destroy(target);
    return 0;
}
