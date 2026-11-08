/* SPDX-License-Identifier: Apache-2.0 */
#include "fuzz_target.h"

#include "pqscan/baseline/baseline.h"
#include "pqscan/core/finding.h"
#include "pqscan/core/json_fields.h"
#include "pqscan/core/key_size.h"
#include "pqscan/core/primitive.h"
#include "pqscan/core/status.h"
#include "pqscan/core/utc_time.h"
#include "pqscan/risk/priority.h"
#include "pqscan/risk/risk.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/* Matching walks the sorted entries, so a loaded baseline is also searched once. */
static void match_one_finding(baseline *accepted) {
    finding_list *findings = finding_list_create();
    const finding item = {
        "src/a.c",
        1,
        "RSA",
        RISK_QUANTUM_VULNERABLE,
        {KEY_SIZE_KNOWN, 2048},
        PRIMITIVE_UNSPECIFIED,
        "RSA_generate_key_ex",
        utc_time_none(),
        priority_none(),
    };
    if (findings == NULL || finding_list_add(findings, &item) != PQSCAN_OK) {
        abort();
    }
    const size_t removed = baseline_remove_accepted(accepted, findings);
    if (removed + finding_list_count(findings) != 1) {
        abort();
    }
    finding_list_destroy(findings);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const baseline_source source = {(const char *)data, size};
    baseline *accepted = NULL;
    json_error error;
    const pqscan_status status = baseline_load(&source, &accepted, &error);
    if ((status == PQSCAN_OK) != (accepted != NULL) ||
        (status == PQSCAN_ERR_BASELINE && error.message[0] == '\0') ||
        (status != PQSCAN_OK && status != PQSCAN_ERR_BASELINE)) {
        abort();
    }
    if (accepted != NULL) {
        match_one_finding(accepted);
    }
    baseline_destroy(accepted);
    return 0;
}
