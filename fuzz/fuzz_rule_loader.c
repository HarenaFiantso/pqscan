/* SPDX-License-Identifier: Apache-2.0 */
#include "fuzz_target.h"

#include "pqscan/core/status.h"
#include "pqscan/rules/rule_loader.h"
#include "pqscan/rules/rule_set.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/* A refusal must say why, since the message is all a user gets. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const rule_source source = {(const char *)data, size};
    rule_set *rules = NULL;
    rule_error error;
    const pqscan_status status = rule_set_load(&source, &rules, &error);
    if ((status == PQSCAN_OK) != (rules != NULL) ||
        (status == PQSCAN_ERR_RULES && error.message[0] == '\0') ||
        (status != PQSCAN_OK && status != PQSCAN_ERR_RULES)) {
        abort();
    }
    rule_set_destroy(rules);
    return 0;
}
