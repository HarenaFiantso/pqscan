/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/risk/risk.h"

#include "pqscan/core/key_size.h"

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

static const risk_level ALL_LEVELS[] = {
    RISK_OK,
    RISK_REVIEW,
    RISK_QUANTUM_VULNERABLE,
    RISK_CLASSICALLY_WEAK,
};

const char *risk_level_name(risk_level risk) {
    switch (risk) {
    case RISK_OK:
        return "OK";
    case RISK_REVIEW:
        return "REVIEW";
    case RISK_QUANTUM_VULNERABLE:
        return "QUANTUM_VULNERABLE";
    case RISK_CLASSICALLY_WEAK:
        return "CLASSICALLY_WEAK";
    }
    return "UNKNOWN";
}

bool risk_level_parse(const char *name, risk_level *out) {
    for (size_t i = 0; i < sizeof(ALL_LEVELS) / sizeof(ALL_LEVELS[0]); i++) {
        if (strcmp(name, risk_level_name(ALL_LEVELS[i])) == 0) {
            *out = ALL_LEVELS[i];
            return true;
        }
    }
    return false;
}

risk_level risk_classify(const algorithm_policy *policy, key_size size) {
    const bool too_short = size.kind == KEY_SIZE_KNOWN && size.bits < policy->weak_below_bits;
    return (too_short && policy->risk < RISK_CLASSICALLY_WEAK) ? RISK_CLASSICALLY_WEAK
                                                               : policy->risk;
}
