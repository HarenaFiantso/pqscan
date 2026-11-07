/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/risk/risk.h"

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
