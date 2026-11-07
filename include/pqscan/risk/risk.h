/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_RISK_RISK_H
#define PQSCAN_RISK_RISK_H

/** How urgent a finding is. Values are ordered by severity, so they compare with <. */
typedef enum risk_level {
    RISK_OK = 0,
    RISK_REVIEW,
    RISK_QUANTUM_VULNERABLE,
    RISK_CLASSICALLY_WEAK,
} risk_level;

/**
 * @brief Name a risk level as it appears in reports.
 *
 * @param risk The risk level.
 * @return The name, such as "QUANTUM_VULNERABLE". Never NULL. The string has static
 *         storage duration: the caller must not modify or free it.
 */
const char *risk_level_name(risk_level risk);

#endif /* PQSCAN_RISK_RISK_H */
