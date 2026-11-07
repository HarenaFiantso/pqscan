/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_REPORT_REPORT_SUMMARY_H
#define PQSCAN_REPORT_REPORT_SUMMARY_H

#include "pqscan/core/finding.h"
#include "pqscan/risk/risk.h"

#include <stddef.h>

/** How many findings a report has at each risk level. */
typedef struct risk_counts {
    size_t by_level[RISK_LEVEL_COUNT]; /**< Indexed by risk_level. */
} risk_counts;

/**
 * @brief Count the findings at each risk level.
 *
 * @param findings The findings.
 * @return The counts.
 */
risk_counts risk_counts_of(const finding_list *findings);

#endif /* PQSCAN_REPORT_REPORT_SUMMARY_H */
