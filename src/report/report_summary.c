/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/report/report_summary.h"

#include "pqscan/core/finding.h"

#include <stddef.h>

risk_counts risk_counts_of(const finding_list *findings) {
    risk_counts counts = {{0}};
    for (size_t i = 0; i < finding_list_count(findings); i++) {
        counts.by_level[finding_list_get(findings, i)->risk]++;
    }
    return counts;
}
