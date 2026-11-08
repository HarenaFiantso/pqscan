/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_RISK_PRIORITIZE_H
#define PQSCAN_RISK_PRIORITIZE_H

#include "pqscan/core/finding.h"
#include "pqscan/risk/project_file.h"

/**
 * @brief Score every finding with what the project says about its path.
 *
 * @param findings The findings. Their priorities are replaced.
 * @param target The project. Its component names are borrowed by the findings, so it must
 *               outlive them.
 * @param as_of_year The year to score for, from PRIORITY_MIN_YEAR to PRIORITY_MAX_YEAR.
 */
void prioritize_findings(finding_list *findings, const project *target, int as_of_year);

/**
 * @brief Put the most urgent findings first.
 *
 * Findings of equal score keep a fixed order, by path, line, then the rest of what a report
 * shows, so that two runs on the same files print the same report.
 *
 * @param findings The findings.
 */
void sort_by_priority(finding_list *findings);

#endif /* PQSCAN_RISK_PRIORITIZE_H */
