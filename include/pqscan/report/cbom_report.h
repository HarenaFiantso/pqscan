/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_REPORT_CBOM_REPORT_H
#define PQSCAN_REPORT_CBOM_REPORT_H

#include "pqscan/report/reporter.h"

/**
 * Writes a CycloneDX 1.6 Cryptography Bill of Materials. Findings that use the same algorithm,
 * key size and primitive are one component, whose occurrences list where it is used.
 */
extern const reporter cbom_reporter;

#endif /* PQSCAN_REPORT_CBOM_REPORT_H */
