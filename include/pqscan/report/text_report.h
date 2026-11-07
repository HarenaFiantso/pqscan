/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_REPORT_TEXT_REPORT_H
#define PQSCAN_REPORT_TEXT_REPORT_H

#include "pqscan/report/reporter.h"

/** Writes one "file:line: algorithm (risk)" line per finding, then a line that counts them. */
extern const reporter text_reporter;

#endif /* PQSCAN_REPORT_TEXT_REPORT_H */
