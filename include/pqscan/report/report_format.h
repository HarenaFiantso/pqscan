/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_REPORT_REPORT_FORMAT_H
#define PQSCAN_REPORT_REPORT_FORMAT_H

#include "pqscan/report/reporter.h"

/**
 * @brief Find the reporter for an output format. This is the one place that lists them.
 *
 * @param name The format, such as "text". Case-sensitive.
 * @return The reporter, which has static storage duration, or NULL if no format has this name.
 */
const reporter *reporter_find(const char *name);

#endif /* PQSCAN_REPORT_REPORT_FORMAT_H */
