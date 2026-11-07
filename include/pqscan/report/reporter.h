/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_REPORT_REPORTER_H
#define PQSCAN_REPORT_REPORTER_H

#include "pqscan/core/finding.h"
#include "pqscan/core/skip_list.h"
#include "pqscan/core/status.h"

#include <stdio.h>

/** What a finished run has to say. Everything is borrowed for the duration of a write. */
typedef struct scan_report {
    const finding_list *findings; /**< What was found. */
    const skip_list *skipped;     /**< What is in scope but was not analyzed. */
} scan_report;

/** One output format. Reporters only consume findings, and know nothing about scanners. */
typedef struct reporter {
    const char *name;

    /**
     * @brief Write a report and flush the stream.
     *
     * @param report What to write. Not modified.
     * @param out The stream to write to. Stays open and owned by the caller.
     * @return PQSCAN_OK, or PQSCAN_ERR_IO if writing or flushing failed.
     */
    pqscan_status (*write)(const scan_report *report, FILE *out);
} reporter;

#endif /* PQSCAN_REPORT_REPORTER_H */
