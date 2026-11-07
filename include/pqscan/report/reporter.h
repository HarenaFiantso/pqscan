/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_REPORT_REPORTER_H
#define PQSCAN_REPORT_REPORTER_H

#include "pqscan/core/finding.h"
#include "pqscan/core/status.h"

#include <stdio.h>

/** One output format. Reporters only consume findings, and know nothing about scanners. */
typedef struct reporter {
    const char *name;

    /**
     * @brief Write findings and flush the stream.
     *
     * @param findings The findings. Not modified.
     * @param out The stream to write to. Stays open and owned by the caller.
     * @return PQSCAN_OK, or PQSCAN_ERR_IO if writing or flushing failed.
     */
    pqscan_status (*write)(const finding_list *findings, FILE *out);
} reporter;

#endif /* PQSCAN_REPORT_REPORTER_H */
