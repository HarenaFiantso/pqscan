/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/report/text_report.h"

#include "pqscan/core/finding.h"
#include "pqscan/core/status.h"
#include "pqscan/report/reporter.h"
#include "pqscan/risk/risk.h"

#include <stddef.h>
#include <stdio.h>

static pqscan_status write_text(const finding_list *findings, FILE *out) {
    for (size_t i = 0; i < finding_list_count(findings); i++) {
        const finding *item = finding_list_get(findings, i);
        const int written = fprintf(out, "%s:%zu: %s (%s)\n", item->path, item->line,
                                    item->algorithm, risk_level_name(item->risk));
        if (written < 0) {
            return PQSCAN_ERR_IO;
        }
    }
    return (fflush(out) == 0) ? PQSCAN_OK : PQSCAN_ERR_IO;
}

const reporter text_reporter = {"text", write_text};
