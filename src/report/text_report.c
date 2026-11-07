/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/report/text_report.h"

#include "pqscan/core/finding.h"
#include "pqscan/core/key_size.h"
#include "pqscan/core/safe_text.h"
#include "pqscan/core/status.h"
#include "pqscan/report/reporter.h"
#include "pqscan/risk/risk.h"

#include <stddef.h>
#include <stdio.h>

static pqscan_status write_text(const scan_report *report, FILE *out) {
    const finding_list *findings = report->findings;
    for (size_t i = 0; i < finding_list_count(findings); i++) {
        const finding *item = finding_list_get(findings, i);
        char key_suffix[KEY_SIZE_SUFFIX_SIZE];
        key_size_format_suffix(item->size, key_suffix, sizeof(key_suffix));
        if (safe_text_write(out, item->path) != PQSCAN_OK) {
            return PQSCAN_ERR_IO;
        }
        const int written = fprintf(out, ":%zu: %s%s (%s)\n", item->line, item->algorithm,
                                    key_suffix, risk_level_name(item->risk));
        if (written < 0) {
            return PQSCAN_ERR_IO;
        }
    }
    return (fflush(out) == 0) ? PQSCAN_OK : PQSCAN_ERR_IO;
}

const reporter text_reporter = {"text", write_text};
