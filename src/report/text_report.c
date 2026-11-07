/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/report/text_report.h"

#include "pqscan/core/finding.h"
#include "pqscan/core/key_size.h"
#include "pqscan/core/safe_text.h"
#include "pqscan/core/status.h"
#include "pqscan/report/report_summary.h"
#include "pqscan/report/reporter.h"
#include "pqscan/risk/risk.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

static pqscan_status write_finding(const finding *item, FILE *out) {
    char key_suffix[KEY_SIZE_SUFFIX_SIZE];
    key_size_format_suffix(item->size, key_suffix, sizeof(key_suffix));
    if (safe_text_write(out, item->path) != PQSCAN_OK || fprintf(out, ":%zu: ", item->line) < 0 ||
        safe_text_write(out, item->algorithm) != PQSCAN_OK ||
        fprintf(out, "%s (%s)\n", key_suffix, risk_level_name(item->risk)) < 0) {
        return PQSCAN_ERR_IO;
    }
    return PQSCAN_OK;
}

/* Most severe first, because that is what a reader acts on. Levels with no finding are left
 * out, and so is the whole line for a clean scan, which stays silent. */
static pqscan_status write_summary(const finding_list *findings, FILE *out) {
    const size_t total = finding_list_count(findings);
    if (total == 0) {
        return PQSCAN_OK;
    }
    const risk_counts counts = risk_counts_of(findings);
    bool failed = fprintf(out, "%zu finding%s", total, (total == 1) ? "" : "s") < 0;
    const char *separator = ": ";
    for (int level = RISK_LEVEL_COUNT - 1; level >= RISK_OK; level--) {
        if (counts.by_level[level] > 0) {
            failed = failed || fprintf(out, "%s%zu %s", separator, counts.by_level[level],
                                       risk_level_name((risk_level)level)) < 0;
            separator = ", ";
        }
    }
    return (failed || fputc('\n', out) == EOF) ? PQSCAN_ERR_IO : PQSCAN_OK;
}

static pqscan_status write_text(const scan_report *report, FILE *out) {
    const finding_list *findings = report->findings;
    for (size_t i = 0; i < finding_list_count(findings); i++) {
        if (write_finding(finding_list_get(findings, i), out) != PQSCAN_OK) {
            return PQSCAN_ERR_IO;
        }
    }
    if (write_summary(findings, out) != PQSCAN_OK) {
        return PQSCAN_ERR_IO;
    }
    return (fflush(out) == 0) ? PQSCAN_OK : PQSCAN_ERR_IO;
}

const reporter text_reporter = {"text", write_text};
