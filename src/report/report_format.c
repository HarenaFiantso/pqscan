/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/report/report_format.h"

#include "pqscan/report/json_report.h"
#include "pqscan/report/reporter.h"
#include "pqscan/report/sarif_report.h"
#include "pqscan/report/text_report.h"

#include <stddef.h>
#include <string.h>

static const reporter *const REPORTERS[] = {&text_reporter, &json_reporter, &sarif_reporter};

const reporter *reporter_find(const char *name) {
    for (size_t i = 0; i < sizeof(REPORTERS) / sizeof(REPORTERS[0]); i++) {
        if (strcmp(name, REPORTERS[i]->name) == 0) {
            return REPORTERS[i];
        }
    }
    return NULL;
}
