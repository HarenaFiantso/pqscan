/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_SCAN_SCANNER_H
#define PQSCAN_SCAN_SCANNER_H

#include "pqscan/core/finding.h"
#include "pqscan/core/status.h"
#include "pqscan/rules/rule_set.h"
#include "pqscan/scan/file_reader.h"

#include <stdbool.h>

/** What one file needs to be scanned. Everything is borrowed for the duration of the call. */
typedef struct scan_input {
    const char *path;          /**< The path to record in findings. */
    const file_contents *file; /**< The contents. Not modified. */
    const rule_set *rules;     /**< A sealed set, which must outlive the findings. */
} scan_input;

/** One kind of input. Scanners only produce findings, and know nothing about reports. */
typedef struct scanner {
    const char *name;

    /**
     * @brief Tell whether this scanner handles a file.
     *
     * @param path The path. It is not opened.
     * @return true if the file should be passed to scan.
     */
    bool (*accepts)(const char *path);

    /**
     * @brief Add the findings of one file to a list.
     *
     * @param input The file and the rules.
     * @param findings Where to add findings.
     * @return PQSCAN_OK, PQSCAN_ERR_NOMEM, or a status explaining why the file was skipped.
     */
    pqscan_status (*scan)(const scan_input *input, finding_list *findings);
} scanner;

#endif /* PQSCAN_SCAN_SCANNER_H */
