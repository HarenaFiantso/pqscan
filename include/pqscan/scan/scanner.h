/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_SCAN_SCANNER_H
#define PQSCAN_SCAN_SCANNER_H

#include "pqscan/core/finding.h"
#include "pqscan/core/status.h"
#include "pqscan/scan/file_reader.h"

#include <stdbool.h>

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
     * @param path The path to record in findings.
     * @param file The contents. Not modified.
     * @param findings Where to add findings.
     * @return PQSCAN_OK, PQSCAN_ERR_NOMEM, or a status explaining why the file was skipped.
     */
    pqscan_status (*scan)(const char *path, const file_contents *file, finding_list *findings);
} scanner;

#endif /* PQSCAN_SCAN_SCANNER_H */
