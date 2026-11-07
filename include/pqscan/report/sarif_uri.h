/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_REPORT_SARIF_URI_H
#define PQSCAN_REPORT_SARIF_URI_H

#include "pqscan/report/json_writer.h"

/**
 * @brief Write a path as the JSON string SARIF expects in artifactLocation.uri.
 *
 * SARIF wants a URI reference, not a file name. Every byte that is not plain in a URI is
 * percent-encoded, which keeps the path exact whatever its bytes are. A leading "./" is
 * dropped, because code scanning matches results against paths from the repository root. An
 * absolute path becomes a file:// URI.
 *
 * @param json The writer.
 * @param path The path, NUL-terminated.
 */
void sarif_write_uri(json_writer *json, const char *path);

#endif /* PQSCAN_REPORT_SARIF_URI_H */
