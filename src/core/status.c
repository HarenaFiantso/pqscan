/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/status.h"

const char *pqscan_status_message(pqscan_status status) {
    switch (status) {
    case PQSCAN_OK:
        return "success";
    case PQSCAN_ERR_NOMEM:
        return "out of memory";
    case PQSCAN_ERR_IO:
        return "cannot read";
    case PQSCAN_ERR_NOT_FOUND:
        return "no such file or directory";
    case PQSCAN_ERR_NOT_REGULAR:
        return "skipped, not a regular file or directory";
    case PQSCAN_ERR_TOO_LARGE:
        return "skipped, file too large";
    case PQSCAN_ERR_BINARY:
        return "skipped, binary file";
    case PQSCAN_ERR_PARSE:
        return "skipped, cannot parse source in time";
    case PQSCAN_ERR_RULES:
        return "invalid rules";
    case PQSCAN_ERR_BUDGET:
        return "skipped, scan time budget used up";
    case PQSCAN_ERR_ENCRYPTED:
        return "skipped, encrypted key";
    case PQSCAN_ERR_MALFORMED:
        return "skipped, not a certificate or key that can be read";
    case PQSCAN_ERR_ELF_MALFORMED:
        return "skipped, malformed ELF file";
    case PQSCAN_ERR_ELF_UNSUPPORTED:
        return "skipped, not a 64-bit ELF file";
    case PQSCAN_ERR_ELF_NO_SYMBOLS:
        return "skipped, ELF file without a symbol table";
    case PQSCAN_ERR_PROJECT:
        return "invalid project file";
    case PQSCAN_ERR_BASELINE:
        return "invalid baseline";
    }
    return "unknown status";
}
