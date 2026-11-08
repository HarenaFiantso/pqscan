/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_BASELINE_BASELINE_WRITER_H
#define PQSCAN_BASELINE_BASELINE_WRITER_H

#include "pqscan/core/finding.h"
#include "pqscan/core/status.h"

#include <stdio.h>

/**
 * @brief Write a baseline that accepts every finding of a list, and flush the stream.
 *
 * Identical findings become one entry with a count, and entries are sorted, so the file only
 * changes when the findings do, whatever order they were found in and whatever their lines.
 *
 * @param findings The findings. Not modified.
 * @param out The stream. Stays open and owned by the caller.
 * @return PQSCAN_OK, PQSCAN_ERR_NOMEM, or PQSCAN_ERR_IO if writing or flushing failed.
 */
pqscan_status baseline_write(const finding_list *findings, FILE *out);

#endif /* PQSCAN_BASELINE_BASELINE_WRITER_H */
