/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_CLI_BASELINE_OPTION_H
#define PQSCAN_CLI_BASELINE_OPTION_H

#include "pqscan/baseline/baseline.h"
#include "pqscan/core/finding.h"

/**
 * @brief Load the baseline given to --diff, and explain any failure on stderr.
 *
 * Unlike a project file, a baseline is never looked for on its own: one found by accident
 * would hide findings.
 *
 * @param path The file given to --diff, or NULL.
 * @param out On success, the baseline, owned by the caller and freed with baseline_destroy(),
 *            or NULL if @p path is NULL. Untouched on failure.
 * @return PQSCAN_EXIT_CLEAN, PQSCAN_EXIT_USAGE if the file cannot be read or used, or
 *         PQSCAN_EXIT_INTERNAL if memory runs out.
 */
int cli_load_baseline(const char *path, baseline **out);

/**
 * @brief Keep only the findings a baseline does not accept, and say on stderr how many
 *        findings it accepts were not found, as those entries are stale.
 *
 * @param path The baseline file, to name it in the message.
 * @param accepted The baseline. Its occurrences are used up.
 * @param findings The findings of the run.
 */
void cli_diff_against_baseline(const char *path, baseline *accepted, finding_list *findings);

/**
 * @brief Replace a file with a baseline that accepts every finding, and say so on stderr.
 *
 * @param path The file given to --write-baseline. Created if it does not exist.
 * @param findings The findings of the run.
 * @return PQSCAN_EXIT_CLEAN, PQSCAN_EXIT_USAGE if the file cannot be created, or
 *         PQSCAN_EXIT_INTERNAL if writing it fails.
 */
int cli_write_baseline(const char *path, const finding_list *findings);

#endif /* PQSCAN_CLI_BASELINE_OPTION_H */
