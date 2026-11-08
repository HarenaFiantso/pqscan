/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_BASELINE_BASELINE_H
#define PQSCAN_BASELINE_BASELINE_H

#include "pqscan/core/finding.h"
#include "pqscan/core/json_fields.h"
#include "pqscan/core/status.h"

#include <stddef.h>

/** The text of a baseline file. It need not be NUL-terminated. */
typedef struct baseline_source {
    const char *text;
    size_t len;
} baseline_source;

/**
 * The findings a project has accepted, each with how many times it may occur.
 *
 * A baseline is used up as it matches: each finding it accepts takes one of the occurrences of
 * its entry, so a file that gains a second identical call has one new finding.
 */
typedef struct baseline baseline;

/**
 * @brief Read a baseline from the JSON text that baseline_write() produces.
 *
 * Validation is as strict as for rules: an unknown field, a wrong type or an out-of-range
 * value refuses the whole file, because a typo would otherwise hide or accept findings.
 *
 * @param source The text.
 * @param out On success, the baseline, owned by the caller and freed with baseline_destroy().
 *            Untouched on failure.
 * @param error Out: on PQSCAN_ERR_BASELINE, what is wrong. Empty otherwise.
 * @return PQSCAN_OK, PQSCAN_ERR_NOMEM or PQSCAN_ERR_BASELINE.
 */
pqscan_status baseline_load(const baseline_source *source, baseline **out, json_error *error);

/**
 * @brief Free a baseline.
 *
 * @param accepted The baseline. May be NULL.
 */
void baseline_destroy(baseline *accepted);

/**
 * @brief Remove from a list the findings the baseline accepts, and use up their occurrences.
 *
 * Findings are matched in list order, so when a file has more identical findings than the
 * baseline accepts, the last ones are the ones left in the list.
 *
 * @param accepted The baseline.
 * @param findings The list. What is left is the findings the baseline does not accept.
 * @return The number of findings removed.
 */
size_t baseline_remove_accepted(baseline *accepted, finding_list *findings);

/**
 * @brief Count the occurrences no finding has used, such as calls that were since removed.
 *
 * @param accepted The baseline.
 * @return The count, or SIZE_MAX if it does not fit.
 */
size_t baseline_unused(const baseline *accepted);

#endif /* PQSCAN_BASELINE_BASELINE_H */
