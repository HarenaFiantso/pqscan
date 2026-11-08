/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_RULES_RULE_LOADER_H
#define PQSCAN_RULES_RULE_LOADER_H

#include "pqscan/core/json_fields.h"
#include "pqscan/core/status.h"
#include "pqscan/rules/rule_set.h"

#include <stddef.h>

/** The text of a rule file. It need not be NUL-terminated. */
typedef struct rule_source {
    const char *text;
    size_t len;
} rule_source;

/** Why a rule file was refused. */
typedef json_error rule_error;

/**
 * @brief Build a sealed rule set from the JSON text of a rule file.
 *
 * Validation is strict: an unknown field, a wrong type or an out-of-range value refuses the
 * whole file, because a rule silently dropped is a finding silently missed. Names must be
 * printable ASCII, so reports and messages can print them without escaping.
 *
 * @param source The text.
 * @param out On success, the set, owned by the caller and freed with rule_set_destroy().
 *            Untouched on failure.
 * @param error Out: on PQSCAN_ERR_RULES, what is wrong. Empty otherwise.
 * @return PQSCAN_OK, PQSCAN_ERR_NOMEM or PQSCAN_ERR_RULES.
 */
pqscan_status rule_set_load(const rule_source *source, rule_set **out, rule_error *error);

#endif /* PQSCAN_RULES_RULE_LOADER_H */
