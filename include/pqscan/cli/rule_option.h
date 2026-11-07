/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_CLI_RULE_OPTION_H
#define PQSCAN_CLI_RULE_OPTION_H

#include "pqscan/rules/rule_set.h"

/**
 * @brief Load the rules a run asked for, and explain any failure on stderr.
 *
 * @param path The file given to --rules, or NULL for the rules built into the binary.
 * @param out On success, the rules, owned by the caller and freed with rule_set_destroy().
 *            Untouched on failure.
 * @return PQSCAN_EXIT_CLEAN, PQSCAN_EXIT_USAGE if the file cannot be used, or
 *         PQSCAN_EXIT_INTERNAL if memory runs out or the built-in rules are invalid.
 */
int cli_load_rules(const char *path, rule_set **out);

#endif /* PQSCAN_CLI_RULE_OPTION_H */
