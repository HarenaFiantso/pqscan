/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_RULES_DEFAULT_RULES_H
#define PQSCAN_RULES_DEFAULT_RULES_H

#include "pqscan/rules/rule_loader.h"

/**
 * @brief Get the text of rules/default.json, which the build embeds in the binary.
 *
 * @return The text, which has static storage duration. It is not NUL-terminated.
 */
rule_source default_rules_source(void);

#endif /* PQSCAN_RULES_DEFAULT_RULES_H */
