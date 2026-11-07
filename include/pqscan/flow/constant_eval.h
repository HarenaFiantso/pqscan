/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_FLOW_CONSTANT_EVAL_H
#define PQSCAN_FLOW_CONSTANT_EVAL_H

#include "pqscan/flow/constant_table.h"
#include "pqscan/flow/flow_source.h"

#include <stdbool.h>
#include <tree_sitter/api.h>

/** What names mean at the point being evaluated. Everything is borrowed. */
typedef struct eval_env {
    const flow_source *source;
    const constant_table *bindings;
    const constant_table *mutations; /**< Names mapped to where they stop being reliable. */
    bool in_macro_body; /**< The code will expand elsewhere, so only macros can be trusted. */
} eval_env;

/**
 * @brief Work out the value of an expression, if it can be known for certain.
 *
 * Literals, names and +, -, * and << on integers resolve, through casts and parentheses.
 * Anything else, including any overflow, gives CONSTANT_UNKNOWN. Macro chains and the size
 * of an expression are bounded, so a hostile file cannot make this slow or deep.
 *
 * @param env What names mean.
 * @param expression The expression.
 * @return The value. A string borrows its bytes from the file.
 */
constant_value constant_eval(const eval_env *env, TSNode expression);

#endif /* PQSCAN_FLOW_CONSTANT_EVAL_H */
