/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_FLOW_CONSTANT_FLOW_H
#define PQSCAN_FLOW_CONSTANT_FLOW_H

#include "pqscan/core/status.h"
#include "pqscan/flow/constant_table.h"
#include "pqscan/flow/flow_source.h"

#include <tree_sitter/api.h>

/**
 * What the names of one file mean at the point a walk has reached. It stays intra-file, and a
 * value that cannot be proved is CONSTANT_UNKNOWN, never a guess.
 *
 * Use: constant_flow_collect_file() once, then constant_flow_visit() on every node in source
 * order, and constant_flow_evaluate() on the way.
 */
typedef struct constant_flow constant_flow;

/**
 * @brief Create the state for one file.
 *
 * @param source The file. The struct is copied, and what it points at must outlive the flow.
 * @param out On success, the state, owned by the caller and freed with constant_flow_destroy().
 *            Untouched on failure.
 * @return PQSCAN_OK, or PQSCAN_ERR_NOMEM.
 */
pqscan_status constant_flow_create(const flow_source *source, constant_flow **out);

/**
 * @brief Free the state of a file.
 *
 * @param flow The state to free. May be NULL.
 */
void constant_flow_destroy(constant_flow *flow);

/**
 * @brief Learn the macros and constants of a file before the walk starts.
 *
 * @param flow The state.
 * @param root The root of the tree, which must outlive the flow.
 * @return PQSCAN_OK, PQSCAN_ERR_NOMEM, or PQSCAN_ERR_PARSE past the deadline.
 */
pqscan_status constant_flow_collect_file(constant_flow *flow, TSNode root);

/**
 * @brief Move the walk to a node, updating scopes and locals.
 *
 * @param flow The state.
 * @param node The node, reached in source order.
 * @return PQSCAN_OK, PQSCAN_ERR_NOMEM, or PQSCAN_ERR_PARSE past the deadline.
 */
pqscan_status constant_flow_visit(constant_flow *flow, TSNode node);

/**
 * @brief Say whether the walk is inside the body of a macro.
 *
 * Such code runs wherever the macro expands, where a local could hide any name, so only
 * macros resolve there. While inside, constant_flow_visit() does nothing.
 *
 * @param flow The state.
 * @param in_macro_body true on entering a body, false on leaving it.
 */
void constant_flow_set_macro_body(constant_flow *flow, bool in_macro_body);

/**
 * @brief Work out the value of an expression at the point the walk has reached.
 *
 * @param flow The state.
 * @param expression The expression.
 * @return The value. See constant_eval().
 */
constant_value constant_flow_evaluate(const constant_flow *flow, TSNode expression);

#endif /* PQSCAN_FLOW_CONSTANT_FLOW_H */
