/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_FLOW_FUNCTION_MUTATIONS_H
#define PQSCAN_FLOW_FUNCTION_MUTATIONS_H

#include "pqscan/core/status.h"
#include "pqscan/flow/constant_table.h"
#include "pqscan/flow/flow_source.h"

#include <tree_sitter/api.h>

/**
 * @brief Find every local in a function whose value can stop following the code in order.
 *
 * Each name is bound in the innermost scope of @p mutations, with as its position the offset
 * from which the variable can no longer be trusted. A plain x = 1 in straight-line code stays
 * trustworthy and is bound with UINT32_MAX, which evaluation follows instead.
 *
 * - Written in a branch: from that write onward.
 * - Written in a loop or a lambda: from the start of it, since a later iteration or call can
 *   reach a use that comes earlier in the text.
 * - Changed by +=, ++, its address, a C++ reference, or a C++ call that may take a reference.
 * - In a function with a label, every write counts from the start of the function.
 *
 * @param source The file.
 * @param function A function_definition or lambda_expression node.
 * @param mutations Where to bind the names.
 * @return PQSCAN_OK, PQSCAN_ERR_NOMEM, or PQSCAN_ERR_PARSE past the deadline.
 */
pqscan_status function_mutations_collect(const flow_source *source, TSNode function,
                                         constant_table *mutations);

#endif /* PQSCAN_FLOW_FUNCTION_MUTATIONS_H */
