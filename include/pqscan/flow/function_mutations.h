/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_FLOW_FUNCTION_MUTATIONS_H
#define PQSCAN_FLOW_FUNCTION_MUTATIONS_H

#include "pqscan/core/status.h"
#include "pqscan/flow/constant_table.h"
#include "pqscan/flow/flow_source.h"

#include <tree_sitter/api.h>

/** The tables that function_mutations_collect() reads and writes. */
typedef struct mutation_tables {
    const constant_table *bindings; /**< What the names of the file stand for. Not modified. */
    constant_table *mutations;      /**< Where to bind the names that were found. */
} mutation_tables;

/**
 * @brief Find every local in a function whose value can stop following the code in order.
 *
 * Each name is bound in the innermost scope of the mutations table, with as its position the offset
 * from which the variable can no longer be trusted. A plain x = 1 in straight-line code stays
 * trustworthy and is bound with UINT32_MAX, which evaluation follows instead.
 *
 * - Written in a branch: from that write onward.
 * - Written in a loop or a lambda: from the start of it, since a later iteration or call can
 *   reach a use that comes earlier in the text.
 * - Changed by +=, ++, its address, a C++ reference, or a C++ call that may take a reference.
 * - Passed to a C macro, which is what an all-caps name or a macro with parameters of this
 *   file is taken to be: unlike a function, it can write what it is given. A lowercase macro
 *   from a header cannot be told from a function, and neither can a macro's use of a local
 *   it does not receive as an argument.
 * - In a function with a label, every write counts from the start of the function.
 *
 * @param source The file.
 * @param function A function_definition or lambda_expression node.
 * @param tables The tables.
 * @return PQSCAN_OK, PQSCAN_ERR_NOMEM, or PQSCAN_ERR_PARSE past the deadline.
 */
pqscan_status function_mutations_collect(const flow_source *source, TSNode function,
                                         const mutation_tables *tables);

#endif /* PQSCAN_FLOW_FUNCTION_MUTATIONS_H */
