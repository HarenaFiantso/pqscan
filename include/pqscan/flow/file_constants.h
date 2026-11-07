/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_FLOW_FILE_CONSTANTS_H
#define PQSCAN_FLOW_FILE_CONSTANTS_H

#include "pqscan/core/status.h"
#include "pqscan/flow/constant_table.h"
#include "pqscan/flow/flow_source.h"

#include <tree_sitter/api.h>

/**
 * @brief Record the object-like macros and the constants at file scope of a whole file.
 *
 * A name that cannot be trusted across the file is bound to an unknown value, so that it
 * still hides nothing: one with two different definitions, one defined inside a conditional
 * other than the include guard, a macro with parameters, and anything named by #undef.
 *
 * @param source The file.
 * @param root The root of its tree.
 * @param table Where to bind the names.
 * @return PQSCAN_OK, PQSCAN_ERR_NOMEM, or PQSCAN_ERR_PARSE past the deadline.
 */
pqscan_status file_constants_collect(const flow_source *source, TSNode root, constant_table *table);

#endif /* PQSCAN_FLOW_FILE_CONSTANTS_H */
