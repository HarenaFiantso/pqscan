/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/scan/call_arguments.h"

#include "pqscan/core/key_size.h"
#include "pqscan/flow/constant_flow.h"
#include "pqscan/flow/constant_table.h"
#include "pqscan/scan/syntax_parser.h"

#include <limits.h>
#include <stdbool.h>
#include <tree_sitter/api.h>

static bool find_argument(const call_argument *argument, TSNode *out) {
    const TSNode arguments = syntax_node_field(argument->call, "arguments");
    return !ts_node_is_null(arguments) && syntax_named_child(arguments, argument->index, out);
}

key_size call_key_size(const call_argument *argument, const constant_flow *flow) {
    key_size size = {KEY_SIZE_NOT_APPLICABLE, 0};
    TSNode expression;
    if (!find_argument(argument, &expression)) {
        return size;
    }
    const constant_value value = constant_flow_evaluate(flow, expression);
    if (value.kind == CONSTANT_STRING ||
        syntax_node_is(syntax_strip_parentheses(expression), "string_literal")) {
        return size;
    }
    const bool known = value.kind == CONSTANT_INTEGER && value.integer <= UINT_MAX;
    size.kind = known ? KEY_SIZE_KNOWN : KEY_SIZE_UNKNOWN;
    size.bits = known ? (unsigned)value.integer : 0;
    return size;
}

bool call_string_argument(const call_argument *argument, const constant_flow *flow,
                          string_argument *out) {
    TSNode expression;
    if (!find_argument(argument, &expression)) {
        return false;
    }
    const constant_value value = constant_flow_evaluate(flow, expression);
    if (value.kind != CONSTANT_STRING) {
        return false;
    }
    out->node = syntax_strip_parentheses(expression);
    out->text = value.text;
    return true;
}
