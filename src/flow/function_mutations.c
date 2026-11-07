/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/flow/function_mutations.h"

#include "pqscan/core/status.h"
#include "pqscan/flow/constant_table.h"
#include "pqscan/flow/flow_source.h"
#include "pqscan/scan/syntax_parser.h"
#include "pqscan/walk/file_type.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <tree_sitter/api.h>

static const char *const LOOP_TYPES[] = {
    "do_statement", "for_range_loop", "for_statement", "while_statement", "lambda_expression",
};
static const char *const BRANCH_TYPES[] = {
    "conditional_expression", "if_statement",     "preproc_if",
    "preproc_ifdef",          "switch_statement", "try_statement",
};
static const uint32_t NEVER = UINT32_MAX;

/* A nested construct always ends inside the outermost one, so one offset covers them all. */
typedef struct mutation_scan {
    const flow_source *source;
    constant_table *mutations;
    uint32_t function_start;
    uint32_t loop_start;
    uint32_t loop_end;
    uint32_t branch_end;
    uint32_t preproc_end;
    bool has_label;
} mutation_scan;

static bool is_one_of(TSNode node, const char *const *types, size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (syntax_node_is(node, types[i])) {
            return true;
        }
    }
    return false;
}

static syntax_text text_of(const mutation_scan *scan, TSNode node) {
    return syntax_node_text(node, scan->source->file);
}

static bool in_loop(const mutation_scan *scan, TSNode node) {
    return ts_node_start_byte(node) < scan->loop_end;
}

static bool in_branch(const mutation_scan *scan, TSNode node) {
    return ts_node_start_byte(node) < scan->branch_end;
}

static pqscan_status mark(const mutation_scan *scan, TSNode name, uint32_t position) {
    const syntax_text text = text_of(scan, name);
    constant_binding *known = constant_table_find(scan->mutations, text);
    if (known != NULL) {
        known->position = (position < known->position) ? position : known->position;
        return PQSCAN_OK;
    }
    constant_binding binding;
    memset(&binding, 0, sizeof(binding));
    binding.name = text;
    binding.position = position;
    return constant_table_bind(scan->mutations, &binding);
}

/* The variable is changed by this node, so it cannot be trusted from here on. */
static pqscan_status mark_changed(const mutation_scan *scan, TSNode name, uint32_t position) {
    if (!syntax_node_is(name, "identifier")) {
        return PQSCAN_OK;
    }
    return mark(scan, name, in_loop(scan, name) ? scan->loop_start : position);
}

static pqscan_status visit_assignment(const mutation_scan *scan, TSNode node) {
    const TSNode left = syntax_node_field(node, "left");
    const TSNode operator_node = syntax_node_field(node, "operator");
    const uint32_t position = ts_node_start_byte(node);
    const bool plain = syntax_text_is(text_of(scan, operator_node), "=");
    if (plain && !in_loop(scan, node) && !in_branch(scan, node)) {
        return syntax_node_is(left, "identifier") ? mark(scan, left, NEVER) : PQSCAN_OK;
    }
    return mark_changed(scan, left, position);
}

static pqscan_status visit_pointer(const mutation_scan *scan, TSNode node) {
    const TSNode operator_node = syntax_node_field(node, "operator");
    if (!syntax_text_is(text_of(scan, operator_node), "&")) {
        return PQSCAN_OK;
    }
    return mark_changed(scan, syntax_node_field(node, "argument"), ts_node_start_byte(node));
}

/* Declarations in #ifdef branches share one block, so the last one is not the one in force. */
static pqscan_status visit_init_declarator(const mutation_scan *scan, TSNode node) {
    const TSNode declarator = syntax_node_field(node, "declarator");
    if (syntax_node_is(declarator, "reference_declarator")) {
        return mark_changed(scan, syntax_node_field(node, "value"), ts_node_start_byte(node));
    }
    if (ts_node_start_byte(node) < scan->preproc_end) {
        return mark_changed(scan, declarator, ts_node_start_byte(node));
    }
    return PQSCAN_OK;
}

/* C++ may bind any argument to a non-const reference, which the call does not show. The
 * call itself still reads the old value, so the variable is lost only after it. */
static pqscan_status visit_cpp_arguments(const mutation_scan *scan, TSNode node) {
    TSTreeCursor cursor = ts_tree_cursor_new(node);
    const uint32_t end = ts_node_end_byte(node);
    pqscan_status status = PQSCAN_OK;
    bool more = ts_tree_cursor_goto_first_child(&cursor);
    while (more && status == PQSCAN_OK) {
        status = mark_changed(scan, ts_tree_cursor_current_node(&cursor), end);
        more = ts_tree_cursor_goto_next_sibling(&cursor);
    }
    ts_tree_cursor_delete(&cursor);
    return status;
}

static void enter_branch(mutation_scan *scan, TSNode node) {
    const uint32_t end = ts_node_end_byte(node);
    scan->branch_end = (end > scan->branch_end) ? end : scan->branch_end;
}

static void enter_loop(mutation_scan *scan, TSNode node) {
    if (!in_loop(scan, node)) {
        scan->loop_start = ts_node_start_byte(node);
        scan->loop_end = ts_node_end_byte(node);
    }
}

static void enter_preproc(mutation_scan *scan, TSNode node) {
    const uint32_t end = ts_node_end_byte(node);
    scan->preproc_end = (end > scan->preproc_end) ? end : scan->preproc_end;
}

static pqscan_status visit_binary(mutation_scan *scan, TSNode node) {
    const syntax_text operator_text = text_of(scan, syntax_node_field(node, "operator"));
    if (syntax_text_is(operator_text, "&&") || syntax_text_is(operator_text, "||")) {
        enter_branch(scan, node);
    }
    const bool cpp_stream =
        scan->source->language == SOURCE_LANGUAGE_CPP && syntax_text_is(operator_text, ">>");
    return cpp_stream ? mark_changed(scan, syntax_node_field(node, "right"), ts_node_end_byte(node))
                      : PQSCAN_OK;
}

static void enter_region(mutation_scan *scan, TSNode node) {
    if (is_one_of(node, LOOP_TYPES, sizeof(LOOP_TYPES) / sizeof(LOOP_TYPES[0]))) {
        enter_loop(scan, node);
    } else if (is_one_of(node, BRANCH_TYPES, sizeof(BRANCH_TYPES) / sizeof(BRANCH_TYPES[0]))) {
        enter_branch(scan, node);
        if (syntax_node_is(node, "preproc_if") || syntax_node_is(node, "preproc_ifdef")) {
            enter_preproc(scan, node);
        }
    } else if (syntax_node_is(node, "labeled_statement")) {
        scan->has_label = true;
    }
}

static pqscan_status visit_node(void *context, TSNode node) {
    mutation_scan *scan = context;
    enter_region(scan, node);
    if (syntax_node_is(node, "assignment_expression")) {
        return visit_assignment(scan, node);
    }
    if (syntax_node_is(node, "update_expression")) {
        return mark_changed(scan, syntax_node_field(node, "argument"), ts_node_start_byte(node));
    }
    if (syntax_node_is(node, "pointer_expression")) {
        return visit_pointer(scan, node);
    }
    if (syntax_node_is(node, "init_declarator")) {
        return visit_init_declarator(scan, node);
    }
    if (syntax_node_is(node, "binary_expression")) {
        return visit_binary(scan, node);
    }
    const bool cpp = scan->source->language == SOURCE_LANGUAGE_CPP;
    return (cpp && syntax_node_is(node, "argument_list")) ? visit_cpp_arguments(scan, node)
                                                          : PQSCAN_OK;
}

pqscan_status function_mutations_collect(const flow_source *source, TSNode function,
                                         constant_table *mutations) {
    mutation_scan scan = {
        source, mutations, ts_node_start_byte(function), 0, 0, 0, 0, false,
    };
    const syntax_walk_spec spec = {visit_node, &scan, source->parser};
    const pqscan_status status = syntax_walk(function, &spec);
    if (status == PQSCAN_OK && scan.has_label) {
        constant_table_set_scope_position(mutations, scan.function_start);
    }
    return status;
}
