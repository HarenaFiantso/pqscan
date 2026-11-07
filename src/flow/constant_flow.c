/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/flow/constant_flow.h"

#include "pqscan/core/status.h"
#include "pqscan/flow/constant_eval.h"
#include "pqscan/flow/constant_table.h"
#include "pqscan/flow/declarations.h"
#include "pqscan/flow/file_constants.h"
#include "pqscan/flow/flow_source.h"
#include "pqscan/flow/function_mutations.h"
#include "pqscan/scan/syntax_parser.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <tree_sitter/api.h>

struct constant_flow {
    flow_source source;
    constant_table *bindings;
    constant_table *mutations;
    uint32_t function_end; /* Locals are only tracked before this offset. */
    bool in_macro_body;
};

typedef pqscan_status (*node_handler)(constant_flow *flow, TSNode node);

typedef struct handler_entry {
    const char *type;
    node_handler handle;
} handler_entry;

pqscan_status constant_flow_create(const flow_source *source, constant_flow **out) {
    constant_flow *flow = calloc(1, sizeof(constant_flow));
    if (flow == NULL) {
        return PQSCAN_ERR_NOMEM;
    }
    flow->source = *source;
    flow->bindings = constant_table_create();
    flow->mutations = constant_table_create();
    if (flow->bindings == NULL || flow->mutations == NULL) {
        constant_flow_destroy(flow);
        return PQSCAN_ERR_NOMEM;
    }
    *out = flow;
    return PQSCAN_OK;
}

void constant_flow_destroy(constant_flow *flow) {
    if (flow == NULL) {
        return;
    }
    constant_table_destroy(flow->mutations);
    constant_table_destroy(flow->bindings);
    free(flow);
}

pqscan_status constant_flow_collect_file(constant_flow *flow, TSNode root) {
    return file_constants_collect(&flow->source, root, flow->bindings);
}

void constant_flow_set_macro_body(constant_flow *flow, bool in_macro_body) {
    flow->in_macro_body = in_macro_body;
}

constant_value constant_flow_evaluate(const constant_flow *flow, TSNode expression) {
    const eval_env env = {&flow->source, flow->bindings, flow->mutations, flow->in_macro_body};
    return constant_eval(&env, expression);
}

static bool in_function(const constant_flow *flow, TSNode node) {
    return ts_node_start_byte(node) < flow->function_end;
}

static pqscan_status bind_local(const constant_flow *flow, TSNode name, constant_value value) {
    constant_binding binding;
    memset(&binding, 0, sizeof(binding));
    binding.name = syntax_node_text(name, flow->source.file);
    binding.value = value;
    return constant_table_bind(flow->bindings, &binding);
}

static const constant_value UNKNOWN_VALUE = {CONSTANT_UNKNOWN, 0, {"", 0}};

static pqscan_status open_node_scope(const constant_flow *flow, TSNode node) {
    return constant_table_open_scope(flow->bindings, ts_node_end_byte(node));
}

static pqscan_status enter_function(constant_flow *flow, TSNode node) {
    if (!in_function(flow, node)) {
        const uint32_t end = ts_node_end_byte(node);
        const pqscan_status status = constant_table_open_scope(flow->mutations, end);
        if (status != PQSCAN_OK) {
            return status;
        }
        flow->function_end = end;
        const pqscan_status collected =
            function_mutations_collect(&flow->source, node, flow->mutations);
        if (collected != PQSCAN_OK) {
            return collected;
        }
    }
    return open_node_scope(flow, node);
}

/* Every handler shares one signature, even one that does not modify the flow. */
// cppcheck-suppress constParameterCallback
// cppcheck-suppress constParameterPointer
static pqscan_status enter_block(constant_flow *flow, TSNode node) {
    return in_function(flow, node) ? open_node_scope(flow, node) : PQSCAN_OK;
}

/* A parameter hides any constant of the same name, and its value comes from the caller. */
// cppcheck-suppress constParameterCallback
// cppcheck-suppress constParameterPointer
static pqscan_status bind_declarator_unknown(constant_flow *flow, TSNode node) {
    TSNode name;
    const bool named =
        in_function(flow, node) && declarator_name(syntax_node_field(node, "declarator"), &name);
    return named ? bind_local(flow, name, UNKNOWN_VALUE) : PQSCAN_OK;
}

// cppcheck-suppress constParameterCallback
// cppcheck-suppress constParameterPointer
static pqscan_status handle_macro_parameters(constant_flow *flow, TSNode node) {
    const pqscan_status opened = open_node_scope(flow, node);
    const TSNode parameters = syntax_node_field(node, "parameters");
    if (opened != PQSCAN_OK || ts_node_is_null(parameters)) {
        return opened;
    }
    pqscan_status status = PQSCAN_OK;
    TSTreeCursor cursor = ts_tree_cursor_new(parameters);
    bool more = ts_tree_cursor_goto_first_child(&cursor);
    while (more && status == PQSCAN_OK) {
        const TSNode child = ts_tree_cursor_current_node(&cursor);
        if (syntax_node_is(child, "identifier")) {
            status = bind_local(flow, child, UNKNOWN_VALUE);
        }
        more = ts_tree_cursor_goto_next_sibling(&cursor);
    }
    ts_tree_cursor_delete(&cursor);
    return status;
}

typedef struct local_declaration {
    const constant_flow *flow;
    bool is_const;
    bool tracked;
} local_declaration;

static local_declaration describe_declaration(const constant_flow *flow, TSNode node) {
    const source_node declaration = {node, flow->source.file};
    const bool is_const = declaration_is_const(&declaration);
    /* A static local keeps its last value from one call to the next. */
    const bool shared = declaration_has_specifier(&declaration, "volatile") ||
                        declaration_has_specifier(&declaration, "extern") ||
                        (declaration_has_specifier(&declaration, "static") && !is_const);
    const local_declaration local = {flow, is_const, !shared};
    return local;
}

/* The name of a writable array changes contents through any call it is passed to. */
static bool can_hold_value(const local_declaration *local, TSNode init_declarator) {
    const TSNode declarator = syntax_node_field(init_declarator, "declarator");
    if (syntax_node_is(declarator, "reference_declarator")) {
        return false;
    }
    return !syntax_node_is(declarator, "array_declarator") || local->is_const;
}

static pqscan_status bind_declarator(const void *context, TSNode declarator) {
    const local_declaration *local = context;
    TSNode name;
    if (!declarator_name(declarator, &name)) {
        return PQSCAN_OK;
    }
    constant_value value = UNKNOWN_VALUE;
    if (local->tracked && syntax_node_is(declarator, "init_declarator") &&
        can_hold_value(local, declarator)) {
        value = constant_flow_evaluate(local->flow, syntax_node_field(declarator, "value"));
    }
    return bind_local(local->flow, name, value);
}

// cppcheck-suppress constParameterCallback
// cppcheck-suppress constParameterPointer
static pqscan_status handle_declaration(constant_flow *flow, TSNode node) {
    if (!in_function(flow, node)) {
        return PQSCAN_OK;
    }
    const local_declaration local = describe_declaration(flow, node);
    return declaration_each_declarator(node, bind_declarator, &local);
}

// cppcheck-suppress constParameterCallback
// cppcheck-suppress constParameterPointer
static pqscan_status handle_assignment(constant_flow *flow, TSNode node) {
    const TSNode left = syntax_node_field(node, "left");
    const syntax_text operator_text =
        syntax_node_text(syntax_node_field(node, "operator"), flow->source.file);
    if (!in_function(flow, node) || !syntax_node_is(left, "identifier") ||
        !syntax_text_is(operator_text, "=")) {
        return PQSCAN_OK;
    }
    const syntax_text name = syntax_node_text(left, flow->source.file);
    const constant_value value = constant_flow_evaluate(flow, syntax_node_field(node, "right"));
    constant_binding *binding = constant_table_find(flow->bindings, name);
    if (binding != NULL && binding->kind == BINDING_VALUE) {
        binding->value = value;
    }
    return PQSCAN_OK;
}

static pqscan_status handle_range_loop(constant_flow *flow, TSNode node) {
    const pqscan_status status = enter_block(flow, node);
    return (status == PQSCAN_OK) ? bind_declarator_unknown(flow, node) : status;
}

static const handler_entry HANDLERS[] = {
    {"assignment_expression", handle_assignment},
    {"catch_clause", enter_block},
    {"compound_statement", enter_block},
    {"declaration", handle_declaration},
    {"for_range_loop", handle_range_loop},
    {"for_statement", enter_block},
    {"function_definition", enter_function},
    {"if_statement", enter_block},
    {"lambda_expression", enter_function},
    {"optional_parameter_declaration", bind_declarator_unknown},
    {"parameter_declaration", bind_declarator_unknown},
    {"preproc_function_def", handle_macro_parameters},
    {"switch_statement", enter_block},
    {"while_statement", enter_block},
};

pqscan_status constant_flow_visit(constant_flow *flow, TSNode node) {
    if (flow->in_macro_body) {
        return PQSCAN_OK;
    }
    const uint32_t position = ts_node_start_byte(node);
    constant_table_close_ended(flow->bindings, position);
    constant_table_close_ended(flow->mutations, position);
    const char *type = ts_node_type(node);
    for (size_t i = 0; i < sizeof(HANDLERS) / sizeof(HANDLERS[0]); i++) {
        if (strcmp(type, HANDLERS[i].type) == 0) {
            return HANDLERS[i].handle(flow, node);
        }
    }
    return PQSCAN_OK;
}
