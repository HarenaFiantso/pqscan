/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/flow/file_constants.h"

#include "pqscan/core/status.h"
#include "pqscan/flow/constant_table.h"
#include "pqscan/flow/declarations.h"
#include "pqscan/flow/flow_source.h"
#include "pqscan/scan/syntax_parser.h"

#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <tree_sitter/api.h>

typedef struct collector {
    const flow_source *source;
    constant_table *table;
    TSNode include_guard;     /* A null node if the file has none. */
    uint32_t conditional_end; /* Code before this offset sits in a conditional. */
    uint32_t block_end;       /* Code before this offset sits in a function body. */
} collector;

static syntax_text text_of(const collector *state, TSNode node) {
    return syntax_node_text(node, state->source->file);
}

static bool same_text(syntax_text left, syntax_text right) {
    return left.len == right.len && memcmp(left.data, right.data, left.len) == 0;
}

static bool same_definition(const collector *state, const constant_binding *known,
                            const constant_binding *added) {
    if (known->kind != added->kind || known->kind == BINDING_VALUE) {
        return false;
    }
    return same_text(text_of(state, known->definition), text_of(state, added->definition));
}

/* Whatever the name stood for, it no longer has one meaning across the file. */
static void make_unknown(constant_binding *binding) {
    binding->kind = BINDING_VALUE;
    binding->value.kind = CONSTANT_UNKNOWN;
}

static pqscan_status record(const collector *state, const constant_binding *binding) {
    constant_binding *known = constant_table_find(state->table, binding->name);
    if (known == NULL) {
        return constant_table_bind(state->table, binding);
    }
    /* In any conditional branch, a macro with parameters can write what it is given. */
    if (known->kind == BINDING_FUNCTION_MACRO || binding->kind == BINDING_FUNCTION_MACRO) {
        known->kind = BINDING_FUNCTION_MACRO;
    } else if (!same_definition(state, known, binding)) {
        make_unknown(known);
    }
    return PQSCAN_OK;
}

static pqscan_status record_unknown(const collector *state, syntax_text name) {
    constant_binding binding;
    memset(&binding, 0, sizeof(binding));
    binding.name = name;
    return record(state, &binding);
}

static bool in_conditional(const collector *state, TSNode node) {
    return ts_node_start_byte(node) < state->conditional_end;
}

static pqscan_status record_definition(const collector *state, const constant_binding *binding,
                                       TSNode node) {
    return (in_conditional(state, node) || ts_node_is_null(binding->definition))
               ? record_unknown(state, binding->name)
               : record(state, binding);
}

static pqscan_status record_macro(const collector *state, TSNode node) {
    constant_binding binding;
    memset(&binding, 0, sizeof(binding));
    binding.name = text_of(state, syntax_node_field(node, "name"));
    binding.kind = BINDING_MACRO;
    binding.definition = syntax_node_field(node, "value");
    binding.position = ts_node_start_byte(node);
    return record_definition(state, &binding, node);
}

static pqscan_status record_macro_with_parameters(const collector *state, TSNode node) {
    constant_binding binding;
    memset(&binding, 0, sizeof(binding));
    binding.name = text_of(state, syntax_node_field(node, "name"));
    binding.kind = BINDING_FUNCTION_MACRO;
    binding.position = ts_node_start_byte(node);
    return record(state, &binding);
}

/* The argument of #undef keeps whatever follows the name on the line, such as a comment. */
static syntax_text leading_identifier(syntax_text text) {
    syntax_text name = {text.data, 0};
    while (name.len < text.len &&
           (isalnum((unsigned char)text.data[name.len]) || text.data[name.len] == '_')) {
        name.len++;
    }
    return name;
}

static pqscan_status record_undef(const collector *state, TSNode node) {
    const TSNode directive = syntax_node_field(node, "directive");
    const TSNode argument = syntax_node_field(node, "argument");
    if (ts_node_is_null(argument) || !syntax_text_is(text_of(state, directive), "#undef")) {
        return PQSCAN_OK;
    }
    return record_unknown(state, leading_identifier(text_of(state, argument)));
}

typedef struct global_declaration {
    const collector *state;
    TSNode node;
} global_declaration;

static pqscan_status record_global(const void *context, TSNode declarator) {
    const global_declaration *global = context;
    const collector *state = global->state;
    const source_node declaration = {global->node, state->source->file};
    TSNode name;
    if (!syntax_node_is(declarator, "init_declarator") ||
        !declarator_is_fixed(&declaration, declarator) || !declarator_name(declarator, &name)) {
        return PQSCAN_OK;
    }
    constant_binding binding;
    memset(&binding, 0, sizeof(binding));
    binding.name = text_of(state, name);
    binding.kind = BINDING_GLOBAL;
    binding.definition = syntax_node_field(declarator, "value");
    binding.position = ts_node_start_byte(declarator);
    return record_definition(state, &binding, global->node);
}

static pqscan_status visit_declaration(const collector *state, TSNode node) {
    const source_node declaration = {node, state->source->file};
    if (ts_node_start_byte(node) < state->block_end ||
        declaration_has_specifier(&declaration, "volatile")) {
        return PQSCAN_OK;
    }
    const global_declaration global = {state, node};
    return declaration_each_declarator(node, record_global, &global);
}

static void enter_conditional(collector *state, TSNode node) {
    const uint32_t end = ts_node_end_byte(node);
    if (!ts_node_eq(node, state->include_guard) && end > state->conditional_end) {
        state->conditional_end = end;
    }
}

static void enter_block(collector *state, TSNode node) {
    const uint32_t end = ts_node_end_byte(node);
    state->block_end = (end > state->block_end) ? end : state->block_end;
}

static pqscan_status visit_node(void *context, TSNode node) {
    collector *state = context;
    if (syntax_node_is(node, "preproc_if") || syntax_node_is(node, "preproc_ifdef")) {
        enter_conditional(state, node);
    } else if (syntax_node_is(node, "compound_statement")) {
        enter_block(state, node);
    } else if (syntax_node_is(node, "preproc_def")) {
        return record_macro(state, node);
    } else if (syntax_node_is(node, "preproc_function_def")) {
        return record_macro_with_parameters(state, node);
    } else if (syntax_node_is(node, "preproc_call")) {
        return record_undef(state, node);
    } else if (syntax_node_is(node, "declaration")) {
        return visit_declaration(state, node);
    }
    return PQSCAN_OK;
}

static bool first_token_is(const collector *state, TSNode node, const char *token) {
    return ts_node_child_count(node) > 0 &&
           syntax_text_is(text_of(state, ts_node_child(node, 0)), token);
}

/* #ifndef N, then #define N, with no #else: the shape every header wraps itself in. */
static bool is_include_guard(const collector *state, TSNode node) {
    TSNode name;
    TSNode definition;
    if (!syntax_node_is(node, "preproc_ifdef") || !first_token_is(state, node, "#ifndef") ||
        !ts_node_is_null(syntax_node_field(node, "alternative")) ||
        !syntax_named_child(node, 0, &name) || !syntax_named_child(node, 1, &definition) ||
        !syntax_node_is(definition, "preproc_def")) {
        return false;
    }
    return same_text(text_of(state, name), text_of(state, syntax_node_field(definition, "name")));
}

/* A guard wraps the whole file. With code after it, the same shape is a default value that
 * the build can override, as in #ifndef BITS, #define BITS 2048, #endif. */
static TSNode find_include_guard(const collector *state, TSNode root) {
    TSNode first;
    TSNode second;
    const TSNode none = {{0, 0, 0, 0}, NULL, NULL};
    const bool alone = syntax_named_child(root, 0, &first) && !syntax_named_child(root, 1, &second);
    return (alone && is_include_guard(state, first)) ? first : none;
}

pqscan_status file_constants_collect(const flow_source *source, TSNode root,
                                     constant_table *table) {
    collector state = {source, table, {{0, 0, 0, 0}, NULL, NULL}, 0, 0};
    state.include_guard = find_include_guard(&state, root);
    const syntax_walk_spec spec = {visit_node, &state, source->parser};
    return syntax_walk(root, &spec);
}
