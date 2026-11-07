/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/scan/source_scanner.h"

#include "pqscan/core/finding.h"
#include "pqscan/core/key_size.h"
#include "pqscan/core/status.h"
#include "pqscan/flow/constant_flow.h"
#include "pqscan/flow/flow_source.h"
#include "pqscan/risk/risk.h"
#include "pqscan/rules/rule_set.h"
#include "pqscan/scan/call_arguments.h"
#include "pqscan/scan/file_reader.h"
#include "pqscan/scan/scanner.h"
#include "pqscan/scan/syntax_parser.h"
#include "pqscan/walk/file_type.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <tree_sitter/api.h>

/* A CI job must not hang on one hostile file, and real sources parse in milliseconds. */
enum { PARSE_BUDGET_SECONDS = 30, DEADLINE_CHECK_INTERVAL = 1024 };

typedef struct source_walk {
    const char *path;
    const file_contents *file;
    const rule_set *rules;
    syntax_parser *parser;
    constant_flow *flow;
    finding_list *findings;
    uint32_t skip_until; /* Nodes that start before this offset are not visited. */
    size_t visited;
    bool in_macro_body;
} source_walk;

typedef pqscan_status (*node_visitor)(source_walk *walk, TSNode node, const char *field);

typedef struct node_handler {
    const char *type;
    node_visitor visit;
} node_handler;

static pqscan_status walk_nodes(source_walk *walk, TSNode root);

static bool field_is(const char *field, const char *name) {
    return field != NULL && strcmp(field, name) == 0;
}

/* Tree-sitter puts the name being declared in one of these two fields of its parent. */
static bool is_declared_name(const char *field) {
    return field_is(field, "declarator") || field_is(field, "name");
}

static finding finding_at(const source_walk *walk, TSNode node, const crypto_rule *rule) {
    const finding item = {
        walk->path,
        (size_t)ts_node_start_point(node).row + 1,
        rule->algorithm->name,
        rule->algorithm->risk,
        {KEY_SIZE_NOT_APPLICABLE, 0},
        rule->primitive,
    };
    return item;
}

static void set_key_size(finding *item, const crypto_rule *rule, key_size size) {
    item->size = size;
    item->risk = risk_classify(rule->algorithm, size);
}

static pqscan_status report_identifier(const source_walk *walk, TSNode node) {
    const syntax_text name = syntax_node_text(node, walk->file);
    const crypto_rule *rule = rule_set_find_mention(walk->rules, name.data, name.len);
    if (rule == NULL) {
        return PQSCAN_OK;
    }
    const finding item = finding_at(walk, node, rule);
    return finding_list_add(walk->findings, &item);
}

static key_size signature_key_size(const source_walk *walk, TSNode call,
                                   const call_signature *signature) {
    if (signature->key_bits_argument == CALL_NO_ARGUMENT) {
        const key_size none = {KEY_SIZE_NOT_APPLICABLE, 0};
        return none;
    }
    const call_argument argument = {call, (uint32_t)signature->key_bits_argument};
    return call_key_size(&argument, walk->flow);
}

static const call_signature *find_signature(const source_walk *walk, TSNode name) {
    const syntax_text text = syntax_node_text(name, walk->file);
    return rule_set_find_call(walk->rules, text.data, text.len);
}

static pqscan_status report_callee(const source_walk *walk, TSNode call, TSNode name) {
    const syntax_text text = syntax_node_text(name, walk->file);
    const crypto_rule *rule = rule_set_find_callee(walk->rules, text.data, text.len);
    if (rule == NULL) {
        return PQSCAN_OK;
    }
    finding item = finding_at(walk, name, rule);
    const call_signature *signature = find_signature(walk, name);
    if (signature != NULL) {
        set_key_size(&item, rule, signature_key_size(walk, call, signature));
    }
    return finding_list_add(walk->findings, &item);
}

static pqscan_status report_algorithm_argument(const source_walk *walk, TSNode call, TSNode name) {
    const call_signature *signature = find_signature(walk, name);
    if (signature == NULL || signature->algorithm_argument == CALL_NO_ARGUMENT) {
        return PQSCAN_OK;
    }
    const call_argument argument = {call, (uint32_t)signature->algorithm_argument};
    string_argument found;
    if (!call_string_argument(&argument, walk->flow, &found)) {
        return PQSCAN_OK;
    }
    const crypto_rule *rule = rule_set_find_string(walk->rules, found.text.data, found.text.len);
    if (rule == NULL) {
        return PQSCAN_OK;
    }
    finding item = finding_at(walk, found.node, rule);
    set_key_size(&item, rule, signature_key_size(walk, call, signature));
    return finding_list_add(walk->findings, &item);
}

/* ns::a::name nests one qualified_identifier in the name field of the previous one, and
 * name<int> keeps it in the same field. (name)(x) is how code avoids a macro of that name. */
static TSNode strip_name_wrapping(TSNode name) {
    TSNode inner = syntax_strip_parentheses(name);
    while (syntax_node_is(inner, "qualified_identifier") ||
           syntax_node_is(inner, "template_function")) {
        inner = syntax_strip_parentheses(syntax_node_field(inner, "name"));
    }
    return inner;
}

static pqscan_status visit_call(source_walk *walk, TSNode node, const char *field) {
    (void)field;
    const TSNode name = strip_name_wrapping(syntax_node_field(node, "function"));
    if (!syntax_node_is(name, "identifier")) {
        return PQSCAN_OK;
    }
    /* Not the end of the callee, because the template arguments still need visiting. */
    walk->skip_until = ts_node_end_byte(name);
    const pqscan_status status = report_callee(walk, node, name);
    if (status != PQSCAN_OK) {
        return status;
    }
    return report_algorithm_argument(walk, node, name);
}

/* Every visitor shares one signature, even one that does not modify the walk. */
// cppcheck-suppress constParameterCallback
// cppcheck-suppress constParameterPointer
static pqscan_status visit_identifier(source_walk *walk, TSNode node, const char *field) {
    return is_declared_name(field) ? PQSCAN_OK : report_identifier(walk, node);
}

static pqscan_status skip_subtree(source_walk *walk, TSNode node, const char *field) {
    (void)field;
    walk->skip_until = ts_node_end_byte(node);
    return PQSCAN_OK;
}

static pqscan_status visit_qualified_identifier(source_walk *walk, TSNode node, const char *field) {
    walk->skip_until = ts_node_end_byte(node);
    const TSNode name = strip_name_wrapping(node);
    if (is_declared_name(field) || !syntax_node_is(name, "identifier")) {
        return PQSCAN_OK;
    }
    return report_identifier(walk, name);
}

/* The name in int (RSA_new)(void), written that way to avoid macro expansion, has no field. */
static pqscan_status visit_parenthesized_declarator(source_walk *walk, TSNode node,
                                                    const char *field) {
    return syntax_node_is(ts_node_named_child(node, 0), "identifier")
               ? skip_subtree(walk, node, field)
               : PQSCAN_OK;
}

static bool is_literal_zero(const source_walk *walk, TSNode condition) {
    if (!syntax_node_is(condition, "number_literal")) {
        return false;
    }
    const syntax_text text = syntax_node_text(condition, walk->file);
    return text.len == 1 && text.data[0] == '0';
}

/* Skipping by offset rather than by recursing into the #else keeps the walk iterative, so
 * thousands of nested conditionals cannot exhaust the stack. */
static pqscan_status visit_conditional(source_walk *walk, TSNode node, const char *field) {
    if (!is_literal_zero(walk, syntax_node_field(node, "condition"))) {
        return PQSCAN_OK;
    }
    const TSNode alternative = syntax_node_field(node, "alternative");
    if (ts_node_is_null(alternative)) {
        return skip_subtree(walk, node, field);
    }
    walk->skip_until = ts_node_start_byte(alternative);
    return PQSCAN_OK;
}

/* A body can contain the text of another #define, so this must only ever go one level deep:
 * following those would let a hostile file recurse once per directive. */
static pqscan_status visit_macro_body(source_walk *walk, TSNode node, const char *field) {
    if (walk->in_macro_body || !field_is(field, "value")) {
        return PQSCAN_OK;
    }
    TSTree *tree = NULL;
    pqscan_status status = syntax_parser_parse_node(walk->parser, node, &tree);
    if (status != PQSCAN_OK) {
        return status;
    }
    source_walk body = *walk;
    body.in_macro_body = true;
    body.skip_until = 0;
    constant_flow_set_macro_body(walk->flow, true);
    status = walk_nodes(&body, ts_tree_root_node(tree));
    constant_flow_set_macro_body(walk->flow, false);
    walk->visited = body.visited;
    ts_tree_delete(tree);
    return status;
}

static const node_handler HANDLERS[] = {
    {"call_expression", visit_call},
    {"identifier", visit_identifier},
    {"parenthesized_declarator", visit_parenthesized_declarator},
    {"preproc_arg", visit_macro_body},
    {"preproc_defined", skip_subtree},
    {"preproc_elif", visit_conditional},
    {"preproc_if", visit_conditional},
    {"preproc_params", skip_subtree},
    {"qualified_identifier", visit_qualified_identifier},
};

static pqscan_status visit_node(source_walk *walk, TSNode node, const char *field) {
    walk->visited++;
    if (walk->visited % DEADLINE_CHECK_INTERVAL == 0 && syntax_parser_expired(walk->parser)) {
        return PQSCAN_ERR_PARSE;
    }
    const pqscan_status status = constant_flow_visit(walk->flow, node);
    if (status != PQSCAN_OK) {
        return status;
    }
    const char *type = ts_node_type(node);
    for (size_t i = 0; i < sizeof(HANDLERS) / sizeof(HANDLERS[0]); i++) {
        if (strcmp(type, HANDLERS[i].type) == 0) {
            return HANDLERS[i].visit(walk, node, field);
        }
    }
    return PQSCAN_OK;
}

/* A cursor keeps its position on the heap. Recursing over the tree instead would let deeply
 * nested input overflow the C stack. */
static pqscan_status walk_nodes(source_walk *walk, TSNode root) {
    TSTreeCursor cursor = ts_tree_cursor_new(root);
    pqscan_status status = PQSCAN_OK;
    bool more = true;
    while (more && status == PQSCAN_OK) {
        const TSNode node = ts_tree_cursor_current_node(&cursor);
        const bool skipped = ts_node_start_byte(node) < walk->skip_until;
        if (!skipped) {
            status = visit_node(walk, node, ts_tree_cursor_current_field_name(&cursor));
        }
        more = syntax_cursor_advance(&cursor, skipped);
    }
    ts_tree_cursor_delete(&cursor);
    return status;
}

static pqscan_status parse_and_walk(source_walk *walk) {
    TSTree *tree = NULL;
    pqscan_status status = syntax_parser_parse_file(walk->parser, &tree);
    if (status != PQSCAN_OK) {
        return status;
    }
    const TSNode root = ts_tree_root_node(tree);
    status = constant_flow_collect_file(walk->flow, root);
    if (status == PQSCAN_OK) {
        status = walk_nodes(walk, root);
    }
    ts_tree_delete(tree);
    return status;
}

static pqscan_status walk_with_flow(const scan_input *input, syntax_parser *parser,
                                    finding_list *findings) {
    const flow_source source = {
        input->file,
        parser,
        file_type_source_language(input->path),
    };
    constant_flow *flow = NULL;
    pqscan_status status = constant_flow_create(&source, &flow);
    if (status != PQSCAN_OK) {
        return status;
    }
    source_walk walk = {
        input->path, input->file, input->rules, parser, flow, findings, 0, 0, false,
    };
    status = parse_and_walk(&walk);
    constant_flow_destroy(flow);
    return status;
}

static pqscan_status scan_source(const scan_input *input, finding_list *findings) {
    if (memchr(input->file->data, '\0', input->file->len) != NULL) {
        return PQSCAN_ERR_BINARY;
    }
    const syntax_source source = {
        file_type_source_language(input->path),
        input->file,
        PARSE_BUDGET_SECONDS,
    };
    syntax_parser *parser = NULL;
    pqscan_status status = syntax_parser_create(&source, &parser);
    if (status != PQSCAN_OK) {
        return status;
    }
    status = walk_with_flow(input, parser, findings);
    syntax_parser_destroy(parser);
    return status;
}

const scanner source_scanner = {"source", file_type_is_source, scan_source};
