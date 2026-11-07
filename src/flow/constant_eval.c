/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/flow/constant_eval.h"

#include "pqscan/core/status.h"
#include "pqscan/flow/constant_table.h"
#include "pqscan/flow/flow_source.h"
#include "pqscan/scan/file_reader.h"
#include "pqscan/scan/syntax_parser.h"

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <tree_sitter/api.h>

/* Far beyond any real key size, and small enough that macros doubling each other, or a file
 * full of them, stop quickly. */
enum {
    MAX_EVAL_DEPTH = 32,
    MAX_EVAL_STEPS = 256,
    NUMBER_TEXT_SIZE = 32, /* Longer than any integer literal worth reading. */
    MAX_SHIFT = 63,
};

static const char INTEGER_SUFFIX_CHARS[] = "uUlLzZ";

typedef struct eval_run {
    const eval_env *env;
    uint32_t position;    /* Where the expression stands in the file. */
    unsigned steps;       /* Nodes evaluated so far. */
    bool file_scope_only; /* Inside the initializer of a constant, which sees no locals. */
} eval_run;

static const constant_value UNKNOWN_VALUE = {CONSTANT_UNKNOWN, 0, {"", 0}};

static constant_value eval_node(eval_run *run, TSNode expression, unsigned depth);

static constant_value integer_value(uint64_t integer) {
    const constant_value value = {CONSTANT_INTEGER, integer, {"", 0}};
    return value;
}

/* C++14 allows digit separators, which strtoull() would stop at. */
static bool copy_without_separators(syntax_text text, char *digits) {
    size_t len = 0;
    for (size_t i = 0; i < text.len; i++) {
        if (text.data[i] != '\'') {
            if (len + 1 >= NUMBER_TEXT_SIZE) {
                return false;
            }
            digits[len++] = text.data[i];
        }
    }
    digits[len] = '\0';
    return true;
}

static constant_value eval_number(syntax_text text) {
    char digits[NUMBER_TEXT_SIZE];
    /* The grammar puts a sign inside the literal, and strtoull() wraps -1 around silently. */
    if (!copy_without_separators(text, digits) || !isdigit((unsigned char)digits[0])) {
        return UNKNOWN_VALUE;
    }
    char *end = NULL;
    errno = 0;
    const unsigned long long parsed = strtoull(digits, &end, 0);
    const bool only_suffix_left = strspn(end, INTEGER_SUFFIX_CHARS) == strlen(end);
    if (errno != 0 || end == digits || !only_suffix_left) {
        return UNKNOWN_VALUE;
    }
    return integer_value((uint64_t)parsed);
}

static constant_value eval_string(const eval_run *run, TSNode literal) {
    const TSNode content = ts_node_named_child(literal, 0);
    if (ts_node_named_child_count(literal) != 1 || !syntax_node_is(content, "string_content")) {
        return UNKNOWN_VALUE;
    }
    const constant_value value = {
        CONSTANT_STRING,
        0,
        syntax_node_text(content, run->env->source->file),
    };
    return value;
}

static constant_value apply_operator(syntax_text operator_text, uint64_t left, uint64_t right) {
    if (syntax_text_is(operator_text, "+") && left <= UINT64_MAX - right) {
        return integer_value(left + right);
    }
    if (syntax_text_is(operator_text, "-") && left >= right) {
        return integer_value(left - right);
    }
    if (syntax_text_is(operator_text, "*") && (right == 0 || left <= UINT64_MAX / right)) {
        return integer_value(left * right);
    }
    if (syntax_text_is(operator_text, "<<") && right <= MAX_SHIFT &&
        left <= (UINT64_MAX >> right)) {
        return integer_value(left << right);
    }
    return UNKNOWN_VALUE;
}

// NOLINTNEXTLINE(misc-no-recursion): MAX_EVAL_DEPTH bounds the recursion.
static constant_value eval_binary(eval_run *run, TSNode expression, unsigned depth) {
    const constant_value left = eval_node(run, syntax_node_field(expression, "left"), depth + 1);
    const constant_value right = eval_node(run, syntax_node_field(expression, "right"), depth + 1);
    if (left.kind != CONSTANT_INTEGER || right.kind != CONSTANT_INTEGER) {
        return UNKNOWN_VALUE;
    }
    const TSNode operator_node = syntax_node_field(expression, "operator");
    return apply_operator(syntax_node_text(operator_node, run->env->source->file), left.integer,
                          right.integer);
}

static bool starts_comment(syntax_text text) {
    return text.len >= 2 && text.data[0] == '/' && (text.data[1] == '/' || text.data[1] == '*');
}

static bool is_blank_or_comment(syntax_text text) {
    syntax_text rest = text;
    while (rest.len > 0 && (rest.data[0] == ' ' || rest.data[0] == '\t' || rest.data[0] == '\r')) {
        rest.data++;
        rest.len--;
    }
    return rest.len == 0 || starts_comment(rest);
}

static bool find_only_child(TSNode parent, TSNode *out) {
    TSNode ignored;
    return syntax_named_child(parent, 0, out) && !syntax_named_child(parent, 1, &ignored);
}

/* Alone, a macro body such as 2048 is no valid C, so the grammar wraps it in an ERROR. */
static bool find_macro_expression(TSNode root, TSNode *out) {
    return find_only_child(root, out) &&
           (!syntax_node_is(*out, "ERROR") || find_only_child(*out, out));
}

/* The grammar stops at the first thing it understands, so that 1024 + gives 1024. */
static bool reaches_end_of_body(const eval_run *run, TSNode expression, TSNode body) {
    const file_contents *file = run->env->source->file;
    const size_t end = ts_node_end_byte(expression);
    const size_t stop = ts_node_end_byte(body);
    if (end > stop || stop > file->len) {
        return false;
    }
    const syntax_text rest = {file->data + end, stop - end};
    return is_blank_or_comment(rest);
}

// NOLINTNEXTLINE(misc-no-recursion): MAX_EVAL_DEPTH bounds the recursion.
static constant_value eval_macro(eval_run *run, TSNode body, unsigned depth) {
    TSTree *tree = NULL;
    if (syntax_parser_parse_node(run->env->source->parser, body, &tree) != PQSCAN_OK) {
        return UNKNOWN_VALUE;
    }
    TSNode expression;
    constant_value value = UNKNOWN_VALUE;
    if (find_macro_expression(ts_tree_root_node(tree), &expression) &&
        reaches_end_of_body(run, expression, body)) {
        value = eval_node(run, expression, depth + 1);
    }
    ts_tree_delete(tree);
    return value;
}

// NOLINTNEXTLINE(misc-no-recursion): MAX_EVAL_DEPTH bounds the recursion.
static constant_value eval_global(eval_run *run, TSNode initializer, unsigned depth) {
    const bool outer = run->file_scope_only;
    run->file_scope_only = true;
    const constant_value value = eval_node(run, initializer, depth + 1);
    run->file_scope_only = outer;
    return value;
}

static bool is_saturated(const eval_env *env) {
    return constant_table_is_saturated(env->bindings) ||
           constant_table_is_saturated(env->mutations);
}

static bool is_reliable(const eval_run *run, const constant_binding *binding) {
    if (binding->kind != BINDING_VALUE) {
        return binding->position < run->position;
    }
    if (run->env->in_macro_body) {
        return false;
    }
    const constant_binding *mutated = constant_table_find(run->env->mutations, binding->name);
    return mutated == NULL || mutated->position > run->position;
}

// NOLINTNEXTLINE(misc-no-recursion): MAX_EVAL_DEPTH bounds the recursion.
static constant_value eval_name(eval_run *run, syntax_text name, unsigned depth) {
    const eval_env *env = run->env;
    if (is_saturated(env)) {
        return UNKNOWN_VALUE;
    }
    const constant_binding *binding = run->file_scope_only
                                          ? constant_table_find_file_scope(env->bindings, name)
                                          : constant_table_find(env->bindings, name);
    if (binding == NULL || !is_reliable(run, binding)) {
        return UNKNOWN_VALUE;
    }
    if (binding->kind == BINDING_MACRO) {
        return eval_macro(run, binding->definition, depth);
    }
    if (binding->kind == BINDING_GLOBAL && !env->in_macro_body) {
        return eval_global(run, binding->definition, depth);
    }
    return (binding->kind == BINDING_VALUE) ? binding->value : UNKNOWN_VALUE;
}

// NOLINTNEXTLINE(misc-no-recursion): MAX_EVAL_DEPTH bounds the recursion.
static constant_value eval_node(eval_run *run, TSNode expression, unsigned depth) {
    run->steps++;
    if (depth > MAX_EVAL_DEPTH || run->steps > MAX_EVAL_STEPS) {
        return UNKNOWN_VALUE;
    }
    const TSNode node = syntax_unwrap_expression(expression);
    const file_contents *file = run->env->source->file;
    if (syntax_node_is(node, "number_literal")) {
        return eval_number(syntax_node_text(node, file));
    }
    if (syntax_node_is(node, "string_literal")) {
        return eval_string(run, node);
    }
    if (syntax_node_is(node, "identifier")) {
        return eval_name(run, syntax_node_text(node, file), depth);
    }
    return syntax_node_is(node, "binary_expression") ? eval_binary(run, node, depth)
                                                     : UNKNOWN_VALUE;
}

constant_value constant_eval(const eval_env *env, TSNode expression) {
    eval_run run = {env, ts_node_start_byte(expression), 0, false};
    return eval_node(&run, expression, 0);
}
