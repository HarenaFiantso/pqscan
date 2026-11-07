/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/scan/call_arguments.h"

#include "pqscan/core/finding.h"
#include "pqscan/scan/file_reader.h"
#include "pqscan/scan/syntax_parser.h"

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <tree_sitter/api.h>

/* Longer than any integer literal worth reading as a key size. */
enum { NUMBER_TEXT_SIZE = 32 };

static const char INTEGER_SUFFIX_CHARS[] = "uUlLzZ";

/* Comments are named nodes that can sit between arguments. A cursor keeps this linear, where
 * ts_node_named_child() in a loop would be quadratic on a list of hostile length. */
static bool find_expression(TSNode parent, uint32_t index, TSNode *out) {
    TSTreeCursor cursor = ts_tree_cursor_new(parent);
    uint32_t seen = 0;
    bool found = false;
    bool more = ts_tree_cursor_goto_first_child(&cursor);
    while (more && !found) {
        const TSNode child = ts_tree_cursor_current_node(&cursor);
        if (ts_node_is_named(child) && !syntax_node_is(child, "comment")) {
            found = seen == index;
            *out = found ? child : *out;
            seen++;
        }
        more = ts_tree_cursor_goto_next_sibling(&cursor);
    }
    ts_tree_cursor_delete(&cursor);
    return found;
}

static TSNode strip_cast_and_parentheses(TSNode expression) {
    TSNode inner = expression;
    for (;;) {
        if (syntax_node_is(inner, "cast_expression")) {
            inner = syntax_node_field(inner, "value");
        } else if (!syntax_node_is(inner, "parenthesized_expression") ||
                   !find_expression(inner, 0, &inner)) {
            return inner;
        }
    }
}

static bool find_argument(TSNode call, uint32_t index, TSNode *out) {
    const TSNode arguments = syntax_node_field(call, "arguments");
    if (ts_node_is_null(arguments) || !find_expression(arguments, index, out)) {
        return false;
    }
    *out = strip_cast_and_parentheses(*out);
    return true;
}

/* C++14 allows digit separators, which strtoul() would stop at. */
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

static bool parse_integer(syntax_text text, unsigned *value) {
    char digits[NUMBER_TEXT_SIZE];
    if (!copy_without_separators(text, digits)) {
        return false;
    }
    char *end = NULL;
    errno = 0;
    const unsigned long parsed = strtoul(digits, &end, 0);
    const bool only_suffix_left = strspn(end, INTEGER_SUFFIX_CHARS) == strlen(end);
    if (errno != 0 || end == digits || parsed > UINT_MAX || !only_suffix_left) {
        return false;
    }
    *value = (unsigned)parsed;
    return true;
}

key_size call_key_size(TSNode call, uint32_t index, const file_contents *file) {
    key_size size = {KEY_SIZE_NOT_APPLICABLE, 0};
    TSNode argument;
    if (!find_argument(call, index, &argument) || syntax_node_is(argument, "string_literal")) {
        return size;
    }
    const bool literal = syntax_node_is(argument, "number_literal") &&
                         parse_integer(syntax_node_text(argument, file), &size.bits);
    size.kind = literal ? KEY_SIZE_KNOWN : KEY_SIZE_UNKNOWN;
    return size;
}

bool call_string_argument(TSNode call, uint32_t index, TSNode *out) {
    TSNode argument;
    if (!find_argument(call, index, &argument) || !syntax_node_is(argument, "string_literal")) {
        return false;
    }
    const TSNode content = ts_node_named_child(argument, 0);
    if (ts_node_named_child_count(argument) != 1 || !syntax_node_is(content, "string_content")) {
        return false;
    }
    *out = content;
    return true;
}
