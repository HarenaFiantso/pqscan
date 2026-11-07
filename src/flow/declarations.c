/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/flow/declarations.h"

#include "pqscan/core/status.h"
#include "pqscan/scan/syntax_parser.h"

#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <tree_sitter/api.h>

static bool is_declarator_field(const char *field) {
    return field != NULL && strcmp(field, "declarator") == 0;
}

pqscan_status declaration_each_declarator(TSNode declaration, declarator_visitor visit,
                                          const void *context) {
    TSTreeCursor cursor = ts_tree_cursor_new(declaration);
    pqscan_status status = PQSCAN_OK;
    bool more = ts_tree_cursor_goto_first_child(&cursor);
    while (more && status == PQSCAN_OK) {
        if (is_declarator_field(ts_tree_cursor_current_field_name(&cursor))) {
            status = visit(context, ts_tree_cursor_current_node(&cursor));
        }
        more = ts_tree_cursor_goto_next_sibling(&cursor);
    }
    ts_tree_cursor_delete(&cursor);
    return status;
}

bool declarator_name(TSNode declarator, TSNode *out) {
    TSNode node = declarator;
    while (!ts_node_is_null(node) && !syntax_node_is(node, "identifier")) {
        const TSNode inner = syntax_node_field(node, "declarator");
        /* A C++ reference holds its name without a field. */
        node = syntax_node_is(node, "reference_declarator") ? ts_node_named_child(node, 0) : inner;
    }
    if (ts_node_is_null(node)) {
        return false;
    }
    *out = node;
    return true;
}

static bool child_is_keyword(const source_node *parent, TSNode child, const char *keyword) {
    const bool is_specifier =
        syntax_node_is(child, "type_qualifier") || syntax_node_is(child, "storage_class_specifier");
    return is_specifier && syntax_text_is(syntax_node_text(child, parent->file), keyword);
}

bool declaration_has_specifier(const source_node *declaration, const char *specifier) {
    TSTreeCursor cursor = ts_tree_cursor_new(declaration->node);
    bool found = false;
    bool more = ts_tree_cursor_goto_first_child(&cursor);
    while (more && !found) {
        found = child_is_keyword(declaration, ts_tree_cursor_current_node(&cursor), specifier);
        more = ts_tree_cursor_goto_next_sibling(&cursor);
    }
    ts_tree_cursor_delete(&cursor);
    return found;
}

bool declaration_is_const(const source_node *declaration) {
    return declaration_has_specifier(declaration, "const") ||
           declaration_has_specifier(declaration, "constexpr");
}

bool declarator_is_fixed(const source_node *declaration, TSNode declarator) {
    const TSNode node = syntax_node_is(declarator, "init_declarator")
                            ? syntax_node_field(declarator, "declarator")
                            : declarator;
    if (syntax_node_is(node, "reference_declarator")) {
        return false;
    }
    if (syntax_node_is(node, "pointer_declarator")) {
        const source_node pointer = {node, declaration->file};
        return declaration_has_specifier(&pointer, "const");
    }
    return declaration_is_const(declaration);
}
