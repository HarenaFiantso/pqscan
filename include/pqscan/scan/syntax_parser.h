/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_SCAN_SYNTAX_PARSER_H
#define PQSCAN_SCAN_SYNTAX_PARSER_H

#include "pqscan/core/status.h"
#include "pqscan/scan/file_reader.h"
#include "pqscan/walk/file_type.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <tree_sitter/api.h>

/** A Tree-sitter parser bound to one file and one deadline. */
typedef struct syntax_parser syntax_parser;

/** What to parse. */
typedef struct syntax_source {
    source_language language;
    const file_contents *file; /**< Borrowed. Must outlive the parser and its trees. */
    unsigned budget_seconds;   /**< Time allowed for the whole file, from creation. */
} syntax_source;

/** A slice of a file. It is not NUL-terminated, and the file owns the bytes. */
typedef struct syntax_text {
    const char *data;
    size_t len;
} syntax_text;

/** Called for each node of a walk. Anything but PQSCAN_OK stops it. */
typedef pqscan_status (*syntax_visitor)(void *context, TSNode node);

/** A depth-first walk over a whole subtree. */
typedef struct syntax_walk_spec {
    syntax_visitor visit;
    void *context;                 /**< Passed to visit. */
    const syntax_parser *deadline; /**< Stops the walk with PQSCAN_ERR_PARSE when it expires. */
} syntax_walk_spec;

/**
 * @brief Create a parser and start its deadline.
 *
 * @param source What to parse. The struct itself may go out of scope after this call.
 * @param out On success, the parser, owned by the caller and freed with
 *            syntax_parser_destroy(). Untouched on failure.
 * @return PQSCAN_OK, PQSCAN_ERR_TOO_LARGE if the file exceeds PQSCAN_MAX_FILE_SIZE, which
 *         keeps every offset within Tree-sitter's 32 bits, PQSCAN_ERR_NOMEM, or
 *         PQSCAN_ERR_PARSE if the grammar does not fit the Tree-sitter runtime.
 */
pqscan_status syntax_parser_create(const syntax_source *source, syntax_parser **out);

/**
 * @brief Free a parser. Trees it produced stay valid.
 *
 * @param parser The parser to free. May be NULL.
 */
void syntax_parser_destroy(syntax_parser *parser);

/**
 * @brief Parse the whole file. Syntax errors are not failures: they become ERROR nodes.
 *
 * @param parser The parser.
 * @param out On success, the tree, owned by the caller and freed with ts_tree_delete().
 *            Untouched on failure.
 * @return PQSCAN_OK, or PQSCAN_ERR_PARSE if the deadline passed.
 */
pqscan_status syntax_parser_parse_file(syntax_parser *parser, TSTree **out);

/**
 * @brief Parse only the bytes of a node, as if the rest of the file did not exist.
 *
 * Macro bodies need this, because the grammars keep them as opaque text. The positions in
 * the new tree are still positions in the file.
 *
 * @param parser The parser.
 * @param node The node, from a tree of the same file.
 * @param out On success, the tree, owned by the caller and freed with ts_tree_delete().
 *            Untouched on failure.
 * @return PQSCAN_OK, or PQSCAN_ERR_PARSE if the deadline passed.
 */
pqscan_status syntax_parser_parse_node(syntax_parser *parser, TSNode node, TSTree **out);

/**
 * @brief Tell whether the time budget is spent, so that long walks can stop too.
 *
 * @param parser The parser.
 * @return true once the deadline has passed.
 */
bool syntax_parser_expired(const syntax_parser *parser);

/**
 * @brief Get the source text of a node.
 *
 * @param node The node.
 * @param file The file the node was parsed from.
 * @return A slice of @p file, empty if the node lies outside it.
 */
syntax_text syntax_node_text(TSNode node, const file_contents *file);

/**
 * @brief Compare a slice of a file with a string.
 *
 * @param text The slice.
 * @param expected The NUL-terminated string.
 * @return true if they hold the same bytes.
 */
bool syntax_text_is(syntax_text text, const char *expected);

/**
 * @brief Compare the type of a node.
 *
 * @param node The node. May be a null node.
 * @param type The grammar's name for the type, such as "identifier".
 * @return true if the node exists and has this type.
 */
bool syntax_node_is(TSNode node, const char *type);

/**
 * @brief Get a child of a node by its field name.
 *
 * @param node The node.
 * @param field The grammar's name for the field, such as "function".
 * @return The child, or a null node if there is none. Check with ts_node_is_null().
 */
TSNode syntax_node_field(TSNode node, const char *field);

/**
 * @brief Find a named child, not counting comments, which can sit between any two nodes.
 *
 * @param parent The node. It should have no more children than an expression list can.
 * @param index The position among such children, from zero.
 * @param out On success, the child. Untouched on failure.
 * @return true on success, false if there are not enough children.
 */
bool syntax_named_child(TSNode parent, uint32_t index, TSNode *out);

/**
 * @brief Look through the parentheses around an expression.
 *
 * @param expression The expression. May be a null node.
 * @return The inner expression, which may be @p expression itself.
 */
TSNode syntax_strip_parentheses(TSNode expression);

/**
 * @brief Look through the parentheses and value-preserving casts around an expression.
 *
 * A cast to a type that could change a key size, such as (char)4096, or to a type this
 * cannot see through, such as a typedef, is left in place for the caller to treat as unknown.
 *
 * @param expression The expression. May be a null node.
 * @param file The file the node was parsed from.
 * @return The inner expression, which may be @p expression itself.
 */
TSNode syntax_unwrap_expression(TSNode expression, const file_contents *file);

/**
 * @brief Move a cursor to the next node of a depth-first walk.
 *
 * @param cursor The cursor.
 * @param skip_children true to leave the current node's subtree without entering it.
 * @return false once the walk is over.
 */
bool syntax_cursor_advance(TSTreeCursor *cursor, bool skip_children);

/**
 * @brief Visit a node and everything under it, in source order.
 *
 * The walk keeps its position on the heap, so that deep nesting in a hostile file cannot
 * overflow the C stack.
 *
 * @param root The node to start from.
 * @param spec What to do with each node.
 * @return PQSCAN_OK, what a visitor returned, or PQSCAN_ERR_PARSE past the deadline.
 */
pqscan_status syntax_walk(TSNode root, const syntax_walk_spec *spec);

#endif /* PQSCAN_SCAN_SYNTAX_PARSER_H */
