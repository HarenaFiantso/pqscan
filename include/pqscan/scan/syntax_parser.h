/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_SCAN_SYNTAX_PARSER_H
#define PQSCAN_SCAN_SYNTAX_PARSER_H

#include "pqscan/core/status.h"
#include "pqscan/scan/file_reader.h"
#include "pqscan/walk/file_type.h"

#include <stdbool.h>
#include <stddef.h>
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

#endif /* PQSCAN_SCAN_SYNTAX_PARSER_H */
