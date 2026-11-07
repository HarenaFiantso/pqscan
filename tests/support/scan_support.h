/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_TESTS_SUPPORT_SCAN_SUPPORT_H
#define PQSCAN_TESTS_SUPPORT_SCAN_SUPPORT_H

#include "pqscan/core/finding.h"
#include "pqscan/flow/constant_table.h"
#include "pqscan/flow/flow_source.h"
#include "pqscan/scan/file_reader.h"
#include "pqscan/scan/syntax_parser.h"
#include "pqscan/walk/file_type.h"

#include <stddef.h>
#include <tree_sitter/api.h>

/** A source text, parsed. */
typedef struct parsed_source {
    file_contents file; /**< Borrows the text. */
    syntax_parser *parser;
    TSTree *tree;
    flow_source flow;
} parsed_source;

/**
 * @brief Parse a text, failing the test if that goes wrong.
 *
 * @param source Out: the result, freed with parsed_source_release().
 * @param text The text, which must outlive @p source.
 * @param language The grammar to use.
 */
void parsed_source_init(parsed_source *source, char *text, source_language language);

/**
 * @brief Free what a parsed source owns.
 *
 * @param source The source.
 */
void parsed_source_release(parsed_source *source);

/**
 * @brief Get the root of a parsed source.
 *
 * @param source The source.
 * @return The root node.
 */
TSNode parsed_source_root(const parsed_source *source);

/**
 * @brief Find the first node of a type, in source order.
 *
 * @param root Where to look.
 * @param type The grammar's name for the type.
 * @return The node. Fails the test if there is none.
 */
TSNode find_node_of_type(TSNode root, const char *type);

/**
 * @brief Make a syntax_text out of a string.
 *
 * @param text The string, which must outlive the result.
 * @return The slice.
 */
syntax_text text_from(const char *text);

/**
 * @brief Write one "line:label" word per finding, where a label carries any key size.
 *
 * @param findings The findings.
 * @param description Out: the words, separated by spaces.
 * @param size The size of @p description. Running out fails the test.
 */
void describe_findings(const finding_list *findings, char *description, size_t size);

#endif /* PQSCAN_TESTS_SUPPORT_SCAN_SUPPORT_H */
