/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_FLOW_DECLARATIONS_H
#define PQSCAN_FLOW_DECLARATIONS_H

#include "pqscan/core/status.h"
#include "pqscan/scan/file_reader.h"

#include <stdbool.h>
#include <tree_sitter/api.h>

/** Called for each declarator of a declaration. Anything but PQSCAN_OK stops the loop. */
typedef pqscan_status (*declarator_visitor)(const void *context, TSNode declarator);

/** A node, with the file it came from. */
typedef struct source_node {
    TSNode node;
    const file_contents *file;
} source_node;

/**
 * @brief Visit each thing a declaration declares, as in int a = 1, *b;
 *
 * @param declaration A declaration node.
 * @param visit Called with each declarator, which may be an init_declarator.
 * @param context Passed to @p visit.
 * @return PQSCAN_OK, or what @p visit returned.
 */
pqscan_status declaration_each_declarator(TSNode declaration, declarator_visitor visit,
                                          const void *context);

/**
 * @brief Find the name that a declarator introduces, through pointers, arrays and references.
 *
 * @param declarator The declarator, which may be an init_declarator.
 * @param out On success, the identifier. Untouched on failure.
 * @return true on success, false if the declarator has no plain name.
 */
bool declarator_name(TSNode declarator, TSNode *out);

/**
 * @brief Tell whether a declaration carries a qualifier or a storage class.
 *
 * @param declaration The declaration, with its file.
 * @param specifier The keyword, such as "const" or "static".
 * @return true if it does.
 */
bool declaration_has_specifier(const source_node *declaration, const char *specifier);

/**
 * @brief Tell whether a declaration says const or constexpr.
 *
 * @param declaration The declaration, with its file.
 * @return true if it does.
 */
bool declaration_is_const(const source_node *declaration);

/**
 * @brief Tell whether a variable can never change.
 *
 * const char *p leaves p free to point elsewhere, unlike char *const p or const char a[].
 *
 * @param declaration The declaration, with its file.
 * @param declarator One of its declarators. An init_declarator is looked through.
 * @return true if the variable is fixed.
 */
bool declarator_is_fixed(const source_node *declaration, TSNode declarator);

#endif /* PQSCAN_FLOW_DECLARATIONS_H */
