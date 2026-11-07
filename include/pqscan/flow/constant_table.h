/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_FLOW_CONSTANT_TABLE_H
#define PQSCAN_FLOW_CONSTANT_TABLE_H

#include "pqscan/core/status.h"
#include "pqscan/scan/syntax_parser.h"

#include <stdbool.h>
#include <stdint.h>
#include <tree_sitter/api.h>

/** A table this full stops answering, so a hostile file cannot make lookups slow. */
enum { CONSTANT_TABLE_MAX_BINDINGS = 65536 };

/** What an expression evaluates to. */
typedef enum constant_kind {
    CONSTANT_UNKNOWN = 0, /**< Not known. This is never a guess. */
    CONSTANT_INTEGER,
    CONSTANT_STRING,
} constant_kind;

/** A value. A string borrows its bytes from the file being scanned. */
typedef struct constant_value {
    constant_kind kind;
    uint64_t integer;
    syntax_text text;
} constant_value;

/** How to get the value of a name. */
typedef enum binding_kind {
    BINDING_VALUE = 0,      /**< It is in value, which may be CONSTANT_UNKNOWN. */
    BINDING_MACRO,          /**< definition is the body of a macro, evaluated where it is used. */
    BINDING_GLOBAL,         /**< definition is the initializer of a constant at file scope. */
    BINDING_FUNCTION_MACRO, /**< A macro with parameters: unknown, and it may write them. */
} binding_kind;

/** What a name stands for. The table copies this struct but not what it points at. */
typedef struct constant_binding {
    syntax_text name;
    binding_kind kind;
    constant_value value;
    TSNode definition;
    uint32_t position; /**< Byte offset that gives the binding its meaning. */
} constant_binding;

/**
 * A symbol table with nested scopes. Names and strings stay in the file, so nothing here
 * outlives it. Once full, it is saturated: see constant_table_is_saturated().
 */
typedef struct constant_table constant_table;

/**
 * @brief Create an empty table, whose only scope is the file.
 *
 * @return The table, owned by the caller and freed with constant_table_destroy(), or NULL
 *         if out of memory.
 */
constant_table *constant_table_create(void);

/**
 * @brief Free a table.
 *
 * @param table The table to free. May be NULL.
 */
void constant_table_destroy(constant_table *table);

/**
 * @brief Add a name to the innermost scope, hiding any outer binding of it.
 *
 * @param table The table.
 * @param binding The binding to copy.
 * @return PQSCAN_OK, or PQSCAN_ERR_NOMEM.
 */
pqscan_status constant_table_bind(constant_table *table, const constant_binding *binding);

/**
 * @brief Find what a name stands for at this point.
 *
 * @param table The table.
 * @param name The name.
 * @return The innermost binding, owned by the table and valid until the next bind, or NULL.
 */
constant_binding *constant_table_find(const constant_table *table, syntax_text name);

/**
 * @brief Find what a name stands for at file scope, ignoring any local that hides it.
 *
 * @param table The table.
 * @param name The name.
 * @return The binding, owned by the table and valid until the next bind, or NULL.
 */
const constant_binding *constant_table_find_file_scope(const constant_table *table,
                                                       syntax_text name);

/**
 * @brief Open a scope.
 *
 * @param table The table.
 * @param end The byte offset where the scope stops, for constant_table_close_ended().
 * @return PQSCAN_OK, or PQSCAN_ERR_NOMEM.
 */
pqscan_status constant_table_open_scope(constant_table *table, uint32_t end);

/**
 * @brief Close every scope that stops at or before a position, with its bindings.
 *
 * Offsets stand in for "leaving a block" because the walks are iterative and so have no
 * moment that marks the end of a node.
 *
 * @param table The table.
 * @param position The byte offset the walk has reached.
 */
void constant_table_close_ended(constant_table *table, uint32_t position);

/**
 * @brief Tell whether a binding was refused for lack of room.
 *
 * It stays true for the life of the table. Every answer is then suspect, because the
 * missing binding might have hidden one that is present, so callers must treat every
 * name as unknown.
 *
 * @param table The table.
 * @return true once saturated.
 */
bool constant_table_is_saturated(const constant_table *table);

/**
 * @brief Set the position of every binding in the innermost scope.
 *
 * @param table The table.
 * @param position The new position.
 */
void constant_table_set_scope_position(constant_table *table, uint32_t position);

#endif /* PQSCAN_FLOW_CONSTANT_TABLE_H */
