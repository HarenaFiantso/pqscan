/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_CORE_SKIP_LIST_H
#define PQSCAN_CORE_SKIP_LIST_H

#include "pqscan/core/status.h"

#include <stddef.h>

/** A path in scope that a run could not analyze. */
typedef struct skipped_path {
    const char *path;     /**< Owned by the list. */
    pqscan_status reason; /**< Why it was skipped. */
} skipped_path;

/** A growable list of skipped paths, in the order they were added. */
typedef struct skip_list skip_list;

/**
 * @brief Create an empty list.
 *
 * @return The list, owned by the caller and freed with skip_list_destroy(), or NULL if out
 *         of memory.
 */
skip_list *skip_list_create(void);

/**
 * @brief Free a list and every path it holds.
 *
 * @param list The list to free. May be NULL.
 */
void skip_list_destroy(skip_list *list);

/**
 * @brief Append a skipped path.
 *
 * @param list The list.
 * @param path The path to copy. The caller keeps ownership of it.
 * @param reason Why it was skipped.
 * @return PQSCAN_OK, or PQSCAN_ERR_NOMEM.
 */
pqscan_status skip_list_add(skip_list *list, const char *path, pqscan_status reason);

/**
 * @brief Count the skipped paths in a list.
 *
 * @param list The list.
 * @return The number of paths.
 */
size_t skip_list_count(const skip_list *list);

/**
 * @brief Read a skipped path by position.
 *
 * @param list The list.
 * @param index The position, from zero.
 * @return The entry, still owned by the list, or NULL if @p index is out of range. It stays
 *         valid until the next skip_list_add() or skip_list_destroy().
 */
const skipped_path *skip_list_get(const skip_list *list, size_t index);

#endif /* PQSCAN_CORE_SKIP_LIST_H */
