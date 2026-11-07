/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_CORE_STRING_LIST_H
#define PQSCAN_CORE_STRING_LIST_H

#include "pqscan/core/status.h"

#include <stddef.h>

/** A growable list of strings. The list owns every string it holds. */
typedef struct string_list string_list;

/**
 * @brief Create an empty list.
 *
 * @return The list, owned by the caller and freed with string_list_destroy(), or NULL if
 *         out of memory.
 */
string_list *string_list_create(void);

/**
 * @brief Free a list and every string it holds.
 *
 * @param list The list to free. May be NULL.
 */
void string_list_destroy(string_list *list);

/**
 * @brief Append a copy of a string.
 *
 * @param list The list.
 * @param text The string to copy. The caller keeps ownership of it.
 * @return PQSCAN_OK, or PQSCAN_ERR_NOMEM.
 */
pqscan_status string_list_add(string_list *list, const char *text);

/**
 * @brief Append a heap-allocated string, taking ownership of it.
 *
 * @param list The list.
 * @param text The string to adopt. It is freed if this function fails, so the caller
 *             must not use it after the call in either case.
 * @return PQSCAN_OK, or PQSCAN_ERR_NOMEM.
 */
pqscan_status string_list_add_owned(string_list *list, char *text);

/**
 * @brief Remove the last string.
 *
 * @param list The list.
 * @return The string, now owned by the caller and freed with free(), or NULL if the list
 *         is empty.
 */
char *string_list_pop(string_list *list);

/**
 * @brief Count the strings in a list.
 *
 * @param list The list.
 * @return The number of strings.
 */
size_t string_list_count(const string_list *list);

/**
 * @brief Read a string by position.
 *
 * @param list The list.
 * @param index The position, from zero.
 * @return The string, still owned by the list, or NULL if @p index is out of range. It
 *         stays valid until it is removed or the list is destroyed.
 */
const char *string_list_get(const string_list *list, size_t index);

/**
 * @brief Sort the strings by byte value.
 *
 * @param list The list.
 */
void string_list_sort(string_list *list);

#endif /* PQSCAN_CORE_STRING_LIST_H */
