/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_CORE_MEMORY_H
#define PQSCAN_CORE_MEMORY_H

#include <stddef.h>

/**
 * @brief Enlarge a dynamic array, with overflow checks on the size arithmetic.
 *
 * @param items The array, or NULL when it has no storage yet.
 * @param capacity In: the current capacity. Out: the new capacity, only on success.
 * @param element_size The size of one element. Must not be zero.
 * @return The enlarged array, which replaces @p items, or NULL if the size overflows or
 *         allocation fails. On NULL, @p items stays valid and owned by the caller.
 */
void *pqscan_array_grow(void *items, size_t *capacity, size_t element_size);

#endif /* PQSCAN_CORE_MEMORY_H */
