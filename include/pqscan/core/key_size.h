/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_CORE_KEY_SIZE_H
#define PQSCAN_CORE_KEY_SIZE_H

#include <stddef.h>

/** Large enough for any suffix, so that formatting one never truncates. */
enum { KEY_SIZE_SUFFIX_SIZE = 32 };

/** What is known about the key size of a finding. */
typedef enum key_size_kind {
    KEY_SIZE_NOT_APPLICABLE = 0, /**< The finding has no key size, such as a hash. */
    KEY_SIZE_UNKNOWN,            /**< It has one, but the scanner could not resolve it. */
    KEY_SIZE_KNOWN,              /**< It has one, and bits holds it. */
} key_size_kind;

/** A key size. A plain 0 could not tell "no key size" from "not resolved". */
typedef struct key_size {
    key_size_kind kind;
    unsigned bits; /**< Only meaningful for KEY_SIZE_KNOWN. */
} key_size;

/**
 * @brief Format what follows an algorithm name in a report: "-2048", "-unknown" or nothing.
 *
 * @param size The key size.
 * @param suffix Out: the suffix, NUL-terminated.
 * @param capacity The size of @p suffix. KEY_SIZE_SUFFIX_SIZE is always enough.
 */
void key_size_format_suffix(key_size size, char *suffix, size_t capacity);

/**
 * @brief Order two key sizes: none first, then unresolved, then known ones by their bits.
 *
 * @param left The first size.
 * @param right The second size.
 * @return Less than, equal to or greater than zero, as for qsort().
 */
int key_size_compare(key_size left, key_size right);

#endif /* PQSCAN_CORE_KEY_SIZE_H */
