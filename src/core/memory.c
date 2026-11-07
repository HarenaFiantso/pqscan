/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/memory.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

enum { INITIAL_CAPACITY = 8, GROWTH_FACTOR = 2 };

void *pqscan_array_grow(void *items, size_t *capacity, size_t element_size) {
    if (*capacity > SIZE_MAX / GROWTH_FACTOR) {
        return NULL;
    }
    const size_t new_capacity = (*capacity == 0) ? INITIAL_CAPACITY : *capacity * GROWTH_FACTOR;
    if (new_capacity > SIZE_MAX / element_size) {
        return NULL;
    }
    void *grown = realloc(items, new_capacity * element_size);
    if (grown != NULL) {
        *capacity = new_capacity;
    }
    return grown;
}
