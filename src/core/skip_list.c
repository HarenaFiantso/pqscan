/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/skip_list.h"

#include "pqscan/core/memory.h"
#include "pqscan/core/status.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

struct skip_list {
    skipped_path *items;
    size_t count;
    size_t capacity;
};

skip_list *skip_list_create(void) { return calloc(1, sizeof(skip_list)); }

void skip_list_destroy(skip_list *list) {
    if (list == NULL) {
        return;
    }
    for (size_t i = 0; i < list->count; i++) {
        free((void *)list->items[i].path);
    }
    free(list->items);
    free(list);
}

pqscan_status skip_list_add(skip_list *list, const char *path, pqscan_status reason) {
    if (list->count == list->capacity) {
        skipped_path *grown =
            pqscan_array_grow(list->items, &list->capacity, sizeof(list->items[0]));
        if (grown == NULL) {
            return PQSCAN_ERR_NOMEM;
        }
        list->items = grown;
    }
    const char *copy = strdup(path);
    if (copy == NULL) {
        return PQSCAN_ERR_NOMEM;
    }
    list->items[list->count].path = copy;
    list->items[list->count].reason = reason;
    list->count++;
    return PQSCAN_OK;
}

size_t skip_list_count(const skip_list *list) { return list->count; }

const skipped_path *skip_list_get(const skip_list *list, size_t index) {
    return (index < list->count) ? &list->items[index] : NULL;
}
