/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/finding.h"

#include "pqscan/core/memory.h"
#include "pqscan/core/status.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

struct finding_list {
    finding *items;
    size_t count;
    size_t capacity;
};

finding_list *finding_list_create(void) { return calloc(1, sizeof(finding_list)); }

void finding_list_destroy(finding_list *list) {
    if (list == NULL) {
        return;
    }
    for (size_t i = 0; i < list->count; i++) {
        free((void *)list->items[i].path);
    }
    free(list->items);
    free(list);
}

pqscan_status finding_list_add(finding_list *list, const finding *item) {
    if (list->count == list->capacity) {
        finding *grown = pqscan_array_grow(list->items, &list->capacity, sizeof(list->items[0]));
        if (grown == NULL) {
            return PQSCAN_ERR_NOMEM;
        }
        list->items = grown;
    }
    const char *path = strdup(item->path);
    if (path == NULL) {
        return PQSCAN_ERR_NOMEM;
    }
    list->items[list->count] = *item;
    list->items[list->count].path = path;
    list->count++;
    return PQSCAN_OK;
}

size_t finding_list_count(const finding_list *list) { return list->count; }

const finding *finding_list_get(const finding_list *list, size_t index) {
    return (index < list->count) ? &list->items[index] : NULL;
}
