/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/finding.h"

#include "pqscan/core/memory.h"
#include "pqscan/core/status.h"
#include "pqscan/risk/priority.h"

#include <stdbool.h>
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

void finding_list_set_priority(finding_list *list, size_t index, priority value) {
    if (index < list->count) {
        list->items[index].priority = value;
    }
}

void finding_list_sort(finding_list *list, int (*compare)(const void *left, const void *right)) {
    if (list->count > 1) {
        qsort(list->items, list->count, sizeof(list->items[0]), compare);
    }
}

/* Compacts in place: kept findings slide down over the removed ones, in one pass. */
size_t finding_list_remove_if(finding_list *list, finding_filter matches, void *context) {
    size_t kept = 0;
    for (size_t i = 0; i < list->count; i++) {
        if (matches(&list->items[i], context)) {
            free((void *)list->items[i].path);
        } else {
            list->items[kept++] = list->items[i];
        }
    }
    const size_t removed = list->count - kept;
    list->count = kept;
    return removed;
}

size_t finding_list_count(const finding_list *list) { return list->count; }

const finding *finding_list_get(const finding_list *list, size_t index) {
    return (index < list->count) ? &list->items[index] : NULL;
}

/* An empty list still gets one element, because calloc(0, ...) may return NULL. */
const finding **finding_list_pointers(const finding_list *list) {
    const finding **pointers =
        (const finding **)calloc((list->count > 0) ? list->count : 1, sizeof(pointers[0]));
    if (pointers == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < list->count; i++) {
        pointers[i] = &list->items[i];
    }
    return pointers;
}
