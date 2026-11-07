/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/string_list.h"

#include "pqscan/core/memory.h"
#include "pqscan/core/status.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

struct string_list {
    char **items;
    size_t count;
    size_t capacity;
};

string_list *string_list_create(void) { return calloc(1, sizeof(string_list)); }

void string_list_destroy(string_list *list) {
    if (list == NULL) {
        return;
    }
    for (size_t i = 0; i < list->count; i++) {
        free(list->items[i]);
    }
    free((void *)list->items);
    free(list);
}

pqscan_status string_list_add(string_list *list, const char *text) {
    char *copy = strdup(text);
    if (copy == NULL) {
        return PQSCAN_ERR_NOMEM;
    }
    return string_list_add_owned(list, copy);
}

pqscan_status string_list_add_owned(string_list *list, char *text) {
    if (list->count == list->capacity) {
        char **grown = (char **)pqscan_array_grow((void *)list->items, &list->capacity,
                                                  sizeof(list->items[0]));
        if (grown == NULL) {
            free(text);
            return PQSCAN_ERR_NOMEM;
        }
        list->items = grown;
    }
    list->items[list->count] = text;
    list->count++;
    return PQSCAN_OK;
}

char *string_list_pop(string_list *list) {
    if (list->count == 0) {
        return NULL;
    }
    list->count--;
    return list->items[list->count];
}

size_t string_list_count(const string_list *list) { return list->count; }

const char *string_list_get(const string_list *list, size_t index) {
    return (index < list->count) ? list->items[index] : NULL;
}

static int compare_strings(const void *left, const void *right) {
    return strcmp(*(char *const *)left, *(char *const *)right);
}

void string_list_sort(string_list *list) {
    if (list->count > 1) {
        qsort((void *)list->items, list->count, sizeof(list->items[0]), compare_strings);
    }
}
