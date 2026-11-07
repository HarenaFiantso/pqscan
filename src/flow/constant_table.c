/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/flow/constant_table.h"

#include "pqscan/core/memory.h"
#include "pqscan/core/status.h"
#include "pqscan/scan/syntax_parser.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

enum { BUCKET_COUNT = 4096 };

static const uint32_t NO_ENTRY = UINT32_MAX;
static const uint32_t FNV_OFFSET_BASIS = 2166136261U;
static const uint32_t FNV_PRIME = 16777619U;

typedef struct table_entry {
    constant_binding binding;
    uint32_t hash;
    uint32_t next; /* The entry this one hid in its bucket. */
} table_entry;

typedef struct table_scope {
    uint32_t end;
    uint32_t first_entry;
} table_scope;

/* Entries form a stack, and each bucket chains from newest to oldest. Popping the stack
 * therefore always removes the head of a bucket, which makes closing a scope cheap and
 * brings back any binding that the scope was hiding. */
struct constant_table {
    uint32_t buckets[BUCKET_COUNT];
    table_entry *entries;
    size_t entry_count;
    size_t entry_capacity;
    table_scope *scopes;
    size_t scope_count;
    size_t scope_capacity;
    bool saturated;
};

static uint32_t hash_name(syntax_text name) {
    uint32_t hash = FNV_OFFSET_BASIS;
    for (size_t i = 0; i < name.len; i++) {
        hash = (hash ^ (unsigned char)name.data[i]) * FNV_PRIME;
    }
    return hash;
}

static bool names_match(syntax_text left, syntax_text right) {
    return left.len == right.len && memcmp(left.data, right.data, left.len) == 0;
}

constant_table *constant_table_create(void) {
    constant_table *table = calloc(1, sizeof(constant_table));
    if (table == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < BUCKET_COUNT; i++) {
        table->buckets[i] = NO_ENTRY;
    }
    return table;
}

void constant_table_destroy(constant_table *table) {
    if (table == NULL) {
        return;
    }
    free(table->entries);
    free(table->scopes);
    free(table);
}

pqscan_status constant_table_bind(constant_table *table, const constant_binding *binding) {
    if (table->entry_count == CONSTANT_TABLE_MAX_BINDINGS) {
        table->saturated = true;
        return PQSCAN_OK;
    }
    if (table->entry_count == table->entry_capacity) {
        table_entry *grown =
            pqscan_array_grow(table->entries, &table->entry_capacity, sizeof(table->entries[0]));
        if (grown == NULL) {
            return PQSCAN_ERR_NOMEM;
        }
        table->entries = grown;
    }
    const uint32_t hash = hash_name(binding->name);
    const size_t bucket = hash % BUCKET_COUNT;
    table_entry *entry = &table->entries[table->entry_count];
    entry->binding = *binding;
    entry->hash = hash;
    entry->next = table->buckets[bucket];
    table->buckets[bucket] = (uint32_t)table->entry_count;
    table->entry_count++;
    return PQSCAN_OK;
}

constant_binding *constant_table_find(const constant_table *table, syntax_text name) {
    const uint32_t hash = hash_name(name);
    uint32_t index = table->buckets[hash % BUCKET_COUNT];
    while (index != NO_ENTRY) {
        table_entry *entry = &table->entries[index];
        if (entry->hash == hash && names_match(entry->binding.name, name)) {
            return &entry->binding;
        }
        index = entry->next;
    }
    return NULL;
}

const constant_binding *constant_table_find_file_scope(const constant_table *table,
                                                       syntax_text name) {
    const uint32_t file_entries =
        (table->scope_count > 0) ? table->scopes[0].first_entry : (uint32_t)table->entry_count;
    const uint32_t hash = hash_name(name);
    uint32_t index = table->buckets[hash % BUCKET_COUNT];
    while (index != NO_ENTRY) {
        const table_entry *entry = &table->entries[index];
        if (index < file_entries && entry->hash == hash && names_match(entry->binding.name, name)) {
            return &entry->binding;
        }
        index = entry->next;
    }
    return NULL;
}

pqscan_status constant_table_open_scope(constant_table *table, uint32_t end) {
    if (table->scope_count == table->scope_capacity) {
        table_scope *grown =
            pqscan_array_grow(table->scopes, &table->scope_capacity, sizeof(table->scopes[0]));
        if (grown == NULL) {
            return PQSCAN_ERR_NOMEM;
        }
        table->scopes = grown;
    }
    const table_scope scope = {end, (uint32_t)table->entry_count};
    table->scopes[table->scope_count++] = scope;
    return PQSCAN_OK;
}

static void pop_entries(constant_table *table, uint32_t first_entry) {
    while (table->entry_count > first_entry) {
        const table_entry *entry = &table->entries[--table->entry_count];
        table->buckets[entry->hash % BUCKET_COUNT] = entry->next;
    }
}

void constant_table_close_ended(constant_table *table, uint32_t position) {
    while (table->scope_count > 0 && table->scopes[table->scope_count - 1].end <= position) {
        table->scope_count--;
        pop_entries(table, table->scopes[table->scope_count].first_entry);
    }
}

bool constant_table_is_saturated(const constant_table *table) { return table->saturated; }

void constant_table_set_scope_position(constant_table *table, uint32_t position) {
    const size_t first =
        (table->scope_count > 0) ? table->scopes[table->scope_count - 1].first_entry : 0;
    for (size_t i = first; i < table->entry_count; i++) {
        table->entries[i].binding.position = position;
    }
}
