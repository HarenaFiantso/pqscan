/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/baseline/baseline.h"

#include "pqscan/baseline/baseline_format.h"
#include "pqscan/core/finding.h"
#include "pqscan/core/json_fields.h"
#include "pqscan/core/key_size.h"
#include "pqscan/core/primitive.h"
#include "pqscan/core/relative_path.h"
#include "pqscan/core/status.h"
#include "pqscan/report/key_size_json.h"

#include <cJSON.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct baseline_entry {
    baseline_identity identity; /* Text in safe form, borrowed from the document. */
    size_t unused;              /* How many more findings the entry accepts. */
} baseline_entry;

struct baseline {
    cJSON *document;         /* Owns the text of every entry. */
    baseline_entry *entries; /* Sorted by baseline_identity_compare(). */
    size_t count;
};

typedef struct baseline_loader {
    baseline *target;
    json_place place;
} baseline_loader;

/* These lists end in NULL. */
static const char *const DOCUMENT_FIELDS[] = {"schema_version", "findings", NULL};
static const char *const ENTRY_FIELDS[] = {
    "path", "algorithm", "symbol", "primitive", "key_size", "count", NULL,
};

void baseline_destroy(baseline *accepted) {
    if (accepted == NULL) {
        return;
    }
    free(accepted->entries);
    cJSON_Delete(accepted->document);
    free(accepted);
}

static pqscan_status reject(const baseline_loader *load, const char *field, const char *reason) {
    return json_reject(&load->place, field, reason);
}

static pqscan_status read_text(const baseline_loader *load, const json_name_field *field,
                               const char **out) {
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(field->object, field->name);
    if (!cJSON_IsString(item) || item->valuestring[0] == '\0') {
        return reject(load, field->name, "expected a non-empty string");
    }
    *out = item->valuestring;
    return PQSCAN_OK;
}

static pqscan_status read_texts(const baseline_loader *load, const cJSON *entry,
                                baseline_identity *out) {
    const json_name_field path = {entry, "path"};
    const json_name_field algorithm = {entry, "algorithm"};
    const json_name_field symbol = {entry, "symbol"};
    const char *path_as_written = NULL;
    pqscan_status status = read_text(load, &path, &path_as_written);
    if (status == PQSCAN_OK) {
        out->path = relative_path_of(path_as_written);
        status = read_text(load, &algorithm, &out->algorithm);
    }
    return (status == PQSCAN_OK) ? read_text(load, &symbol, &out->symbol) : status;
}

static pqscan_status read_primitive(const baseline_loader *load, const cJSON *entry,
                                    crypto_primitive *out) {
    const json_name_field field = {entry, "primitive"};
    const char *name = NULL;
    const pqscan_status status = read_text(load, &field, &name);
    if (status == PQSCAN_OK && !crypto_primitive_parse(name, out)) {
        return reject(load, field.name, "unknown primitive");
    }
    return status;
}

/* The range check comes first: casting a double outside unsigned's range is undefined. */
static bool is_bits(double value) {
    return value >= 0.0 && value <= (double)UINT_MAX && (double)(unsigned)value == value;
}

static pqscan_status read_key_size(const baseline_loader *load, const cJSON *entry, key_size *out) {
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(entry, "key_size");
    if (cJSON_IsNull(item)) {
        *out = (key_size){KEY_SIZE_NOT_APPLICABLE, 0};
    } else if (cJSON_IsString(item) && strcmp(item->valuestring, KEY_SIZE_JSON_UNKNOWN) == 0) {
        *out = (key_size){KEY_SIZE_UNKNOWN, 0};
    } else if (cJSON_IsNumber(item) && is_bits(item->valuedouble)) {
        *out = (key_size){KEY_SIZE_KNOWN, (unsigned)item->valuedouble};
    } else {
        return reject(load, "key_size", "expected a number of bits, \"unknown\" or null");
    }
    return PQSCAN_OK;
}

static pqscan_status read_count(const baseline_loader *load, const cJSON *entry, size_t *out) {
    const json_int_field field = {entry, "count", 1, INT_MAX, 1};
    int count = 0;
    const pqscan_status status = json_read_int(&load->place, &field, &count);
    *out = (status == PQSCAN_OK) ? (size_t)count : 0;
    return status;
}

static pqscan_status read_entry(const baseline_loader *load, const cJSON *entry,
                                baseline_entry *out) {
    if (!cJSON_IsObject(entry)) {
        return reject(load, "entry", "expected an object");
    }
    pqscan_status status = json_check_fields(&load->place, entry, ENTRY_FIELDS);
    if (status == PQSCAN_OK) {
        status = read_texts(load, entry, &out->identity);
    }
    if (status == PQSCAN_OK) {
        status = read_primitive(load, entry, &out->identity.primitive);
    }
    if (status == PQSCAN_OK) {
        status = read_key_size(load, entry, &out->identity.size);
    }
    return (status == PQSCAN_OK) ? read_count(load, entry, &out->unused) : status;
}

static size_t count_items(const cJSON *array) {
    size_t count = 0;
    for (const cJSON *item = array->child; item != NULL; item = item->next) {
        count++;
    }
    return count;
}

/* calloc() is asked for one entry at least, since calloc(0, ...) may return NULL. */
static pqscan_status read_entries(baseline_loader *load, const cJSON *entries) {
    baseline *target = load->target;
    const size_t count = count_items(entries);
    target->entries = calloc((count > 0) ? count : 1, sizeof(target->entries[0]));
    if (target->entries == NULL) {
        return PQSCAN_ERR_NOMEM;
    }
    load->place.section = "findings";
    for (const cJSON *entry = entries->child; entry != NULL; entry = entry->next) {
        const pqscan_status status = read_entry(load, entry, &target->entries[target->count]);
        if (status != PQSCAN_OK) {
            return status;
        }
        target->count++;
        load->place.index++;
    }
    return PQSCAN_OK;
}

static pqscan_status load_document(baseline_loader *load, const cJSON *document) {
    if (!cJSON_IsObject(document)) {
        return reject(load, "document", "expected an object");
    }
    pqscan_status status = json_check_fields(&load->place, document, DOCUMENT_FIELDS);
    if (status == PQSCAN_OK) {
        status = json_check_schema_version(&load->place, document, BASELINE_SCHEMA_VERSION);
    }
    if (status != PQSCAN_OK) {
        return status;
    }
    const cJSON *entries = cJSON_GetObjectItemCaseSensitive(document, "findings");
    if (!cJSON_IsArray(entries)) {
        return reject(load, "findings", "expected an array");
    }
    return read_entries(load, entries);
}

static int compare_entries(const void *left, const void *right) {
    const baseline_entry *first = left;
    const baseline_entry *second = right;
    return baseline_identity_compare(&first->identity, &second->identity);
}

static pqscan_status load_into(baseline *loaded, const baseline_source *source, json_error *error) {
    loaded->document = json_parse_document(source->text, source->len, error);
    if (loaded->document == NULL) {
        return PQSCAN_ERR_BASELINE;
    }
    baseline_loader load = {loaded, {error, PQSCAN_ERR_BASELINE, NULL, 0}};
    const pqscan_status status = load_document(&load, loaded->document);
    if (status == PQSCAN_OK && loaded->count > 1) {
        qsort(loaded->entries, loaded->count, sizeof(loaded->entries[0]), compare_entries);
    }
    return status;
}

pqscan_status baseline_load(const baseline_source *source, baseline **out, json_error *error) {
    error->message[0] = '\0';
    baseline *loaded = calloc(1, sizeof(*loaded));
    if (loaded == NULL) {
        return PQSCAN_ERR_NOMEM;
    }
    const pqscan_status status = load_into(loaded, source, error);
    if (status != PQSCAN_OK) {
        baseline_destroy(loaded);
        return status;
    }
    *out = loaded;
    return PQSCAN_OK;
}

/* The first entry that does not sort before the identity. bsearch() could land on any of
 * several equal entries, and a hand-merged file may repeat one. */
static size_t first_not_before(const baseline *accepted, const baseline_identity *raw) {
    size_t low = 0;
    size_t high = accepted->count;
    while (low < high) {
        const size_t middle = low + (high - low) / 2;
        if (baseline_identity_compare_safe(raw, &accepted->entries[middle].identity) > 0) {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    return low;
}

static bool claim_occurrence(const finding *item, void *context) {
    baseline *accepted = context;
    const baseline_identity raw = baseline_identity_of(item);
    for (size_t i = first_not_before(accepted, &raw);
         i < accepted->count &&
         baseline_identity_compare_safe(&raw, &accepted->entries[i].identity) == 0;
         i++) {
        if (accepted->entries[i].unused > 0) {
            accepted->entries[i].unused--;
            return true;
        }
    }
    return false;
}

size_t baseline_remove_accepted(baseline *accepted, finding_list *findings) {
    return finding_list_remove_if(findings, claim_occurrence, accepted);
}

size_t baseline_unused(const baseline *accepted) {
    size_t total = 0;
    for (size_t i = 0; i < accepted->count; i++) {
        const size_t unused = accepted->entries[i].unused;
        total = (unused > SIZE_MAX - total) ? SIZE_MAX : total + unused;
    }
    return total;
}
