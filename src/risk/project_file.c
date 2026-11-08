/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/risk/project_file.h"

#include "pqscan/core/json_fields.h"
#include "pqscan/core/memory.h"
#include "pqscan/core/path_pattern.h"
#include "pqscan/core/status.h"
#include "pqscan/core/string_list.h"
#include "pqscan/risk/priority.h"

#include <cJSON.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

enum { SCHEMA_VERSION = 1 };

typedef struct component {
    char *name;
    string_list *patterns;
    int secrecy_years;
    int migration_years;
} component;

struct project {
    int quantum_year;
    data_lifetime defaults; /* For a path no component claims. Its component is NULL. */
    component *components;  /* In file order, which is the order they are tried in. */
    size_t count;
    size_t capacity;
};

typedef struct project_loader {
    project *target;
    json_place place;
} project_loader;

/* These lists end in NULL. */
static const char *const DOCUMENT_FIELDS[] = {
    "schema_version", "quantum_year", "secrecy_years", "migration_years", "components", NULL,
};
static const char *const COMPONENT_FIELDS[] = {
    "name", "paths", "secrecy_years", "migration_years", NULL,
};

project *project_create_default(void) {
    project *created = calloc(1, sizeof(*created));
    if (created != NULL) {
        created->quantum_year = PROJECT_DEFAULT_QUANTUM_YEAR;
    }
    return created;
}

static void component_free(component *entry) {
    string_list_destroy(entry->patterns);
    free(entry->name);
}

void project_destroy(project *target) {
    if (target == NULL) {
        return;
    }
    for (size_t i = 0; i < target->count; i++) {
        component_free(&target->components[i]);
    }
    free(target->components);
    free(target);
}

static pqscan_status reject(const project_loader *load, const char *field, const char *reason) {
    return json_reject(&load->place, field, reason);
}

/* An absent field keeps the years already in place. */
static pqscan_status read_years(const project_loader *load, const json_name_field *where,
                                int *years) {
    const json_int_field field = {where->object, where->name, 0, PRIORITY_MAX_SPAN_YEARS, *years};
    return json_read_int(&load->place, &field, years);
}

static bool is_pattern(const cJSON *item) {
    if (!cJSON_IsString(item)) {
        return false;
    }
    const size_t len = strlen(item->valuestring);
    return len > 0 && len <= PROJECT_MAX_PATTERN_LENGTH;
}

static pqscan_status add_patterns(const project_loader *load, const cJSON *paths,
                                  string_list *patterns) {
    for (const cJSON *item = paths->child; item != NULL; item = item->next) {
        if (!is_pattern(item)) {
            return reject(load, "paths", "expected patterns of 1 to 1024 bytes");
        }
        if (string_list_add(patterns, item->valuestring) != PQSCAN_OK) {
            return PQSCAN_ERR_NOMEM;
        }
    }
    return PQSCAN_OK;
}

static pqscan_status read_patterns(const project_loader *load, const cJSON *entry, component *out) {
    const cJSON *paths = cJSON_GetObjectItemCaseSensitive(entry, "paths");
    if (!cJSON_IsArray(paths) || paths->child == NULL) {
        return reject(load, "paths", "expected a non-empty array of patterns");
    }
    out->patterns = string_list_create();
    return (out->patterns == NULL) ? PQSCAN_ERR_NOMEM : add_patterns(load, paths, out->patterns);
}

static const component *find_component(const project *target, const char *name) {
    for (size_t i = 0; i < target->count; i++) {
        if (strcmp(target->components[i].name, name) == 0) {
            return &target->components[i];
        }
    }
    return NULL;
}

static pqscan_status read_component_name(const project_loader *load, const cJSON *entry,
                                         component *out) {
    const json_name_field field = {entry, "name"};
    const char *name = NULL;
    const pqscan_status status = json_read_name(&load->place, &field, &name);
    if (status != PQSCAN_OK) {
        return status;
    }
    if (find_component(load->target, name) != NULL) {
        return reject(load, field.name, "repeated");
    }
    out->name = strdup(name);
    return (out->name == NULL) ? PQSCAN_ERR_NOMEM : PQSCAN_OK;
}

/* A component inherits the project's years for whatever it does not say. */
static pqscan_status read_component(const project_loader *load, const cJSON *entry,
                                    component *out) {
    out->secrecy_years = load->target->defaults.secrecy_years;
    out->migration_years = load->target->defaults.migration_years;
    pqscan_status status = json_check_fields(&load->place, entry, COMPONENT_FIELDS);
    if (status == PQSCAN_OK) {
        status = read_component_name(load, entry, out);
    }
    const json_name_field secrecy = {entry, "secrecy_years"};
    const json_name_field migration = {entry, "migration_years"};
    if (status == PQSCAN_OK) {
        status = read_years(load, &secrecy, &out->secrecy_years);
    }
    if (status == PQSCAN_OK) {
        status = read_years(load, &migration, &out->migration_years);
    }
    return (status == PQSCAN_OK) ? read_patterns(load, entry, out) : status;
}

static pqscan_status append_component(project *target, const component *entry) {
    if (target->count == target->capacity) {
        component *grown = pqscan_array_grow(target->components, &target->capacity, sizeof(*grown));
        if (grown == NULL) {
            return PQSCAN_ERR_NOMEM;
        }
        target->components = grown;
    }
    target->components[target->count++] = *entry;
    return PQSCAN_OK;
}

static pqscan_status load_component(const project_loader *load, const cJSON *entry) {
    if (!cJSON_IsObject(entry)) {
        return reject(load, "entry", "expected an object");
    }
    component read = {NULL, NULL, 0, 0};
    pqscan_status status = read_component(load, entry, &read);
    if (status == PQSCAN_OK) {
        status = append_component(load->target, &read);
    }
    if (status != PQSCAN_OK) {
        component_free(&read);
    }
    return status;
}

static pqscan_status load_components(project_loader *load, const cJSON *document) {
    const cJSON *entries = cJSON_GetObjectItemCaseSensitive(document, "components");
    if (entries == NULL) {
        return PQSCAN_OK;
    }
    if (!cJSON_IsArray(entries)) {
        return reject(load, "components", "expected an array");
    }
    load->place.section = "components";
    pqscan_status status = PQSCAN_OK;
    for (const cJSON *entry = entries->child; entry != NULL && status == PQSCAN_OK;
         entry = entry->next) {
        status = load_component(load, entry);
        load->place.index += (status == PQSCAN_OK) ? 1 : 0;
    }
    return status;
}

static pqscan_status read_quantum_year(const project_loader *load, const cJSON *document) {
    const json_int_field field = {
        document, "quantum_year", PRIORITY_MIN_YEAR, PRIORITY_MAX_YEAR, load->target->quantum_year,
    };
    return json_read_int(&load->place, &field, &load->target->quantum_year);
}

/* The defaults are read before the components, which inherit them. */
static pqscan_status read_settings(const project_loader *load, const cJSON *document) {
    data_lifetime *defaults = &load->target->defaults;
    const json_name_field secrecy = {document, "secrecy_years"};
    const json_name_field migration = {document, "migration_years"};
    pqscan_status status = json_check_schema_version(&load->place, document, SCHEMA_VERSION);
    if (status == PQSCAN_OK) {
        status = read_quantum_year(load, document);
    }
    if (status == PQSCAN_OK) {
        status = read_years(load, &secrecy, &defaults->secrecy_years);
    }
    return (status == PQSCAN_OK) ? read_years(load, &migration, &defaults->migration_years)
                                 : status;
}

static pqscan_status load_document(project_loader *load, const cJSON *document) {
    if (!cJSON_IsObject(document)) {
        return reject(load, "document", "expected an object");
    }
    pqscan_status status = json_check_fields(&load->place, document, DOCUMENT_FIELDS);
    if (status == PQSCAN_OK) {
        status = read_settings(load, document);
    }
    return (status == PQSCAN_OK) ? load_components(load, document) : status;
}

pqscan_status project_load(const project_source *source, project **out, json_error *error) {
    error->message[0] = '\0';
    project *loaded = project_create_default();
    if (loaded == NULL) {
        return PQSCAN_ERR_NOMEM;
    }
    cJSON *document = json_parse_document(source->text, source->len, error);
    pqscan_status status = PQSCAN_ERR_PROJECT;
    if (document != NULL) {
        project_loader load = {loaded, {error, PQSCAN_ERR_PROJECT, NULL, 0}};
        status = load_document(&load, document);
        cJSON_Delete(document);
    }
    if (status != PQSCAN_OK) {
        project_destroy(loaded);
        return status;
    }
    *out = loaded;
    return PQSCAN_OK;
}

int project_quantum_year(const project *target) { return target->quantum_year; }

data_lifetime project_lifetime_of(const project *target, const char *path) {
    for (size_t i = 0; i < target->count; i++) {
        const component *entry = &target->components[i];
        if (path_pattern_matches(entry->patterns, path)) {
            const data_lifetime lifetime = {
                entry->name,
                entry->secrecy_years,
                entry->migration_years,
            };
            return lifetime;
        }
    }
    return target->defaults;
}
