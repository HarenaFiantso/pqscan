/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/rules/rule_loader.h"

#include "pqscan/core/json_fields.h"
#include "pqscan/core/primitive.h"
#include "pqscan/core/status.h"
#include "pqscan/risk/risk.h"
#include "pqscan/rules/rule_set.h"

#include <cJSON.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

enum {
    SCHEMA_VERSION = 1,
    MAX_KEY_BITS = 1024 * 1024,
    MAX_ARGUMENT_INDEX = 255,
};

typedef struct loader {
    rule_set *set;
    json_place place;
} loader;

typedef struct kind_name {
    const char *name;
    rule_kind kind;
} kind_name;

typedef pqscan_status (*entry_loader)(loader *load, const cJSON *entry);

typedef struct section_spec {
    const char *name;
    entry_loader load_entry;
} section_spec;

/* These lists end in NULL. */
static const char *const DOCUMENT_FIELDS[] = {
    "schema_version", "algorithms", "rules", "calls", NULL,
};
static const char *const ALGORITHM_FIELDS[] = {"name", "risk", "weak_below_bits", NULL};
static const char *const RULE_FIELDS[] = {
    "pattern", "kind", "algorithm", "primitive", "call_only", "key_bits", NULL,
};
static const char *const CALL_FIELDS[] = {
    "name",
    "key_bits_argument",
    "algorithm_argument",
    NULL,
};

static const kind_name KINDS[] = {
    {"function", RULE_FUNCTION}, {"constant", RULE_CONSTANT}, {"macro", RULE_MACRO},
    {"string", RULE_STRING},     {"config", RULE_CONFIG},     {"key", RULE_KEY},
};

static pqscan_status reject(const loader *load, const char *field, const char *reason) {
    return json_reject(&load->place, field, reason);
}

static pqscan_status read_name(const loader *load, const json_name_field *field, const char **out) {
    return json_read_name(&load->place, field, out);
}

static pqscan_status read_int(const loader *load, const json_int_field *field, int *out) {
    return json_read_int(&load->place, field, out);
}

static pqscan_status read_risk(const loader *load, const cJSON *entry, algorithm_policy *policy) {
    const json_name_field field = {entry, "risk"};
    const char *name = NULL;
    const pqscan_status status = read_name(load, &field, &name);
    if (status != PQSCAN_OK) {
        return status;
    }
    return risk_level_parse(name, &policy->risk) ? PQSCAN_OK
                                                 : reject(load, field.name, "unknown risk level");
}

static pqscan_status read_weak_below(const loader *load, const cJSON *entry,
                                     algorithm_policy *policy) {
    const json_int_field field = {entry, "weak_below_bits", 1, MAX_KEY_BITS, 0};
    int bits = 0;
    const pqscan_status status = read_int(load, &field, &bits);
    if (status == PQSCAN_OK) {
        policy->weak_below_bits = (unsigned)bits;
    }
    return status;
}

static pqscan_status read_policy(const loader *load, const cJSON *entry, algorithm_policy *policy) {
    const json_name_field name = {entry, "name"};
    pqscan_status status = read_name(load, &name, &policy->name);
    if (status == PQSCAN_OK) {
        status = read_risk(load, entry, policy);
    }
    return (status == PQSCAN_OK) ? read_weak_below(load, entry, policy) : status;
}

static pqscan_status load_algorithm(loader *load, const cJSON *entry) {
    algorithm_policy policy = {NULL, RISK_OK, 0};
    pqscan_status status = json_check_fields(&load->place, entry, ALGORITHM_FIELDS);
    if (status == PQSCAN_OK) {
        status = read_policy(load, entry, &policy);
    }
    if (status != PQSCAN_OK) {
        return status;
    }
    status = rule_set_add_algorithm(load->set, &policy);
    return (status == PQSCAN_ERR_RULES) ? reject(load, "name", "repeated, or too many algorithms")
                                        : status;
}

static bool parse_kind(const char *name, rule_kind *out) {
    for (size_t i = 0; i < sizeof(KINDS) / sizeof(KINDS[0]); i++) {
        if (strcmp(name, KINDS[i].name) == 0) {
            *out = KINDS[i].kind;
            return true;
        }
    }
    return false;
}

static pqscan_status read_kind(const loader *load, const cJSON *entry, crypto_rule *rule) {
    const json_name_field field = {entry, "kind"};
    const char *kind = NULL;
    const pqscan_status status = read_name(load, &field, &kind);
    if (status != PQSCAN_OK) {
        return status;
    }
    return parse_kind(kind, &rule->kind) ? PQSCAN_OK : reject(load, field.name, "unknown kind");
}

static pqscan_status read_algorithm(const loader *load, const cJSON *entry, crypto_rule *rule) {
    const json_name_field field = {entry, "algorithm"};
    const char *name = NULL;
    const pqscan_status status = read_name(load, &field, &name);
    if (status != PQSCAN_OK) {
        return status;
    }
    rule->algorithm = rule_set_find_algorithm(load->set, name);
    return (rule->algorithm != NULL) ? PQSCAN_OK
                                     : reject(load, field.name, "not declared in algorithms");
}

static pqscan_status read_primitive(const loader *load, const cJSON *entry, crypto_rule *rule) {
    const json_name_field field = {entry, "primitive"};
    const char *primitive = NULL;
    const pqscan_status status = read_name(load, &field, &primitive);
    if (status != PQSCAN_OK) {
        return status;
    }
    return crypto_primitive_parse(primitive, &rule->primitive)
               ? PQSCAN_OK
               : reject(load, field.name, "unknown primitive");
}

static pqscan_status read_call_only(const loader *load, const cJSON *entry, crypto_rule *rule) {
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(entry, "call_only");
    if (item == NULL) {
        return PQSCAN_OK;
    }
    if (!cJSON_IsBool(item)) {
        return reject(load, "call_only", "expected true or false");
    }
    if (rule->kind != RULE_FUNCTION) {
        return reject(load, "call_only", "only a function can be called");
    }
    rule->call_only = cJSON_IsTrue(item) != 0;
    return PQSCAN_OK;
}

/* A key type gets its size from the key itself, and a string from the call it is passed to. A
 * config token or an identifier, such as a curve NID or DH_get_2048_256(), can name one. */
static pqscan_status read_fixed_key_bits(const loader *load, const cJSON *entry,
                                         crypto_rule *rule) {
    const json_int_field field = {entry, "key_bits", 1, MAX_KEY_BITS, 0};
    int bits = 0;
    const pqscan_status status = read_int(load, &field, &bits);
    if (status != PQSCAN_OK) {
        return status;
    }
    if (bits != 0 && (rule->kind == RULE_STRING || rule->kind == RULE_KEY)) {
        return reject(load, field.name, "a string or a key type cannot fix a key size");
    }
    rule->key_bits = (unsigned)bits;
    return PQSCAN_OK;
}

static pqscan_status read_rule(const loader *load, const cJSON *entry, crypto_rule *rule) {
    const json_name_field pattern = {entry, "pattern"};
    pqscan_status status = read_name(load, &pattern, &rule->pattern);
    if (status == PQSCAN_OK) {
        status = read_kind(load, entry, rule);
    }
    if (status == PQSCAN_OK) {
        status = read_algorithm(load, entry, rule);
    }
    if (status == PQSCAN_OK) {
        status = read_primitive(load, entry, rule);
    }
    if (status == PQSCAN_OK) {
        status = read_call_only(load, entry, rule);
    }
    return (status == PQSCAN_OK) ? read_fixed_key_bits(load, entry, rule) : status;
}

static pqscan_status load_rule(loader *load, const cJSON *entry) {
    crypto_rule rule = {NULL, RULE_FUNCTION, NULL, PRIMITIVE_UNSPECIFIED, false, 0};
    pqscan_status status = json_check_fields(&load->place, entry, RULE_FIELDS);
    if (status == PQSCAN_OK) {
        status = read_rule(load, entry, &rule);
    }
    return (status == PQSCAN_OK) ? rule_set_add_rule(load->set, &rule) : status;
}

static pqscan_status read_call(const loader *load, const cJSON *entry, call_signature *call) {
    const json_name_field name = {entry, "name"};
    const json_int_field bits = {
        entry, "key_bits_argument", 0, MAX_ARGUMENT_INDEX, CALL_NO_ARGUMENT,
    };
    const json_int_field algorithm = {
        entry, "algorithm_argument", 0, MAX_ARGUMENT_INDEX, CALL_NO_ARGUMENT,
    };
    pqscan_status status = read_name(load, &name, &call->name);
    if (status == PQSCAN_OK) {
        status = read_int(load, &bits, &call->key_bits_argument);
    }
    if (status == PQSCAN_OK) {
        status = read_int(load, &algorithm, &call->algorithm_argument);
    }
    return status;
}

static pqscan_status load_call(loader *load, const cJSON *entry) {
    call_signature call = {NULL, CALL_NO_ARGUMENT, CALL_NO_ARGUMENT};
    pqscan_status status = json_check_fields(&load->place, entry, CALL_FIELDS);
    if (status == PQSCAN_OK) {
        status = read_call(load, entry, &call);
    }
    if (status != PQSCAN_OK) {
        return status;
    }
    if (call.key_bits_argument == CALL_NO_ARGUMENT && call.algorithm_argument == CALL_NO_ARGUMENT) {
        return reject(load, "name", "a call needs at least one argument to read");
    }
    return rule_set_add_call(load->set, &call);
}

/* Algorithms load first whatever their place in the file, because rules refer to them. */
static const section_spec SECTIONS[] = {
    {"algorithms", load_algorithm},
    {"rules", load_rule},
    {"calls", load_call},
};

static pqscan_status load_section(loader *load, const cJSON *document, const section_spec *spec) {
    const cJSON *entries = cJSON_GetObjectItemCaseSensitive(document, spec->name);
    if (!cJSON_IsArray(entries)) {
        load->place.section = NULL;
        return reject(load, spec->name, "expected an array");
    }
    load->place.section = spec->name;
    load->place.index = 0;
    for (const cJSON *entry = entries->child; entry != NULL; entry = entry->next) {
        const pqscan_status status = cJSON_IsObject(entry)
                                         ? spec->load_entry(load, entry)
                                         : reject(load, "entry", "expected an object");
        if (status != PQSCAN_OK) {
            return status;
        }
        load->place.index++;
    }
    return PQSCAN_OK;
}

static pqscan_status check_document(const loader *load, const cJSON *document) {
    if (!cJSON_IsObject(document)) {
        return reject(load, "document", "expected an object");
    }
    const pqscan_status status = json_check_fields(&load->place, document, DOCUMENT_FIELDS);
    return (status == PQSCAN_OK) ? json_check_schema_version(&load->place, document, SCHEMA_VERSION)
                                 : status;
}

static pqscan_status seal_set(const loader *load) {
    const char *duplicate = NULL;
    const pqscan_status status = rule_set_seal(load->set, &duplicate);
    if (status == PQSCAN_ERR_RULES) {
        (void)snprintf(load->place.error->message, JSON_ERROR_SIZE, "repeated name: %s", duplicate);
    }
    return status;
}

static pqscan_status load_document(loader *load, const cJSON *document) {
    pqscan_status status = check_document(load, document);
    for (size_t i = 0; i < sizeof(SECTIONS) / sizeof(SECTIONS[0]) && status == PQSCAN_OK; i++) {
        status = load_section(load, document, &SECTIONS[i]);
    }
    return (status == PQSCAN_OK) ? seal_set(load) : status;
}

pqscan_status rule_set_load(const rule_source *source, rule_set **out, rule_error *error) {
    error->message[0] = '\0';
    rule_set *set = rule_set_create();
    if (set == NULL) {
        return PQSCAN_ERR_NOMEM;
    }
    cJSON *document = json_parse_document(source->text, source->len, error);
    pqscan_status status = PQSCAN_ERR_RULES;
    if (document != NULL) {
        loader load = {set, {error, PQSCAN_ERR_RULES, NULL, 0}};
        status = load_document(&load, document);
        cJSON_Delete(document);
    }
    if (status != PQSCAN_OK) {
        rule_set_destroy(set);
        return status;
    }
    *out = set;
    return PQSCAN_OK;
}
