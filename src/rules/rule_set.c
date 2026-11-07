/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/rules/rule_set.h"

#include "pqscan/core/memory.h"
#include "pqscan/core/status.h"
#include "pqscan/risk/risk.h"

#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

typedef struct rule_list {
    crypto_rule *items;
    size_t count;
    size_t capacity;
} rule_list;

/* A name that need not be NUL-terminated, as source text never is. */
typedef struct text_key {
    const char *text;
    size_t len;
} text_key;

/* The algorithms sit inside the struct because rules point at them: an array that could
 * grow would move them and leave every one of those pointers dangling. */
struct rule_set {
    algorithm_policy algorithms[RULE_SET_MAX_ALGORITHMS];
    size_t algorithm_count;
    rule_list identifiers;
    rule_list strings;
    call_signature *calls;
    size_t call_count;
    size_t call_capacity;
};

static void rule_list_destroy(rule_list *list) {
    for (size_t i = 0; i < list->count; i++) {
        free((void *)list->items[i].pattern);
    }
    free(list->items);
}

rule_set *rule_set_create(void) { return calloc(1, sizeof(rule_set)); }

void rule_set_destroy(rule_set *set) {
    if (set == NULL) {
        return;
    }
    for (size_t i = 0; i < set->algorithm_count; i++) {
        free((void *)set->algorithms[i].name);
    }
    rule_list_destroy(&set->identifiers);
    rule_list_destroy(&set->strings);
    for (size_t i = 0; i < set->call_count; i++) {
        free((void *)set->calls[i].name);
    }
    free(set->calls);
    free(set);
}

pqscan_status rule_set_add_algorithm(rule_set *set, const algorithm_policy *policy) {
    if (set->algorithm_count == RULE_SET_MAX_ALGORITHMS ||
        rule_set_find_algorithm(set, policy->name) != NULL) {
        return PQSCAN_ERR_RULES;
    }
    const char *name = strdup(policy->name);
    if (name == NULL) {
        return PQSCAN_ERR_NOMEM;
    }
    algorithm_policy *stored = &set->algorithms[set->algorithm_count++];
    *stored = *policy;
    stored->name = name;
    return PQSCAN_OK;
}

const algorithm_policy *rule_set_find_algorithm(const rule_set *set, const char *name) {
    for (size_t i = 0; i < set->algorithm_count; i++) {
        if (strcmp(set->algorithms[i].name, name) == 0) {
            return &set->algorithms[i];
        }
    }
    return NULL;
}

static pqscan_status rule_list_add(rule_list *list, const crypto_rule *rule) {
    if (list->count == list->capacity) {
        crypto_rule *grown =
            pqscan_array_grow(list->items, &list->capacity, sizeof(list->items[0]));
        if (grown == NULL) {
            return PQSCAN_ERR_NOMEM;
        }
        list->items = grown;
    }
    const char *pattern = strdup(rule->pattern);
    if (pattern == NULL) {
        return PQSCAN_ERR_NOMEM;
    }
    list->items[list->count] = *rule;
    list->items[list->count].pattern = pattern;
    list->count++;
    return PQSCAN_OK;
}

pqscan_status rule_set_add_rule(rule_set *set, const crypto_rule *rule) {
    return rule_list_add((rule->kind == RULE_STRING) ? &set->strings : &set->identifiers, rule);
}

pqscan_status rule_set_add_call(rule_set *set, const call_signature *call) {
    if (set->call_count == set->call_capacity) {
        call_signature *grown =
            pqscan_array_grow(set->calls, &set->call_capacity, sizeof(set->calls[0]));
        if (grown == NULL) {
            return PQSCAN_ERR_NOMEM;
        }
        set->calls = grown;
    }
    const char *name = strdup(call->name);
    if (name == NULL) {
        return PQSCAN_ERR_NOMEM;
    }
    set->calls[set->call_count] = *call;
    set->calls[set->call_count].name = name;
    set->call_count++;
    return PQSCAN_OK;
}

static int compare_exact(const text_key *key, const char *name) {
    const int order = strncmp(key->text, name, key->len);
    if (order != 0) {
        return order;
    }
    /* strncmp() stops at a NUL in both, so the name may be shorter than the key. */
    if (strnlen(name, key->len) < key->len) {
        return 1;
    }
    /* The first len bytes are equal, so a longer name sorts after the key. */
    return (name[key->len] == '\0') ? 0 : -1;
}

static int compare_ignoring_case(const text_key *key, const char *name) {
    for (size_t i = 0; i < key->len; i++) {
        if (name[i] == '\0') {
            return 1; /* A NUL in the key would otherwise equal the end of the name. */
        }
        const int left = tolower((unsigned char)key->text[i]);
        const int right = tolower((unsigned char)name[i]);
        if (left != right) {
            return left - right;
        }
    }
    return (name[key->len] == '\0') ? 0 : -1;
}

/* The sort below and the search must order names the same way, or bsearch() misses entries. */
static int order_identifiers(const void *left_ptr, const void *right_ptr) {
    const crypto_rule *left = left_ptr;
    const crypto_rule *right = right_ptr;
    return strcmp(left->pattern, right->pattern);
}

static int order_strings(const void *left_ptr, const void *right_ptr) {
    const crypto_rule *left = left_ptr;
    const crypto_rule *right = right_ptr;
    const text_key key = {left->pattern, strlen(left->pattern)};
    return compare_ignoring_case(&key, right->pattern);
}

static int order_calls(const void *left_ptr, const void *right_ptr) {
    const call_signature *left = left_ptr;
    const call_signature *right = right_ptr;
    return strcmp(left->name, right->name);
}

static const char *find_adjacent_rules(const rule_list *list,
                                       int (*order)(const void *, const void *)) {
    for (size_t i = 1; i < list->count; i++) {
        if (order(&list->items[i - 1], &list->items[i]) == 0) {
            return list->items[i].pattern;
        }
    }
    return NULL;
}

static const char *find_adjacent_calls(const rule_set *set) {
    for (size_t i = 1; i < set->call_count; i++) {
        if (order_calls(&set->calls[i - 1], &set->calls[i]) == 0) {
            return set->calls[i].name;
        }
    }
    return NULL;
}

static const char *find_duplicate(const rule_set *set) {
    const char *name = find_adjacent_rules(&set->identifiers, order_identifiers);
    if (name == NULL) {
        name = find_adjacent_rules(&set->strings, order_strings);
    }
    return (name != NULL) ? name : find_adjacent_calls(set);
}

static void sort_rules(rule_list *list, int (*order)(const void *, const void *)) {
    if (list->count > 0) {
        qsort(list->items, list->count, sizeof(list->items[0]), order);
    }
}

pqscan_status rule_set_seal(rule_set *set, const char **duplicate) {
    sort_rules(&set->identifiers, order_identifiers);
    sort_rules(&set->strings, order_strings);
    if (set->call_count > 0) {
        qsort(set->calls, set->call_count, sizeof(set->calls[0]), order_calls);
    }
    const char *name = find_duplicate(set);
    if (name != NULL) {
        *duplicate = name;
        return PQSCAN_ERR_RULES;
    }
    return PQSCAN_OK;
}

static int compare_key_to_identifier(const void *key_ptr, const void *entry_ptr) {
    const crypto_rule *entry = entry_ptr;
    return compare_exact(key_ptr, entry->pattern);
}

static int compare_key_to_string(const void *key_ptr, const void *entry_ptr) {
    const crypto_rule *entry = entry_ptr;
    return compare_ignoring_case(key_ptr, entry->pattern);
}

static int compare_key_to_call(const void *key_ptr, const void *entry_ptr) {
    const call_signature *entry = entry_ptr;
    return compare_exact(key_ptr, entry->name);
}

const crypto_rule *rule_set_find_callee(const rule_set *set, const char *name, size_t len) {
    if (set->identifiers.count == 0) {
        return NULL;
    }
    const text_key key = {name, len};
    return bsearch(&key, set->identifiers.items, set->identifiers.count,
                   sizeof(set->identifiers.items[0]), compare_key_to_identifier);
}

const crypto_rule *rule_set_find_mention(const rule_set *set, const char *name, size_t len) {
    const crypto_rule *rule = rule_set_find_callee(set, name, len);
    return (rule != NULL && !rule->call_only) ? rule : NULL;
}

const crypto_rule *rule_set_find_string(const rule_set *set, const char *text, size_t len) {
    if (set->strings.count == 0) {
        return NULL;
    }
    const text_key key = {text, len};
    return bsearch(&key, set->strings.items, set->strings.count, sizeof(set->strings.items[0]),
                   compare_key_to_string);
}

const call_signature *rule_set_find_call(const rule_set *set, const char *name, size_t len) {
    if (set->call_count == 0) {
        return NULL;
    }
    const text_key key = {name, len};
    return bsearch(&key, set->calls, set->call_count, sizeof(set->calls[0]), compare_key_to_call);
}
