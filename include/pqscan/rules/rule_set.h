/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_RULES_RULE_SET_H
#define PQSCAN_RULES_RULE_SET_H

#include "pqscan/core/primitive.h"
#include "pqscan/core/status.h"
#include "pqscan/risk/risk.h"

#include <stdbool.h>
#include <stddef.h>

/** More algorithms than this are refused, which also bounds each search by name. */
enum { RULE_SET_MAX_ALGORITHMS = 256 };

/** Marks a call that has no argument of this kind. */
enum { CALL_NO_ARGUMENT = -1 };

/** What a pattern stands for in source code. */
typedef enum rule_kind {
    RULE_FUNCTION = 0,
    RULE_CONSTANT,
    RULE_MACRO,
    RULE_STRING, /**< An algorithm name passed to a call. Ignores case, as OpenSSL does. */
    RULE_CONFIG, /**< One word of a TLS or SSH setting, such as "ssh-rsa". Ignores case. */
    RULE_KEY,    /**< OpenSSL's short name for a key or digest type, such as "rsaEncryption". */
} rule_kind;

/** Maps a pattern to what it means. Strings are not owned by this struct. */
typedef struct crypto_rule {
    const char *pattern;
    rule_kind kind;
    const algorithm_policy *algorithm; /**< Must belong to the set the rule is added to. */
    crypto_primitive primitive;
    bool call_only;    /**< Count it only when called, for names that are also ordinary words. */
    unsigned key_bits; /**< The key size the pattern fixes, as "ffdhe2048" does. 0 if none. */
} crypto_rule;

/** Which arguments of a known call are worth reading. */
typedef struct call_signature {
    const char *name;       /**< Not owned by this struct. */
    int key_bits_argument;  /**< Index of the key size, or CALL_NO_ARGUMENT. */
    int algorithm_argument; /**< Index of a string naming an algorithm, or CALL_NO_ARGUMENT. */
} call_signature;

/**
 * Every rule pqscan knows. It owns all its strings, which stay valid and unmoved until
 * rule_set_destroy(), so findings can point at algorithm names instead of copying them.
 *
 * A set is built with the rule_set_add_* functions, then rule_set_seal() makes it searchable.
 */
typedef struct rule_set rule_set;

/**
 * @brief Create an empty set.
 *
 * @return The set, owned by the caller and freed with rule_set_destroy(), or NULL if out
 *         of memory.
 */
rule_set *rule_set_create(void);

/**
 * @brief Free a set. Anything borrowed from it, such as a finding's algorithm, dies with it.
 *
 * @param set The set to free. May be NULL.
 */
void rule_set_destroy(rule_set *set);

/**
 * @brief Add an algorithm.
 *
 * @param set The set.
 * @param policy The policy to copy, including its name.
 * @return PQSCAN_OK, PQSCAN_ERR_NOMEM, or PQSCAN_ERR_RULES if the set already holds this
 *         name or RULE_SET_MAX_ALGORITHMS algorithms.
 */
pqscan_status rule_set_add_algorithm(rule_set *set, const algorithm_policy *policy);

/**
 * @brief Look up an algorithm added to a set.
 *
 * @param set The set.
 * @param name The normalized name.
 * @return The policy, owned by the set, or NULL if it is not known. It stays at this address
 *         until the set is destroyed.
 */
const algorithm_policy *rule_set_find_algorithm(const rule_set *set, const char *name);

/**
 * @brief Add a rule.
 *
 * @param set The set. Must not be sealed.
 * @param rule The rule to copy, including its pattern.
 * @return PQSCAN_OK or PQSCAN_ERR_NOMEM.
 */
pqscan_status rule_set_add_rule(rule_set *set, const crypto_rule *rule);

/**
 * @brief Add a call signature.
 *
 * @param set The set. Must not be sealed.
 * @param call The signature to copy, including its name.
 * @return PQSCAN_OK or PQSCAN_ERR_NOMEM.
 */
pqscan_status rule_set_add_call(rule_set *set, const call_signature *call);

/**
 * @brief Finish a set by sorting it for search. Nothing can be added afterwards.
 *
 * @param set The set.
 * @param duplicate On PQSCAN_ERR_RULES, the name that appears twice, owned by the set.
 *                  Untouched otherwise.
 * @return PQSCAN_OK, or PQSCAN_ERR_RULES if two rules of the same kind family or two calls
 *         share a name. Source identifiers form one family, and each other kind forms its own.
 *         Every pattern but a source identifier is compared ignoring case.
 */
pqscan_status rule_set_seal(rule_set *set, const char **duplicate);

/**
 * @brief Find the rule for an identifier that is merely mentioned, not called.
 *
 * @param set A sealed set.
 * @param name The start of the identifier. It need not be NUL-terminated.
 * @param len The length of the identifier.
 * @return The rule, owned by the set, or NULL if none applies. This skips call_only rules.
 */
const crypto_rule *rule_set_find_mention(const rule_set *set, const char *name, size_t len);

/**
 * @brief Find the rule for the name of a called function.
 *
 * @param set A sealed set.
 * @param name The start of the name. It need not be NUL-terminated.
 * @param len The length of the name.
 * @return The rule, owned by the set, or NULL if none applies.
 */
const crypto_rule *rule_set_find_callee(const rule_set *set, const char *name, size_t len);

/**
 * @brief Find the rule for a string naming an algorithm, ignoring case.
 *
 * @param set A sealed set.
 * @param text The start of the string. It need not be NUL-terminated.
 * @param len The length of the string.
 * @return The rule, owned by the set, or NULL if none applies.
 */
const crypto_rule *rule_set_find_string(const rule_set *set, const char *text, size_t len);

/**
 * @brief Find the rule for one word of a list in a configuration file, ignoring case.
 *
 * @param set A sealed set.
 * @param text The start of the word. It need not be NUL-terminated.
 * @param len The length of the word.
 * @return The rule, owned by the set, or NULL if none applies.
 */
const crypto_rule *rule_set_find_config_token(const rule_set *set, const char *text, size_t len);

/**
 * @brief Find the rule for a key or digest type, by OpenSSL's short name, ignoring case.
 *
 * @param set A sealed set.
 * @param name The short name, such as "id-ecPublicKey". NUL-terminated.
 * @return The rule, owned by the set, or NULL if none applies.
 */
const crypto_rule *rule_set_find_key_type(const rule_set *set, const char *name);

/**
 * @brief Find the signature of a call.
 *
 * @param set A sealed set.
 * @param name The start of the function name. It need not be NUL-terminated.
 * @param len The length of the name.
 * @return The signature, owned by the set, or NULL if it is not known.
 */
const call_signature *rule_set_find_call(const rule_set *set, const char *name, size_t len);

#endif /* PQSCAN_RULES_RULE_SET_H */
