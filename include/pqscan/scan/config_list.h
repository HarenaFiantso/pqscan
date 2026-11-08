/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_SCAN_CONFIG_LIST_H
#define PQSCAN_SCAN_CONFIG_LIST_H

#include "pqscan/core/status.h"
#include "pqscan/rules/rule_set.h"
#include "pqscan/scan/config_lexer.h"

#include <stddef.h>

/** How the value of a setting lists algorithms. */
typedef enum config_list_syntax {
    /**
     * OpenSSL's lists: cipher strings, groups and signature algorithms. Entries are separated
     * by ':', ',', '/' or whitespace. An entry starting with '!' or '-' takes algorithms away,
     * so it is skipped, and one starting with '@' is a command such as @SECLEVEL=2. A leading
     * '+', '?' or '*' only changes order or preference. Inside an entry, '-' and '+' join
     * parts, as in ECDHE-RSA-AES128-GCM-SHA256 or RSA+SHA256: the longest run of parts that
     * a rule names is taken first, so DES-CBC3-SHA is 3DES and SHA-1, not DES.
     */
    CONFIG_LIST_OPENSSL,
    /**
     * OpenSSH's lists, separated by ','. A leading '-' removes every name in the list, so the
     * list is skipped. A leading '+' or '^' only adds to the defaults. Each name is matched whole.
     */
    CONFIG_LIST_SSH,
    /** One name, such as the digest of default_md. */
    CONFIG_LIST_SINGLE,
} config_list_syntax;

/** One algorithm named in a setting. */
typedef struct config_match {
    const crypto_rule *rule; /**< Owned by the rule set. */
    size_t line;             /**< Where the name is, which a quoted word can push past its start. */
} config_match;

/**
 * @brief Be told about one match.
 *
 * @param match The match.
 * @param context What config_list_scan carries.
 * @return PQSCAN_OK to go on, anything else to stop with that status.
 */
typedef pqscan_status (*config_match_visitor)(const config_match *match, void *context);

/** How to read one word and whom to tell. Everything is borrowed. */
typedef struct config_list_scan {
    const rule_set *rules; /**< A sealed set. Its config tokens are searched. */
    config_list_syntax syntax;
    config_match_visitor visit;
    void *context;
} config_list_scan;

/**
 * @brief Report every algorithm a word names, in order.
 *
 * Runs in time linear in the word's length, whatever it holds.
 *
 * @param scan The rules, the syntax and the visitor.
 * @param word The word, as the lexer returned it.
 * @return PQSCAN_OK, or the first status other than PQSCAN_OK that the visitor returned.
 */
pqscan_status config_list_match(const config_list_scan *scan, const config_word *word);

#endif /* PQSCAN_SCAN_CONFIG_LIST_H */
