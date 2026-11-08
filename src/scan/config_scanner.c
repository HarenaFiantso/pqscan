/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/scan/config_scanner.h"

#include "pqscan/core/finding.h"
#include "pqscan/core/key_size.h"
#include "pqscan/core/primitive.h"
#include "pqscan/core/status.h"
#include "pqscan/core/utc_time.h"
#include "pqscan/risk/risk.h"
#include "pqscan/rules/rule_set.h"
#include "pqscan/scan/config_lexer.h"
#include "pqscan/scan/config_list.h"
#include "pqscan/scan/file_reader.h"
#include "pqscan/scan/scanner.h"
#include "pqscan/walk/file_type.h"

#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>

/* Distinct names one statement can hold before repeats stop being folded together. Past it,
 * a repeat is reported again, which is noisy but never hides anything. */
enum { MAX_REMEMBERED_MATCHES = 64, MAX_KEY_BITS = 1024 * 1024, DECIMAL_BASE = 10 };

/* openssl req makes an RSA key unless told otherwise, and default_bits sets its size. */
static const char DEFAULT_KEY_ALGORITHM[] = "RSA";
static const char DEFAULT_BITS_SYMBOL[] = "default_bits";

typedef enum directive_action {
    READ_LISTS,        /* Every word after the name is a list. */
    READ_CONF_COMMAND, /* The first word names an SSL_CONF command, and the rest is its value. */
    READ_DEFAULT_BITS, /* The first word is the size of the keys openssl req makes. */
} directive_action;

typedef struct directive {
    const char *name;
    directive_action action;
    config_list_syntax syntax;
    bool is_conf_command; /* Whether nginx's and Apache's pass-through commands accept it. */
} directive;

/* Names are matched ignoring case: OpenSSH and Apache ignore it, and nginx's are lowercase. */
static const directive DIRECTIVES[] = {
    /* OpenSSL's SSL_CONF commands, as openssl.cnf writes them. */
    {"CipherString", READ_LISTS, CONFIG_LIST_OPENSSL, true},
    {"Ciphersuites", READ_LISTS, CONFIG_LIST_OPENSSL, true},
    {"Groups", READ_LISTS, CONFIG_LIST_OPENSSL, true},
    {"Curves", READ_LISTS, CONFIG_LIST_OPENSSL, true},
    {"SignatureAlgorithms", READ_LISTS, CONFIG_LIST_OPENSSL, true},
    {"ClientSignatureAlgorithms", READ_LISTS, CONFIG_LIST_OPENSSL, true},
    /* openssl.cnf's [req] and [ca] sections. */
    {"default_md", READ_LISTS, CONFIG_LIST_SINGLE, false},
    {"default_bits", READ_DEFAULT_BITS, CONFIG_LIST_SINGLE, false},
    /* nginx. */
    {"ssl_ciphers", READ_LISTS, CONFIG_LIST_OPENSSL, false},
    {"ssl_ecdh_curve", READ_LISTS, CONFIG_LIST_OPENSSL, false},
    {"proxy_ssl_ciphers", READ_LISTS, CONFIG_LIST_OPENSSL, false},
    {"grpc_ssl_ciphers", READ_LISTS, CONFIG_LIST_OPENSSL, false},
    {"ssl_conf_command", READ_CONF_COMMAND, CONFIG_LIST_OPENSSL, false},
    {"proxy_ssl_conf_command", READ_CONF_COMMAND, CONFIG_LIST_OPENSSL, false},
    {"grpc_ssl_conf_command", READ_CONF_COMMAND, CONFIG_LIST_OPENSSL, false},
    /* Apache's mod_ssl. */
    {"SSLCipherSuite", READ_LISTS, CONFIG_LIST_OPENSSL, false},
    {"SSLProxyCipherSuite", READ_LISTS, CONFIG_LIST_OPENSSL, false},
    {"SSLOpenSSLConfCmd", READ_CONF_COMMAND, CONFIG_LIST_OPENSSL, false},
    /* OpenSSH's sshd_config and ssh_config. */
    {"KexAlgorithms", READ_LISTS, CONFIG_LIST_SSH, false},
    {"HostKeyAlgorithms", READ_LISTS, CONFIG_LIST_SSH, false},
    {"PubkeyAcceptedAlgorithms", READ_LISTS, CONFIG_LIST_SSH, false},
    {"PubkeyAcceptedKeyTypes", READ_LISTS, CONFIG_LIST_SSH, false},
    {"HostbasedAcceptedAlgorithms", READ_LISTS, CONFIG_LIST_SSH, false},
    {"HostbasedAcceptedKeyTypes", READ_LISTS, CONFIG_LIST_SSH, false},
    {"CASignatureAlgorithms", READ_LISTS, CONFIG_LIST_SSH, false},
    {"Ciphers", READ_LISTS, CONFIG_LIST_SSH, false},
    {"MACs", READ_LISTS, CONFIG_LIST_SSH, false},
};

typedef struct config_walk {
    const scan_input *input;
    finding_list *findings;
    config_match reported[MAX_REMEMBERED_MATCHES]; /* What this statement already reported. */
    size_t reported_count;
} config_walk;

static bool word_is(const config_word *word, const char *name) {
    return word->len == strlen(name) && strncasecmp(word->text, name, word->len) == 0;
}

static const directive *find_directive(const config_word *name) {
    for (size_t i = 0; i < sizeof(DIRECTIVES) / sizeof(DIRECTIVES[0]); i++) {
        if (word_is(name, DIRECTIVES[i].name)) {
            return &DIRECTIVES[i];
        }
    }
    return NULL;
}

static pqscan_status add_finding(const config_walk *walk, const finding *item) {
    return finding_list_add(walk->findings, item);
}

static key_size fixed_size(const crypto_rule *rule) {
    const key_size size = {(rule->key_bits > 0) ? KEY_SIZE_KNOWN : KEY_SIZE_NOT_APPLICABLE,
                           rule->key_bits};
    return size;
}

static bool was_reported(const config_walk *walk, const config_match *match) {
    for (size_t i = 0; i < walk->reported_count; i++) {
        if (walk->reported[i].rule == match->rule && walk->reported[i].line == match->line) {
            return true;
        }
    }
    return false;
}

static void remember(config_walk *walk, const config_match *match) {
    if (walk->reported_count < MAX_REMEMBERED_MATCHES) {
        walk->reported[walk->reported_count++] = *match;
    }
}

static pqscan_status report_match(const config_match *match, void *context) {
    config_walk *walk = context;
    if (was_reported(walk, match)) {
        return PQSCAN_OK;
    }
    remember(walk, match);
    const crypto_rule *rule = match->rule;
    const key_size size = fixed_size(rule);
    const finding item = {
        walk->input->path,
        match->line,
        rule->algorithm->name,
        risk_classify(rule->algorithm, size),
        size,
        rule->primitive,
        rule->pattern,
        utc_time_none(),
    };
    return add_finding(walk, &item);
}

static pqscan_status read_lists(config_walk *walk, const config_statement *statement, size_t first,
                                config_list_syntax syntax) {
    const config_list_scan scan = {walk->input->rules, syntax, report_match, walk};
    for (size_t i = first; i < statement->count; i++) {
        const pqscan_status status = config_list_match(&scan, &statement->words[i]);
        if (status != PQSCAN_OK) {
            return status;
        }
    }
    return PQSCAN_OK;
}

static pqscan_status read_conf_command(config_walk *walk, const config_statement *statement) {
    if (statement->count < 2) {
        return PQSCAN_OK;
    }
    const directive *command = find_directive(&statement->words[1]);
    if (command == NULL || !command->is_conf_command) {
        return PQSCAN_OK;
    }
    return read_lists(walk, statement, 2, command->syntax);
}

/* Anything but a plain decimal in range, such as ${ENV::BITS}, is a size pqscan cannot tell. */
static key_size parse_key_bits(const config_word *word) {
    const key_size unknown = {KEY_SIZE_UNKNOWN, 0};
    if (word->len == 0) {
        return unknown;
    }
    unsigned bits = 0;
    for (size_t i = 0; i < word->len; i++) {
        const char digit = word->text[i];
        if (digit < '0' || digit > '9') {
            return unknown;
        }
        bits = (bits * DECIMAL_BASE) + (unsigned)(digit - '0');
        if (bits > MAX_KEY_BITS) {
            return unknown;
        }
    }
    const key_size known = {KEY_SIZE_KNOWN, bits};
    return (bits > 0) ? known : unknown;
}

static pqscan_status read_default_bits(const config_walk *walk, const config_statement *statement) {
    const algorithm_policy *policy =
        rule_set_find_algorithm(walk->input->rules, DEFAULT_KEY_ALGORITHM);
    if (statement->count < 2 || policy == NULL) {
        return PQSCAN_OK;
    }
    const config_word *value = &statement->words[1];
    const key_size size = parse_key_bits(value);
    const finding item = {
        walk->input->path,
        value->line,
        policy->name,
        risk_classify(policy, size),
        size,
        PRIMITIVE_UNSPECIFIED,
        DEFAULT_BITS_SYMBOL,
        utc_time_none(),
    };
    return add_finding(walk, &item);
}

static pqscan_status read_statement(config_walk *walk, const config_statement *statement) {
    const directive *found = find_directive(&statement->words[0]);
    if (found == NULL) {
        return PQSCAN_OK;
    }
    walk->reported_count = 0;
    switch (found->action) {
    case READ_LISTS:
        return read_lists(walk, statement, 1, found->syntax);
    case READ_CONF_COMMAND:
        return read_conf_command(walk, statement);
    case READ_DEFAULT_BITS:
        return read_default_bits(walk, statement);
    }
    return PQSCAN_OK;
}

static pqscan_status scan_config(const scan_input *input, finding_list *findings) {
    const file_contents *file = input->file;
    if (memchr(file->data, '\0', file->len) != NULL) {
        return PQSCAN_ERR_BINARY;
    }
    config_walk walk = {input, findings, {{NULL, 0}}, 0};
    config_lexer lexer;
    config_lexer_init(&lexer, file->data, file->len);
    config_statement statement;
    while (config_lexer_next(&lexer, &statement)) {
        const pqscan_status status = read_statement(&walk, &statement);
        if (status != PQSCAN_OK) {
            return status;
        }
    }
    return PQSCAN_OK;
}

const scanner config_scanner = {"config", file_type_is_config, scan_config};
