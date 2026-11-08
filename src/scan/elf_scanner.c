/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/scan/elf_scanner.h"

#include "pqscan/core/finding.h"
#include "pqscan/core/key_size.h"
#include "pqscan/core/status.h"
#include "pqscan/core/utc_time.h"
#include "pqscan/risk/priority.h"
#include "pqscan/risk/risk.h"
#include "pqscan/rules/rule_set.h"
#include "pqscan/scan/elf_reader.h"
#include "pqscan/scan/file_reader.h"
#include "pqscan/scan/scanner.h"
#include "pqscan/walk/file_type.h"

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

enum { WHOLE_FILE = 0 };

typedef struct elf_walk {
    const scan_input *input;
    finding_list *findings;
    size_t first; /* Index of this file's first finding, where duplicates are looked for. */
} elf_walk;

/* A defined untyped symbol is a label, not a function. */
static bool names_code(const elf_symbol *symbol) {
    return symbol->type == ELF_SYMBOL_FUNCTION ||
           (symbol->type == ELF_SYMBOL_UNTYPED && !symbol->defined);
}

static bool already_found(const elf_walk *walk, const crypto_rule *rule) {
    for (size_t i = walk->first; i < finding_list_count(walk->findings); i++) {
        if (strcmp(finding_list_get(walk->findings, i)->symbol, rule->pattern) == 0) {
            return true;
        }
    }
    return false;
}

static key_size size_in_binary(const rule_set *rules, const crypto_rule *rule) {
    const call_signature *call = rule_set_find_call(rules, rule->pattern, strlen(rule->pattern));
    const bool takes_size = call != NULL && call->key_bits_argument != CALL_NO_ARGUMENT;
    const key_size size = {takes_size ? KEY_SIZE_UNKNOWN : KEY_SIZE_NOT_APPLICABLE, 0};
    return size;
}

// cppcheck-suppress constParameterCallback
static pqscan_status report_symbol(const elf_symbol *symbol, void *context) {
    const elf_walk *walk = context;
    const rule_set *rules = walk->input->rules;
    const crypto_rule *rule =
        names_code(symbol) ? rule_set_find_callee(rules, symbol->name, symbol->len) : NULL;
    if (rule == NULL || already_found(walk, rule)) {
        return PQSCAN_OK;
    }
    const key_size size = size_in_binary(rules, rule);
    const finding item = {
        walk->input->path,
        WHOLE_FILE,
        rule->algorithm->name,
        risk_classify(rule->algorithm, size),
        size,
        rule->primitive,
        rule->pattern,
        utc_time_none(),
        priority_none(),
    };
    return finding_list_add(walk->findings, &item);
}

static pqscan_status scan_elf(const scan_input *input, finding_list *findings) {
    elf_walk walk = {input, findings, finding_list_count(findings)};
    const elf_symbol_sink sink = {report_symbol, &walk};
    const file_contents *file = input->file;
    return elf_read_symbols((const unsigned char *)file->data, file->len, &sink);
}

const scanner elf_scanner = {"elf", file_type_is_elf, scan_elf};
