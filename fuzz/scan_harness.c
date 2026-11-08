/* SPDX-License-Identifier: Apache-2.0 */
#include "scan_harness.h"

#include "fuzz_checks.h"

#include "pqscan/core/finding.h"
#include "pqscan/core/key_size.h"
#include "pqscan/core/primitive.h"
#include "pqscan/core/status.h"
#include "pqscan/risk/risk.h"
#include "pqscan/rules/default_rules.h"
#include "pqscan/rules/rule_loader.h"
#include "pqscan/rules/rule_set.h"
#include "pqscan/scan/file_reader.h"
#include "pqscan/scan/scanner.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Loaded once and never freed: it stays reachable, so LeakSanitizer does not count it. */
static rule_set *built_in_rules;

static const rule_set *rules(void) {
    if (built_in_rules == NULL) {
        const rule_source source = default_rules_source();
        rule_error error;
        if (rule_set_load(&source, &built_in_rules, &error) != PQSCAN_OK) {
            abort();
        }
    }
    return built_in_rules;
}

static bool is_name(const char *name) { return name != NULL && name[0] != '\0'; }

/* What every reporter takes for granted about a finding. */
static bool is_sound(const finding *item, const char *path, size_t lines) {
    return strcmp(item->path, path) == 0 && item->line <= lines && is_name(item->algorithm) &&
           is_name(item->symbol) && (unsigned)item->risk < RISK_LEVEL_COUNT &&
           item->primitive <= PRIMITIVE_HASH && item->size.kind <= KEY_SIZE_KNOWN;
}

static void check_findings(const finding_list *findings, const char *path, size_t lines) {
    for (size_t i = 0; i < finding_list_count(findings); i++) {
        if (!is_sound(finding_list_get(findings, i), path, lines)) {
            abort();
        }
    }
}

/* A scanner reads a file_contents, which always has a NUL after its last byte. */
static char *copy_as_text(const uint8_t *data, size_t size) {
    char *text = malloc(size + 1);
    if (text == NULL) {
        abort();
    }
    if (size > 0) {
        memcpy(text, data, size);
    }
    text[size] = '\0';
    return text;
}

void fuzz_scan(const fuzz_scan_case *scan_case, const uint8_t *data, size_t size) {
    finding_list *findings = finding_list_create();
    if (findings == NULL || !scan_case->active->accepts(scan_case->path)) {
        abort();
    }
    char *text = copy_as_text(data, size);
    const file_contents file = {text, size};
    const scan_input input = {scan_case->path, &file, rules()};
    if (scan_case->active->scan(&input, findings) == PQSCAN_ERR_NOMEM) {
        abort();
    }
    check_findings(findings, scan_case->path, fuzz_count_lines(data, size));
    finding_list_destroy(findings);
    free(text);
}
