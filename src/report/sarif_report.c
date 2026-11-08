/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/report/sarif_report.h"

#include "pqscan/core/finding.h"
#include "pqscan/core/key_size.h"
#include "pqscan/core/skip_list.h"
#include "pqscan/core/status.h"
#include "pqscan/core/utc_time.h"
#include "pqscan/core/version.h"
#include "pqscan/report/json_writer.h"
#include "pqscan/report/reporter.h"
#include "pqscan/report/sarif_uri.h"
#include "pqscan/risk/risk.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char SCHEMA_URI[] = "https://json.schemastore.org/sarif-2.1.0.json";
static const char INFORMATION_URI[] = "https://github.com/HarenaFiantso/pqscan";
static const char RULE_PREFIX[] = "pqscan/";

/* security-severity is what GitHub turns into critical, high, medium or low. */
typedef struct risk_style {
    const char *level;
    const char *security_severity;
} risk_style;

static const risk_style RISK_STYLES[RISK_LEVEL_COUNT] = {
    [RISK_OK] = {"note", "1.0"},
    [RISK_REVIEW] = {"warning", "4.0"},
    [RISK_QUANTUM_VULNERABLE] = {"error", "8.0"},
    [RISK_CLASSICALLY_WEAK] = {"error", "9.0"},
};

static int compare_algorithms(const void *left, const void *right) {
    const finding *first = *(const finding *const *)left;
    const finding *second = *(const finding *const *)right;
    return strcmp(first->algorithm, second->algorithm);
}

static void write_rule_id(json_writer *json, const char *key, const char *algorithm) {
    json_key(json, key);
    json_begin_string(json);
    json_append(json, RULE_PREFIX);
    json_append(json, algorithm);
    json_end_string(json);
}

static void write_rule_description(json_writer *json, const char *algorithm) {
    json_key(json, "shortDescription");
    json_begin_object(json);
    json_key(json, "text");
    json_begin_string(json);
    json_append(json, "Use of ");
    json_append(json, algorithm);
    json_end_string(json);
    json_end_object(json);
}

static void write_rule_properties(json_writer *json, risk_level risk) {
    json_key(json, "properties");
    json_begin_object(json);
    json_key(json, "tags");
    json_begin_array(json);
    json_string(json, "security");
    json_string(json, "cryptography");
    json_end_array(json);
    json_field_string(json, "security-severity", RISK_STYLES[risk].security_severity);
    json_end_object(json);
}

/* One key size can make an algorithm worse than another, so a rule shows its worst use. */
static void write_rule(json_writer *json, const char *algorithm, risk_level worst) {
    json_begin_object(json);
    write_rule_id(json, "id", algorithm);
    write_rule_description(json, algorithm);
    write_rule_properties(json, worst);
    json_end_object(json);
}

/* Writes the rule of the group that starts at sorted[0], and tells how long the group is. */
static size_t write_rule_group(json_writer *json, const finding *const *sorted, size_t count) {
    risk_level worst = sorted[0]->risk;
    size_t len = 1;
    while (len < count && strcmp(sorted[len]->algorithm, sorted[0]->algorithm) == 0) {
        worst = (sorted[len]->risk > worst) ? sorted[len]->risk : worst;
        len++;
    }
    write_rule(json, sorted[0]->algorithm, worst);
    return len;
}

static void write_rules(json_writer *json, const finding *const *sorted, size_t count) {
    json_key(json, "rules");
    json_begin_array(json);
    for (size_t done = 0; done < count;) {
        done += write_rule_group(json, &sorted[done], count - done);
    }
    json_end_array(json);
}

static void write_tool(json_writer *json, const finding *const *sorted, size_t count) {
    json_key(json, "tool");
    json_begin_object(json);
    json_key(json, "driver");
    json_begin_object(json);
    json_field_string(json, "name", "pqscan");
    json_field_string(json, "version", pqscan_version());
    json_field_string(json, "semanticVersion", pqscan_version());
    json_field_string(json, "informationUri", INFORMATION_URI);
    write_rules(json, sorted, count);
    json_end_object(json);
    json_end_object(json);
}

static void write_location(json_writer *json, const char *path, size_t line) {
    json_begin_object(json);
    json_key(json, "physicalLocation");
    json_begin_object(json);
    json_key(json, "artifactLocation");
    json_begin_object(json);
    json_key(json, "uri");
    sarif_write_uri(json, path);
    json_end_object(json);
    if (line > 0) {
        json_key(json, "region");
        json_begin_object(json);
        json_field_uint(json, "startLine", line);
        json_end_object(json);
    }
    json_end_object(json);
    json_end_object(json);
}

static void write_finding_message(json_writer *json, const finding *item) {
    char key_suffix[KEY_SIZE_SUFFIX_SIZE];
    key_size_format_suffix(item->size, key_suffix, sizeof(key_suffix));
    json_key(json, "message");
    json_begin_object(json);
    json_key(json, "text");
    json_begin_string(json);
    json_append(json, item->symbol);
    json_append(json, " uses ");
    json_append(json, item->algorithm);
    json_append(json, key_suffix);
    json_append(json, ": ");
    json_append(json, risk_level_name(item->risk));
    json_end_string(json);
    json_end_object(json);
}

static bool has_properties(const finding *item) {
    return item->expires.known || item->priority.component != NULL;
}

/* SARIF has no field for when a certificate expires or what a finding belongs to, so they go
 * in the result's property bag. */
static void write_properties(json_writer *json, const finding *item) {
    if (!has_properties(item)) {
        return;
    }
    json_key(json, "properties");
    json_begin_object(json);
    if (item->expires.known) {
        char text[UTC_TIME_TEXT_SIZE];
        utc_time_format(&item->expires, text, sizeof(text));
        json_field_string(json, "expires", text);
    }
    if (item->priority.component != NULL) {
        json_field_string(json, "component", item->priority.component);
    }
    json_end_object(json);
}

static void write_result(json_writer *json, const finding *item) {
    json_begin_object(json);
    write_rule_id(json, "ruleId", item->algorithm);
    json_field_string(json, "level", RISK_STYLES[item->risk].level);
    json_field_uint(json, "rank", item->priority.score);
    write_finding_message(json, item);
    json_key(json, "locations");
    json_begin_array(json);
    write_location(json, item->path, item->line);
    json_end_array(json);
    write_properties(json, item);
    json_end_object(json);
}

static void write_results(json_writer *json, const finding_list *findings) {
    json_key(json, "results");
    json_begin_array(json);
    for (size_t i = 0; i < finding_list_count(findings); i++) {
        write_result(json, finding_list_get(findings, i));
    }
    json_end_array(json);
}

static void write_notification(json_writer *json, const skipped_path *entry) {
    json_begin_object(json);
    json_field_string(json, "level", "warning");
    json_key(json, "message");
    json_begin_object(json);
    json_field_string(json, "text", pqscan_status_message(entry->reason));
    json_end_object(json);
    json_key(json, "locations");
    json_begin_array(json);
    write_location(json, entry->path, 0);
    json_end_array(json);
    json_end_object(json);
}

/* A run that skipped something in scope did not do what it was asked to. */
static void write_invocation(json_writer *json, const skip_list *skipped) {
    json_key(json, "invocations");
    json_begin_array(json);
    json_begin_object(json);
    json_key(json, "executionSuccessful");
    json_bool(json, skip_list_count(skipped) == 0);
    json_key(json, "toolExecutionNotifications");
    json_begin_array(json);
    for (size_t i = 0; i < skip_list_count(skipped); i++) {
        write_notification(json, skip_list_get(skipped, i));
    }
    json_end_array(json);
    json_end_object(json);
    json_end_array(json);
}

static pqscan_status write_log(const scan_report *report, const finding *const *sorted, FILE *out) {
    json_writer json;
    json_writer_init(&json, out);
    json_begin_object(&json);
    json_field_string(&json, "$schema", SCHEMA_URI);
    json_field_string(&json, "version", "2.1.0");
    json_key(&json, "runs");
    json_begin_array(&json);
    json_begin_object(&json);
    write_tool(&json, sorted, finding_list_count(report->findings));
    write_invocation(&json, report->skipped);
    write_results(&json, report->findings);
    json_end_object(&json);
    json_end_array(&json);
    json_end_object(&json);
    return json_writer_finish(&json);
}

static pqscan_status write_sarif(const scan_report *report, FILE *out) {
    const finding **sorted = finding_list_pointers(report->findings);
    if (sorted == NULL) {
        return PQSCAN_ERR_NOMEM;
    }
    qsort((void *)sorted, finding_list_count(report->findings), sizeof(sorted[0]),
          compare_algorithms);
    const pqscan_status status = write_log(report, sorted, out);
    free((void *)sorted);
    return status;
}

const reporter sarif_reporter = {"sarif", write_sarif};
