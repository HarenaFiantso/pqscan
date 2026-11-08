/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/report/json_report.h"

#include "pqscan/core/finding.h"
#include "pqscan/core/primitive.h"
#include "pqscan/core/skip_list.h"
#include "pqscan/core/status.h"
#include "pqscan/core/utc_time.h"
#include "pqscan/core/version.h"
#include "pqscan/report/json_writer.h"
#include "pqscan/report/key_size_json.h"
#include "pqscan/report/report_summary.h"
#include "pqscan/report/reporter.h"
#include "pqscan/risk/priority.h"
#include "pqscan/risk/risk.h"

#include <stddef.h>
#include <stdio.h>

/* Raised when a change could break a consumer of this format. */
enum { JSON_SCHEMA_VERSION = 2 };

static void write_tool(json_writer *json) {
    json_key(json, "tool");
    json_begin_object(json);
    json_field_string(json, "name", "pqscan");
    json_field_string(json, "version", pqscan_version());
    json_end_object(json);
}

static void write_summary(json_writer *json, const finding_list *findings) {
    const risk_counts counts = risk_counts_of(findings);
    json_key(json, "summary");
    json_begin_object(json);
    json_field_uint(json, "total", finding_list_count(findings));
    json_key(json, "by_risk");
    json_begin_object(json);
    for (int level = RISK_OK; level < RISK_LEVEL_COUNT; level++) {
        json_field_uint(json, risk_level_name((risk_level)level), counts.by_level[level]);
    }
    json_end_object(json);
    json_end_object(json);
}

/* null when the finding is about the whole file. */
static void write_line(json_writer *json, size_t line) {
    json_key(json, "line");
    if (line > 0) {
        json_uint(json, line);
    } else {
        json_null(json);
    }
}

static void write_expiry(json_writer *json, const utc_time *expires) {
    json_key(json, "expires");
    if (expires->known) {
        char text[UTC_TIME_TEXT_SIZE];
        utc_time_format(expires, text, sizeof(text));
        json_string(json, text);
    } else {
        json_null(json);
    }
}

static void write_component(json_writer *json, const char *component) {
    json_key(json, "component");
    if (component != NULL) {
        json_string(json, component);
    } else {
        json_null(json);
    }
}

/* null when Shor's algorithm does not apply, so Mosca's theorem has nothing to say. */
static void write_timeline(json_writer *json, const quantum_timeline *timeline) {
    json_key(json, "quantum_timeline");
    if (!timeline->applies) {
        json_null(json);
        return;
    }
    json_begin_object(json);
    json_field_int(json, "secrecy_years", timeline->secrecy_years);
    json_field_int(json, "migration_years", timeline->migration_years);
    json_field_int(json, "years_to_quantum", timeline->years_to_quantum);
    json_key(json, "exposed");
    json_bool(json, quantum_timeline_exposed(timeline));
    json_field_int(json, "migration_ends", timeline->migration_end_year);
    json_field_string(json, "ir8547", ir8547_status_name(timeline->status));
    json_end_object(json);
}

static void write_priority(json_writer *json, const priority *rank) {
    json_key(json, "priority");
    json_begin_object(json);
    json_field_uint(json, "score", rank->score);
    write_component(json, rank->component);
    write_timeline(json, &rank->timeline);
    json_end_object(json);
}

static void write_finding(json_writer *json, const finding *item) {
    json_begin_object(json);
    json_field_string(json, "path", item->path);
    write_line(json, item->line);
    json_field_string(json, "symbol", item->symbol);
    json_field_string(json, "algorithm", item->algorithm);
    json_key(json, "key_size");
    key_size_json_write(json, item->size);
    json_field_string(json, "primitive", crypto_primitive_name(item->primitive));
    json_field_string(json, "risk", risk_level_name(item->risk));
    write_expiry(json, &item->expires);
    write_priority(json, &item->priority);
    json_end_object(json);
}

static void write_findings(json_writer *json, const finding_list *findings) {
    json_key(json, "findings");
    json_begin_array(json);
    for (size_t i = 0; i < finding_list_count(findings); i++) {
        write_finding(json, finding_list_get(findings, i));
    }
    json_end_array(json);
}

static void write_unanalyzed(json_writer *json, const skip_list *skipped) {
    json_key(json, "unanalyzed");
    json_begin_array(json);
    for (size_t i = 0; i < skip_list_count(skipped); i++) {
        const skipped_path *entry = skip_list_get(skipped, i);
        json_begin_object(json);
        json_field_string(json, "path", entry->path);
        json_field_string(json, "reason", pqscan_status_message(entry->reason));
        json_end_object(json);
    }
    json_end_array(json);
}

static pqscan_status write_json(const scan_report *report, FILE *out) {
    json_writer json;
    json_writer_init(&json, out);
    json_begin_object(&json);
    json_field_uint(&json, "schema_version", JSON_SCHEMA_VERSION);
    write_tool(&json);
    json_key(&json, "complete");
    json_bool(&json, skip_list_count(report->skipped) == 0);
    write_summary(&json, report->findings);
    write_findings(&json, report->findings);
    write_unanalyzed(&json, report->skipped);
    json_end_object(&json);
    return json_writer_finish(&json);
}

const reporter json_reporter = {"json", write_json};
