/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/report/cbom_report.h"

#include "pqscan/core/finding.h"
#include "pqscan/core/key_size.h"
#include "pqscan/core/primitive.h"
#include "pqscan/core/skip_list.h"
#include "pqscan/core/status.h"
#include "pqscan/core/version.h"
#include "pqscan/report/json_writer.h"
#include "pqscan/report/reporter.h"
#include "pqscan/risk/risk.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char SCHEMA_URI[] = "http://cyclonedx.org/schema/bom-1.6.schema.json";
static const char PRIMITIVE_UNKNOWN[] = "unknown";

/* CycloneDX has no plain "encryption": it asks what kind. Anything not listed stays unknown. */
typedef struct encryption_kind {
    const char *algorithm;
    const char *primitive;
} encryption_kind;

static const encryption_kind ENCRYPTION_KINDS[] = {
    {"RSA", "pke"},
    {"3DES", "block-cipher"},
    {"AES-128", "block-cipher"},
    {"AES-192", "block-cipher"},
    {"AES-256", "block-cipher"},
    {"DES", "block-cipher"},
    {"RC4", "stream-cipher"},
};

static const char *encryption_primitive(const char *algorithm) {
    for (size_t i = 0; i < sizeof(ENCRYPTION_KINDS) / sizeof(ENCRYPTION_KINDS[0]); i++) {
        if (strcmp(algorithm, ENCRYPTION_KINDS[i].algorithm) == 0) {
            return ENCRYPTION_KINDS[i].primitive;
        }
    }
    return PRIMITIVE_UNKNOWN;
}

static const char *cyclonedx_primitive(const finding *item) {
    switch (item->primitive) {
    case PRIMITIVE_SIGNATURE:
        return "signature";
    case PRIMITIVE_KEY_EXCHANGE:
        return "key-agree";
    case PRIMITIVE_HASH:
        return "hash";
    case PRIMITIVE_ENCRYPTION:
        return encryption_primitive(item->algorithm);
    case PRIMITIVE_UNSPECIFIED:
        return PRIMITIVE_UNKNOWN;
    }
    return PRIMITIVE_UNKNOWN;
}

static int compare_numbers(size_t left, size_t right) { return (left > right) - (left < right); }

/* Zero means both findings belong to one component. */
static int compare_assets(const finding *left, const finding *right) {
    int order = strcmp(left->algorithm, right->algorithm);
    if (order == 0) {
        order = compare_numbers((size_t)left->size.kind, (size_t)right->size.kind);
    }
    if (order == 0 && left->size.kind == KEY_SIZE_KNOWN) {
        order = compare_numbers(left->size.bits, right->size.bits);
    }
    if (order == 0) {
        order = compare_numbers((size_t)left->primitive, (size_t)right->primitive);
    }
    return order;
}

/* qsort() does not keep equal items in order, so ties are broken all the way down to keep two
 * runs on the same files identical. */
static int compare_occurrences(const void *left, const void *right) {
    const finding *first = *(const finding *const *)left;
    const finding *second = *(const finding *const *)right;
    int order = compare_assets(first, second);
    if (order == 0) {
        order = strcmp(first->path, second->path);
    }
    if (order == 0) {
        order = compare_numbers(first->line, second->line);
    }
    return (order == 0) ? strcmp(first->symbol, second->symbol) : order;
}

static void write_property(json_writer *json, const char *name, const char *value) {
    json_begin_object(json);
    json_field_string(json, "name", name);
    json_field_string(json, "value", value);
    json_end_object(json);
}

static void write_tool(json_writer *json) {
    json_key(json, "tools");
    json_begin_object(json);
    json_key(json, "components");
    json_begin_array(json);
    json_begin_object(json);
    json_field_string(json, "type", "application");
    json_field_string(json, "name", "pqscan");
    json_field_string(json, "version", pqscan_version());
    json_end_object(json);
    json_end_array(json);
    json_end_object(json);
}

static void write_unanalyzed_property(json_writer *json, const skipped_path *entry) {
    json_begin_object(json);
    json_field_string(json, "name", "pqscan:unanalyzed");
    json_key(json, "value");
    json_begin_string(json);
    json_append(json, entry->path);
    json_append(json, ": ");
    json_append(json, pqscan_status_message(entry->reason));
    json_end_string(json);
    json_end_object(json);
}

/* CycloneDX has no field for a partial scan, and a BOM that hides one reads as complete. */
static void write_scan_properties(json_writer *json, const skip_list *skipped) {
    const size_t unanalyzed = skip_list_count(skipped);
    json_key(json, "properties");
    json_begin_array(json);
    write_property(json, "pqscan:scan-complete", (unanalyzed == 0) ? "true" : "false");
    for (size_t i = 0; i < unanalyzed; i++) {
        write_unanalyzed_property(json, skip_list_get(skipped, i));
    }
    json_end_array(json);
}

static void write_metadata(json_writer *json, const skip_list *skipped) {
    json_key(json, "metadata");
    json_begin_object(json);
    write_tool(json);
    write_scan_properties(json, skipped);
    json_end_object(json);
}

static void write_algorithm_properties(json_writer *json, const finding *asset) {
    json_key(json, "algorithmProperties");
    json_begin_object(json);
    json_field_string(json, "primitive", cyclonedx_primitive(asset));
    if (asset->size.kind == KEY_SIZE_KNOWN) {
        char bits[KEY_SIZE_SUFFIX_SIZE];
        (void)snprintf(bits, sizeof(bits), "%u", asset->size.bits);
        json_field_string(json, "parameterSetIdentifier", bits);
    }
    json_end_object(json);
}

static void write_crypto_properties(json_writer *json, const finding *asset) {
    json_key(json, "cryptoProperties");
    json_begin_object(json);
    json_field_string(json, "assetType", "algorithm");
    write_algorithm_properties(json, asset);
    json_end_object(json);
}

static void write_occurrence(json_writer *json, const finding *item) {
    json_begin_object(json);
    json_field_string(json, "location", item->path);
    json_field_uint(json, "line", item->line);
    json_field_string(json, "symbol", item->symbol);
    json_end_object(json);
}

static void write_evidence(json_writer *json, const finding *const *group, size_t len) {
    json_key(json, "evidence");
    json_begin_object(json);
    json_key(json, "occurrences");
    json_begin_array(json);
    for (size_t i = 0; i < len; i++) {
        write_occurrence(json, group[i]);
    }
    json_end_array(json);
    json_end_object(json);
}

static void write_identity(json_writer *json, const finding *asset) {
    char key_suffix[KEY_SIZE_SUFFIX_SIZE];
    key_size_format_suffix(asset->size, key_suffix, sizeof(key_suffix));
    json_key(json, "bom-ref");
    json_begin_string(json);
    json_append(json, "crypto/");
    json_append(json, asset->algorithm);
    json_append(json, key_suffix);
    json_append(json, "/");
    json_append(json, crypto_primitive_name(asset->primitive));
    json_end_string(json);
    json_key(json, "name");
    json_begin_string(json);
    json_append(json, asset->algorithm);
    json_append(json, (asset->size.kind == KEY_SIZE_KNOWN) ? key_suffix : "");
    json_end_string(json);
}

static void write_component_properties(json_writer *json, const finding *asset) {
    json_key(json, "properties");
    json_begin_array(json);
    write_property(json, "pqscan:risk", risk_level_name(asset->risk));
    if (asset->size.kind == KEY_SIZE_UNKNOWN) {
        write_property(json, "pqscan:key-size", "unknown");
    }
    json_end_array(json);
}

/* The risk follows from the algorithm and key size, so any finding of a group can tell it. */
static void write_component(json_writer *json, const finding *const *group, size_t len) {
    json_begin_object(json);
    json_field_string(json, "type", "cryptographic-asset");
    write_identity(json, group[0]);
    write_crypto_properties(json, group[0]);
    write_evidence(json, group, len);
    write_component_properties(json, group[0]);
    json_end_object(json);
}

static size_t group_len(const finding *const *sorted, size_t count) {
    size_t len = 1;
    while (len < count && compare_assets(sorted[0], sorted[len]) == 0) {
        len++;
    }
    return len;
}

static void write_components(json_writer *json, const finding *const *sorted, size_t count) {
    json_key(json, "components");
    json_begin_array(json);
    for (size_t done = 0; done < count;) {
        const size_t len = group_len(&sorted[done], count - done);
        write_component(json, &sorted[done], len);
        done += len;
    }
    json_end_array(json);
}

static pqscan_status write_bom(const scan_report *report, const finding *const *sorted, FILE *out) {
    json_writer json;
    json_writer_init(&json, out);
    json_begin_object(&json);
    json_field_string(&json, "$schema", SCHEMA_URI);
    json_field_string(&json, "bomFormat", "CycloneDX");
    json_field_string(&json, "specVersion", "1.6");
    json_field_uint(&json, "version", 1);
    write_metadata(&json, report->skipped);
    write_components(&json, sorted, finding_list_count(report->findings));
    json_end_object(&json);
    return json_writer_finish(&json);
}

static pqscan_status write_cbom(const scan_report *report, FILE *out) {
    const finding **sorted = finding_list_pointers(report->findings);
    if (sorted == NULL) {
        return PQSCAN_ERR_NOMEM;
    }
    qsort((void *)sorted, finding_list_count(report->findings), sizeof(sorted[0]),
          compare_occurrences);
    const pqscan_status status = write_bom(report, sorted, out);
    free((void *)sorted);
    return status;
}

const reporter cbom_reporter = {"cbom", write_cbom};
