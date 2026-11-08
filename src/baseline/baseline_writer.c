/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/baseline/baseline_writer.h"

#include "pqscan/baseline/baseline_format.h"
#include "pqscan/core/finding.h"
#include "pqscan/core/primitive.h"
#include "pqscan/core/status.h"
#include "pqscan/report/json_writer.h"
#include "pqscan/report/key_size_json.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

/* The tool and its version are left out on purpose: they would change the file on every
 * release, and a baseline is meant to be committed and reviewed. */

static int compare_findings(const void *left, const void *right) {
    const baseline_identity first = baseline_identity_of(*(const finding *const *)left);
    const baseline_identity second = baseline_identity_of(*(const finding *const *)right);
    return baseline_identity_compare(&first, &second);
}

static void write_entry(json_writer *json, const baseline_identity *identity, size_t count) {
    json_begin_object(json);
    json_field_string(json, "path", identity->path);
    json_field_string(json, "algorithm", identity->algorithm);
    json_field_string(json, "symbol", identity->symbol);
    json_field_string(json, "primitive", crypto_primitive_name(identity->primitive));
    json_key(json, "key_size");
    key_size_json_write(json, identity->size);
    json_field_uint(json, "count", count);
    json_end_object(json);
}

/* Writes the entry of the run of equal findings that starts at sorted[0], and tells its length. */
static size_t write_run(json_writer *json, const finding *const *sorted, size_t count) {
    const baseline_identity first = baseline_identity_of(sorted[0]);
    size_t len = 1;
    while (len < count) {
        const baseline_identity next = baseline_identity_of(sorted[len]);
        if (baseline_identity_compare(&first, &next) != 0) {
            break;
        }
        len++;
    }
    write_entry(json, &first, len);
    return len;
}

static pqscan_status write_document(const finding *const *sorted, size_t count, FILE *out) {
    json_writer json;
    json_writer_init(&json, out);
    json_begin_object(&json);
    json_field_uint(&json, "schema_version", BASELINE_SCHEMA_VERSION);
    json_key(&json, "findings");
    json_begin_array(&json);
    for (size_t done = 0; done < count;) {
        done += write_run(&json, &sorted[done], count - done);
    }
    json_end_array(&json);
    json_end_object(&json);
    return json_writer_finish(&json);
}

pqscan_status baseline_write(const finding_list *findings, FILE *out) {
    const finding **sorted = finding_list_pointers(findings);
    if (sorted == NULL) {
        return PQSCAN_ERR_NOMEM;
    }
    const size_t count = finding_list_count(findings);
    if (count > 1) {
        qsort((void *)sorted, count, sizeof(sorted[0]), compare_findings);
    }
    const pqscan_status status = write_document(sorted, count, out);
    free((void *)sorted);
    return status;
}
