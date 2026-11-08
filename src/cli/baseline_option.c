/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/cli/baseline_option.h"

#include "pqscan/baseline/baseline.h"
#include "pqscan/baseline/baseline_writer.h"
#include "pqscan/cli/diagnostic.h"
#include "pqscan/cli/exit_code.h"
#include "pqscan/core/finding.h"
#include "pqscan/core/json_fields.h"
#include "pqscan/core/status.h"
#include "pqscan/scan/file_reader.h"

#include <stddef.h>
#include <stdio.h>

/* Room for a message with one count in it. */
enum { MESSAGE_SIZE = 128 };

static int fail(const char *path, pqscan_status status, const char *detail) {
    cli_print_diagnostic("pqscan: ", path, detail);
    return (status == PQSCAN_ERR_NOMEM) ? PQSCAN_EXIT_INTERNAL : PQSCAN_EXIT_USAGE;
}

static int load_file(const char *path, const file_contents *file, baseline **out) {
    json_error error;
    const baseline_source source = {file->data, file->len};
    const pqscan_status status = baseline_load(&source, out, &error);
    if (status == PQSCAN_OK) {
        return PQSCAN_EXIT_CLEAN;
    }
    const char *detail =
        (status == PQSCAN_ERR_BASELINE) ? error.message : pqscan_status_message(status);
    return fail(path, status, detail);
}

int cli_load_baseline(const char *path, baseline **out) {
    if (path == NULL) {
        *out = NULL;
        return PQSCAN_EXIT_CLEAN;
    }
    file_contents *file = NULL;
    const pqscan_status status = file_contents_read(path, &file);
    if (status != PQSCAN_OK) {
        return fail(path, status, pqscan_status_message(status));
    }
    const int code = load_file(path, file, out);
    file_contents_destroy(file);
    return code;
}

static const char *plural(size_t count) { return (count == 1) ? "" : "s"; }

void cli_diff_against_baseline(const char *path, baseline *accepted, finding_list *findings) {
    (void)baseline_remove_accepted(accepted, findings);
    const size_t unused = baseline_unused(accepted);
    if (unused == 0) {
        return;
    }
    char message[MESSAGE_SIZE];
    (void)snprintf(message, sizeof(message),
                   "%zu accepted finding%s no longer found, refresh it with --write-baseline",
                   unused, plural(unused));
    cli_print_diagnostic("pqscan: ", path, message);
}

static void report_written(const char *path, size_t count) {
    char message[MESSAGE_SIZE];
    (void)snprintf(message, sizeof(message), "baseline of %zu finding%s written", count,
                   plural(count));
    cli_print_diagnostic("pqscan: ", path, message);
}

/* fclose() is checked too, as it is where a buffered write to a full disk fails. */
int cli_write_baseline(const char *path, const finding_list *findings) {
    FILE *out = fopen(path, "w");
    if (out == NULL) {
        return fail(path, PQSCAN_ERR_IO, "cannot create the baseline");
    }
    const pqscan_status status = baseline_write(findings, out);
    const int closed = fclose(out);
    if (status == PQSCAN_ERR_NOMEM) {
        return fail(path, status, pqscan_status_message(status));
    }
    if (status != PQSCAN_OK || closed != 0) {
        cli_print_diagnostic("pqscan: ", path, "cannot write the baseline");
        return PQSCAN_EXIT_INTERNAL;
    }
    report_written(path, finding_list_count(findings));
    return PQSCAN_EXIT_CLEAN;
}
