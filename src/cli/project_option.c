/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/cli/project_option.h"

#include "pqscan/cli/diagnostic.h"
#include "pqscan/cli/exit_code.h"
#include "pqscan/core/json_fields.h"
#include "pqscan/core/status.h"
#include "pqscan/risk/project_file.h"
#include "pqscan/scan/file_reader.h"

#include <stddef.h>

static const char DEFAULT_FILE[] = ".pqscan.json";

static int fail(const char *origin, pqscan_status status, const char *detail) {
    cli_print_diagnostic("pqscan: ", origin, detail);
    return (status == PQSCAN_ERR_NOMEM) ? PQSCAN_EXIT_INTERNAL : PQSCAN_EXIT_USAGE;
}

static int use_default(project **out) {
    *out = project_create_default();
    return (*out != NULL) ? PQSCAN_EXIT_CLEAN : fail("project", PQSCAN_ERR_NOMEM, "out of memory");
}

static int load_file(const char *origin, const file_contents *file, project **out) {
    json_error error;
    const project_source source = {file->data, file->len};
    const pqscan_status status = project_load(&source, out, &error);
    if (status == PQSCAN_OK) {
        return PQSCAN_EXIT_CLEAN;
    }
    const char *detail =
        (status == PQSCAN_ERR_PROJECT) ? error.message : pqscan_status_message(status);
    return fail(origin, status, detail);
}

/* Reading and telling "absent" from the result leaves no gap between a check and the read. */
int cli_load_project(const char *path, project **out) {
    const char *origin = (path != NULL) ? path : DEFAULT_FILE;
    file_contents *file = NULL;
    const pqscan_status status = file_contents_read(origin, &file);
    if (status == PQSCAN_ERR_NOT_FOUND && path == NULL) {
        return use_default(out);
    }
    if (status != PQSCAN_OK) {
        return fail(origin, status, pqscan_status_message(status));
    }
    const int code = load_file(origin, file, out);
    file_contents_destroy(file);
    return code;
}
