/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/cli/rule_option.h"

#include "pqscan/cli/diagnostic.h"
#include "pqscan/cli/exit_code.h"
#include "pqscan/core/status.h"
#include "pqscan/rules/default_rules.h"
#include "pqscan/rules/rule_loader.h"
#include "pqscan/rules/rule_set.h"
#include "pqscan/scan/file_reader.h"

#include <stdbool.h>
#include <stddef.h>

static const char BUILT_IN_NAME[] = "built-in rules";

static int fail(const char *origin, pqscan_status status, const char *detail) {
    cli_print_diagnostic("pqscan: ", origin, detail);
    const bool user_can_fix = status != PQSCAN_ERR_NOMEM && origin != BUILT_IN_NAME;
    return user_can_fix ? PQSCAN_EXIT_USAGE : PQSCAN_EXIT_INTERNAL;
}

static int load_source(const char *origin, const rule_source *source, rule_set **out) {
    rule_error error;
    const pqscan_status status = rule_set_load(source, out, &error);
    if (status == PQSCAN_OK) {
        return PQSCAN_EXIT_CLEAN;
    }
    const char *detail =
        (status == PQSCAN_ERR_RULES) ? error.message : pqscan_status_message(status);
    return fail(origin, status, detail);
}

int cli_load_rules(const char *path, rule_set **out) {
    if (path == NULL) {
        const rule_source source = default_rules_source();
        return load_source(BUILT_IN_NAME, &source, out);
    }
    file_contents *file = NULL;
    const pqscan_status status = file_contents_read(path, &file);
    if (status != PQSCAN_OK) {
        return fail(path, status, pqscan_status_message(status));
    }
    const rule_source source = {file->data, file->len};
    const int code = load_source(path, &source, out);
    file_contents_destroy(file);
    return code;
}
