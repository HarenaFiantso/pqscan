/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/cli/run.h"

#include "pqscan/cli/exit_code.h"
#include "pqscan/cli/options.h"
#include "pqscan/core/finding.h"
#include "pqscan/core/status.h"
#include "pqscan/core/version.h"
#include "pqscan/report/reporter.h"
#include "pqscan/report/text_report.h"
#include "pqscan/scan/file_reader.h"
#include "pqscan/scan/scanner.h"
#include "pqscan/scan/source_scanner.h"
#include "pqscan/walk/walker.h"

#include <stddef.h>
#include <stdio.h>

static const char USAGE[] =
    "Usage: pqscan [OPTIONS] PATH...\n"
    "\n"
    "Find quantum-vulnerable cryptography in C/C++ source files.\n"
    "\n"
    "Options:\n"
    "  -i, --ignore PATTERN  skip paths matching this glob (repeatable; .git is always skipped)\n"
    "  -h, --help            show this help and exit\n"
    "  -V, --version         show the version and exit\n"
    "\n"
    "Exit codes:\n"
    "  0  no findings\n"
    "  1  findings reported\n"
    "  2  usage error\n"
    "  3  internal error\n";

static const scanner *const SCANNERS[] = {&source_scanner};

static void warn_skipped(const char *path, pqscan_status reason, void *context) {
    (void)context;
    (void)fprintf(stderr, "pqscan: warning: %s: %s\n", path, pqscan_status_message(reason));
}

static pqscan_status scan_with(const scanner *active, const char *path, finding_list *findings) {
    file_contents *file = NULL;
    pqscan_status status = file_contents_read(path, &file);
    if (status == PQSCAN_OK) {
        status = active->scan(path, file, findings);
    }
    file_contents_destroy(file);
    if (status == PQSCAN_OK || status == PQSCAN_ERR_NOMEM) {
        return status;
    }
    warn_skipped(path, status, NULL);
    return PQSCAN_OK;
}

static pqscan_status scan_file(const char *path, void *context) {
    finding_list *findings = context;
    for (size_t i = 0; i < sizeof(SCANNERS) / sizeof(SCANNERS[0]); i++) {
        if (SCANNERS[i]->accepts(path)) {
            const pqscan_status status = scan_with(SCANNERS[i], path, findings);
            if (status != PQSCAN_OK) {
                return status;
            }
        }
    }
    return PQSCAN_OK;
}

static int fail_on_path(const char *path, pqscan_status status) {
    (void)fprintf(stderr, "pqscan: %s: %s\n", path, pqscan_status_message(status));
    const int bad_argument = status == PQSCAN_ERR_NOT_FOUND || status == PQSCAN_ERR_IO;
    return bad_argument ? PQSCAN_EXIT_USAGE : PQSCAN_EXIT_INTERNAL;
}

static int scan_paths(const cli_options *options, finding_list *findings) {
    const walk_callbacks callbacks = {scan_file, warn_skipped, findings};
    for (size_t i = 0; i < options->path_count; i++) {
        const pqscan_status status = walk_tree(options->paths[i], options->ignores, &callbacks);
        if (status != PQSCAN_OK) {
            return fail_on_path(options->paths[i], status);
        }
    }
    return PQSCAN_EXIT_CLEAN;
}

static int report_findings(const finding_list *findings) {
    if (text_reporter.write(findings, stdout) != PQSCAN_OK) {
        (void)fprintf(stderr, "pqscan: cannot write the report\n");
        return PQSCAN_EXIT_INTERNAL;
    }
    return (finding_list_count(findings) > 0) ? PQSCAN_EXIT_FINDINGS : PQSCAN_EXIT_CLEAN;
}

static int run_scan(const cli_options *options) {
    finding_list *findings = finding_list_create();
    if (findings == NULL) {
        (void)fprintf(stderr, "pqscan: %s\n", pqscan_status_message(PQSCAN_ERR_NOMEM));
        return PQSCAN_EXIT_INTERNAL;
    }
    int code = scan_paths(options, findings);
    if (code == PQSCAN_EXIT_CLEAN) {
        code = report_findings(findings);
    }
    finding_list_destroy(findings);
    return code;
}

static int print_version(void) {
    const int written = printf("pqscan %s\n", pqscan_version());
    return (written < 0 || fflush(stdout) != 0) ? PQSCAN_EXIT_INTERNAL : PQSCAN_EXIT_CLEAN;
}

static int print_help(void) {
    const int written = fputs(USAGE, stdout);
    return (written < 0 || fflush(stdout) != 0) ? PQSCAN_EXIT_INTERNAL : PQSCAN_EXIT_CLEAN;
}

static int fail_with_usage_hint(void) {
    (void)fputs("Try 'pqscan --help' for more information.\n", stderr);
    return PQSCAN_EXIT_USAGE;
}

static int run_command(const cli_options *options) {
    if (options->show_help) {
        return print_help();
    }
    if (options->show_version) {
        return print_version();
    }
    if (options->path_count == 0) {
        (void)fputs("pqscan: missing PATH\n", stderr);
        return fail_with_usage_hint();
    }
    return run_scan(options);
}

int cli_run(int argc, char **argv) {
    cli_options options;
    const cli_parse_result parsed = cli_options_parse(argc, argv, &options);
    int code = PQSCAN_EXIT_INTERNAL;
    if (parsed == CLI_PARSE_OK) {
        code = run_command(&options);
    } else if (parsed == CLI_PARSE_USAGE_ERROR) {
        code = fail_with_usage_hint();
    }
    cli_options_destroy(&options);
    return code;
}
