/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/cli/run.h"

#include "pqscan/cli/diagnostic.h"
#include "pqscan/cli/exit_code.h"
#include "pqscan/cli/options.h"
#include "pqscan/cli/rule_option.h"
#include "pqscan/core/finding.h"
#include "pqscan/core/status.h"
#include "pqscan/core/version.h"
#include "pqscan/report/reporter.h"
#include "pqscan/report/text_report.h"
#include "pqscan/rules/rule_set.h"
#include "pqscan/scan/file_reader.h"
#include "pqscan/scan/scanner.h"
#include "pqscan/scan/source_scanner.h"
#include "pqscan/walk/walker.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

static const char USAGE[] =
    "Usage: pqscan [OPTIONS] PATH...\n"
    "\n"
    "Find quantum-vulnerable cryptography in C/C++ source files.\n"
    "\n"
    "Options:\n"
    "  -i, --ignore PATTERN  skip paths matching this glob (repeatable; .git is always skipped)\n"
    "  -r, --rules FILE      use the rules in this JSON file instead of the built-in ones\n"
    "  -h, --help            show this help and exit\n"
    "  -V, --version         show the version and exit\n"
    "\n"
    "Exit codes:\n"
    "  0  no findings\n"
    "  1  findings reported\n"
    "  2  usage error\n"
    "  3  internal error\n"
    "  4  no findings, but something could not be analyzed\n";

static const scanner *const SCANNERS[] = {&source_scanner};

/* What every file of a run shares. */
typedef struct scan_job {
    const rule_set *rules;
    finding_list *findings;
    const char *root;  /* The PATH being walked. */
    size_t unanalyzed; /* Paths in scope that were not analyzed. */
} scan_job;

/* A symlink or device inside a tree is left out by design. The same thing given as a PATH was
 * asked for by name, so a run that skips it has not done what it was told. */
static bool is_in_scope(const scan_job *job, const char *path, pqscan_status reason) {
    return reason != PQSCAN_ERR_NOT_REGULAR || strcmp(path, job->root) == 0;
}

static void warn_skipped(const char *path, pqscan_status reason, void *context) {
    scan_job *job = context;
    cli_print_diagnostic("pqscan: warning: ", path, pqscan_status_message(reason));
    job->unanalyzed += is_in_scope(job, path, reason) ? 1 : 0;
}

static pqscan_status scan_with(const scanner *active, const char *path, scan_job *job) {
    file_contents *file = NULL;
    pqscan_status status = file_contents_read(path, &file);
    if (status == PQSCAN_OK) {
        const scan_input input = {path, file, job->rules};
        status = active->scan(&input, job->findings);
    }
    file_contents_destroy(file);
    if (status == PQSCAN_OK || status == PQSCAN_ERR_NOMEM) {
        return status;
    }
    warn_skipped(path, status, job);
    return PQSCAN_OK;
}

static pqscan_status scan_file(const char *path, void *context) {
    scan_job *job = context;
    for (size_t i = 0; i < sizeof(SCANNERS) / sizeof(SCANNERS[0]); i++) {
        if (SCANNERS[i]->accepts(path)) {
            const pqscan_status status = scan_with(SCANNERS[i], path, job);
            if (status != PQSCAN_OK) {
                return status;
            }
        }
    }
    return PQSCAN_OK;
}

static int fail_on_path(const char *path, pqscan_status status) {
    cli_print_diagnostic("pqscan: ", path, pqscan_status_message(status));
    const int bad_argument = status == PQSCAN_ERR_NOT_FOUND || status == PQSCAN_ERR_IO;
    return bad_argument ? PQSCAN_EXIT_USAGE : PQSCAN_EXIT_INTERNAL;
}

static int scan_paths(const cli_options *options, scan_job *job) {
    const walk_callbacks callbacks = {scan_file, warn_skipped, job};
    for (size_t i = 0; i < options->path_count; i++) {
        job->root = options->paths[i];
        const pqscan_status status = walk_tree(options->paths[i], options->ignores, &callbacks);
        if (status != PQSCAN_OK) {
            return fail_on_path(options->paths[i], status);
        }
    }
    return PQSCAN_EXIT_CLEAN;
}

/* Findings win over an incomplete scan, because they already need acting on. */
static int exit_code_of(const scan_job *job) {
    if (finding_list_count(job->findings) > 0) {
        return PQSCAN_EXIT_FINDINGS;
    }
    return (job->unanalyzed > 0) ? PQSCAN_EXIT_INCOMPLETE : PQSCAN_EXIT_CLEAN;
}

static int report_findings(const scan_job *job) {
    if (text_reporter.write(job->findings, stdout) != PQSCAN_OK) {
        (void)fprintf(stderr, "pqscan: cannot write the report\n");
        return PQSCAN_EXIT_INTERNAL;
    }
    if (job->unanalyzed > 0) {
        (void)fprintf(stderr, "pqscan: scan incomplete: %zu path%s could not be analyzed\n",
                      job->unanalyzed, (job->unanalyzed == 1) ? "" : "s");
    }
    return exit_code_of(job);
}

static int scan_with_rules(const cli_options *options, const rule_set *rules) {
    finding_list *findings = finding_list_create();
    if (findings == NULL) {
        (void)fprintf(stderr, "pqscan: %s\n", pqscan_status_message(PQSCAN_ERR_NOMEM));
        return PQSCAN_EXIT_INTERNAL;
    }
    scan_job job = {rules, findings, NULL, 0};
    int code = scan_paths(options, &job);
    if (code == PQSCAN_EXIT_CLEAN) {
        code = report_findings(&job);
    }
    finding_list_destroy(findings);
    return code;
}

/* Findings borrow their algorithm names from the rules, so the rules are freed last. */
static int run_scan(const cli_options *options) {
    rule_set *rules = NULL;
    int code = cli_load_rules(options->rules_path, &rules);
    if (code == PQSCAN_EXIT_CLEAN) {
        code = scan_with_rules(options, rules);
    }
    rule_set_destroy(rules);
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
