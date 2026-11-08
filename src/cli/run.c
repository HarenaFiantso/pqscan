/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/cli/run.h"

#include "pqscan/baseline/baseline.h"
#include "pqscan/cli/baseline_option.h"
#include "pqscan/cli/diagnostic.h"
#include "pqscan/cli/exit_code.h"
#include "pqscan/cli/options.h"
#include "pqscan/cli/project_option.h"
#include "pqscan/cli/rule_option.h"
#include "pqscan/core/clock.h"
#include "pqscan/core/finding.h"
#include "pqscan/core/skip_list.h"
#include "pqscan/core/status.h"
#include "pqscan/core/version.h"
#include "pqscan/report/reporter.h"
#include "pqscan/risk/prioritize.h"
#include "pqscan/risk/project_file.h"
#include "pqscan/risk/risk.h"
#include "pqscan/rules/rule_set.h"
#include "pqscan/scan/cert_scanner.h"
#include "pqscan/scan/config_scanner.h"
#include "pqscan/scan/elf_scanner.h"
#include "pqscan/scan/file_reader.h"
#include "pqscan/scan/scanner.h"
#include "pqscan/scan/source_scanner.h"
#include "pqscan/walk/walker.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static const char USAGE[] =
    "Usage: pqscan [OPTIONS] PATH...\n"
    "\n"
    "Find quantum-vulnerable cryptography in C/C++ source, TLS and SSH configuration,\n"
    "certificates, keys and ELF binaries.\n"
    "\n"
    "Options:\n"
    "  -i, --ignore PATTERN  skip paths matching this glob (repeatable; .git is always skipped)\n"
    "  -r, --rules FILE      use the rules in this JSON file instead of the built-in ones\n"
    "      --project FILE    read how long data must stay secret from this project file\n"
    "                        (default .pqscan.json in the current directory, if there is one)\n"
    "      --as-of YEAR      score priorities as if it were this year (default the current year)\n"
    "      --diff FILE       report only the findings this baseline does not accept\n"
    "      --write-baseline FILE\n"
    "                        write a baseline that accepts every finding to this file\n"
    "  -f, --format FORMAT   write the report as text, json, cbom or sarif\n"
    "      --fail-on LEVEL   lowest risk level that exits 1: OK, REVIEW, QUANTUM_VULNERABLE or\n"
    "                        CLASSICALLY_WEAK (default REVIEW)\n"
    "      --max-time SECS   start on no new file after this long (default 3600)\n"
    "  -h, --help            show this help and exit\n"
    "  -V, --version         show the version and exit\n"
    "\n"
    "Exit codes:\n"
    "  0  no findings at or above --fail-on, and everything was analyzed\n"
    "  1  findings at or above --fail-on (with --diff, new findings only; with\n"
    "     --write-baseline, never)\n"
    "  2  usage error\n"
    "  3  internal error\n"
    "  4  no findings at or above --fail-on, but something could not be analyzed\n";

static const scanner *const SCANNERS[] = {
    &source_scanner,
    &config_scanner,
    &cert_scanner,
    &elf_scanner,
};

/* What a run reads before it scans. Findings borrow names from the rules and the project. */
typedef struct run_inputs {
    const rule_set *rules;
    const project *target;
    baseline *accepted; /* The baseline of --diff, or NULL. Used up as findings match it. */
    int as_of_year;
} run_inputs;

/* What every file of a run shares. */
typedef struct scan_job {
    const rule_set *rules;
    finding_list *findings;
    skip_list *skipped;     /* Paths in scope that were not analyzed. */
    risk_level fail_on;     /* The lowest level that counts for the exit code. */
    bool accepts_all;       /* A run that writes a baseline accepts what it finds. */
    const char *root;       /* The PATH being walked. */
    time_t deadline;        /* When to stop starting on new files. */
    pqscan_status recorded; /* Whether skipped is whole, as a walk callback cannot fail. */
} scan_job;

/* A symlink or device inside a tree is left out by design. The same thing given as a PATH was
 * asked for by name, so a run that skips it has not done what it was told. */
static bool is_in_scope(const scan_job *job, const char *path, pqscan_status reason) {
    return reason != PQSCAN_ERR_NOT_REGULAR || strcmp(path, job->root) == 0;
}

static void warn_skipped(const char *path, pqscan_status reason, void *context) {
    scan_job *job = context;
    cli_print_diagnostic("pqscan: warning: ", path, pqscan_status_message(reason));
    if (is_in_scope(job, path, reason) && job->recorded == PQSCAN_OK) {
        job->recorded = skip_list_add(job->skipped, path, reason);
    }
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

/* The budget of each file already bounds how far past the deadline a run can go. */
static pqscan_status scan_or_skip(const scanner *active, const char *path, scan_job *job) {
    if (pqscan_monotonic_seconds() < job->deadline) {
        return scan_with(active, path, job);
    }
    warn_skipped(path, PQSCAN_ERR_BUDGET, job);
    return PQSCAN_OK;
}

static pqscan_status scan_file(const char *path, void *context) {
    scan_job *job = context;
    for (size_t i = 0; i < sizeof(SCANNERS) / sizeof(SCANNERS[0]); i++) {
        if (SCANNERS[i]->accepts(path)) {
            const pqscan_status status = scan_or_skip(SCANNERS[i], path, job);
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
        pqscan_status status = walk_tree(options->paths[i], options->ignores, &callbacks);
        status = (status == PQSCAN_OK) ? job->recorded : status;
        if (status != PQSCAN_OK) {
            return fail_on_path(options->paths[i], status);
        }
    }
    return PQSCAN_EXIT_CLEAN;
}

static bool has_finding_at_or_above(const finding_list *findings, risk_level level) {
    for (size_t i = 0; i < finding_list_count(findings); i++) {
        if (finding_list_get(findings, i)->risk >= level) {
            return true;
        }
    }
    return false;
}

/* Findings win over an incomplete scan, because they already need acting on. */
static int exit_code_of(const scan_job *job) {
    if (!job->accepts_all && has_finding_at_or_above(job->findings, job->fail_on)) {
        return PQSCAN_EXIT_FINDINGS;
    }
    return (skip_list_count(job->skipped) > 0) ? PQSCAN_EXIT_INCOMPLETE : PQSCAN_EXIT_CLEAN;
}

static int report_findings(const scan_job *job, const reporter *format) {
    const scan_report report = {job->findings, job->skipped};
    if (format->write(&report, stdout) != PQSCAN_OK) {
        (void)fprintf(stderr, "pqscan: cannot write the report\n");
        return PQSCAN_EXIT_INTERNAL;
    }
    const size_t unanalyzed = skip_list_count(job->skipped);
    if (unanalyzed > 0) {
        (void)fprintf(stderr, "pqscan: scan incomplete: %zu path%s could not be analyzed\n",
                      unanalyzed, (unanalyzed == 1) ? "" : "s");
    }
    return exit_code_of(job);
}

/* A baseline is written from every finding, before any is filtered or reordered. */
static int apply_baseline(const cli_options *options, scan_job *job, baseline *accepted) {
    if (options->baseline_out != NULL) {
        job->accepts_all = true;
        return cli_write_baseline(options->baseline_out, job->findings);
    }
    if (accepted != NULL) {
        cli_diff_against_baseline(options->diff_path, accepted, job->findings);
    }
    return PQSCAN_EXIT_CLEAN;
}

static int scan_and_report(const cli_options *options, scan_job *job, const run_inputs *inputs) {
    int code = scan_paths(options, job);
    if (code == PQSCAN_EXIT_CLEAN) {
        code = apply_baseline(options, job, inputs->accepted);
    }
    if (code != PQSCAN_EXIT_CLEAN) {
        return code;
    }
    prioritize_findings(job->findings, inputs->target, inputs->as_of_year);
    sort_by_priority(job->findings);
    return report_findings(job, options->format);
}

static int scan_with_inputs(const cli_options *options, const run_inputs *inputs) {
    const time_t deadline = pqscan_monotonic_seconds() + (time_t)options->max_seconds;
    scan_job job = {
        .rules = inputs->rules,
        .findings = finding_list_create(),
        .skipped = skip_list_create(),
        .fail_on = options->fail_on,
        .deadline = deadline,
        .recorded = PQSCAN_OK,
    };
    int code = PQSCAN_EXIT_INTERNAL;
    if (job.findings != NULL && job.skipped != NULL) {
        code = scan_and_report(options, &job, inputs);
    } else {
        (void)fprintf(stderr, "pqscan: %s\n", pqscan_status_message(PQSCAN_ERR_NOMEM));
    }
    skip_list_destroy(job.skipped);
    finding_list_destroy(job.findings);
    return code;
}

static int as_of_year_of(const cli_options *options, int *year) {
    if (options->as_of_year != CLI_AS_OF_NOW) {
        *year = options->as_of_year;
        return PQSCAN_EXIT_CLEAN;
    }
    if (!pqscan_current_utc_year(year)) {
        (void)fputs("pqscan: cannot read the date, give it with --as-of\n", stderr);
        return PQSCAN_EXIT_INTERNAL;
    }
    return PQSCAN_EXIT_CLEAN;
}

static int scan_with_loaded(const cli_options *options, run_inputs *inputs) {
    const int code = as_of_year_of(options, &inputs->as_of_year);
    return (code == PQSCAN_EXIT_CLEAN) ? scan_with_inputs(options, inputs) : code;
}

/* What run_scan() owns, so that one function loads it all and one frees it all. */
typedef struct owned_inputs {
    rule_set *rules;
    project *target;
    baseline *accepted;
} owned_inputs;

static int load_inputs(const cli_options *options, owned_inputs *owned) {
    int code = cli_load_rules(options->rules_path, &owned->rules);
    if (code == PQSCAN_EXIT_CLEAN) {
        code = cli_load_project(options->project_path, &owned->target);
    }
    if (code == PQSCAN_EXIT_CLEAN) {
        code = cli_load_baseline(options->diff_path, &owned->accepted);
    }
    return code;
}

/* Findings borrow names from the rules and the project, so these are freed last. */
static void free_inputs(owned_inputs *owned) {
    baseline_destroy(owned->accepted);
    project_destroy(owned->target);
    rule_set_destroy(owned->rules);
}

static int run_scan(const cli_options *options) {
    owned_inputs owned = {NULL, NULL, NULL};
    int code = load_inputs(options, &owned);
    if (code == PQSCAN_EXIT_CLEAN) {
        run_inputs inputs = {owned.rules, owned.target, owned.accepted, CLI_AS_OF_NOW};
        code = scan_with_loaded(options, &inputs);
    }
    free_inputs(&owned);
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
