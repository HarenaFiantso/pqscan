/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/cli/options.h"

#include "pqscan/core/status.h"
#include "pqscan/core/string_list.h"
#include "pqscan/report/report_format.h"
#include "pqscan/report/text_report.h"
#include "pqscan/risk/priority.h"
#include "pqscan/risk/risk.h"

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

enum { DECIMAL = 10 };

/* Past every char, as these have no short form. */
enum {
    OPTION_MAX_TIME = 256,
    OPTION_FAIL_ON,
    OPTION_PROJECT,
    OPTION_AS_OF,
    OPTION_DIFF,
    OPTION_WRITE_BASELINE,
};

static const char SHORT_OPTIONS[] = "f:hi:r:V";

static const struct option LONG_OPTIONS[] = {
    {"as-of", required_argument, NULL, OPTION_AS_OF},
    {"diff", required_argument, NULL, OPTION_DIFF},
    {"fail-on", required_argument, NULL, OPTION_FAIL_ON},
    {"format", required_argument, NULL, 'f'},
    {"help", no_argument, NULL, 'h'},
    {"ignore", required_argument, NULL, 'i'},
    {"max-time", required_argument, NULL, OPTION_MAX_TIME},
    {"project", required_argument, NULL, OPTION_PROJECT},
    {"rules", required_argument, NULL, 'r'},
    {"version", no_argument, NULL, 'V'},
    {"write-baseline", required_argument, NULL, OPTION_WRITE_BASELINE},
    {NULL, 0, NULL, 0},
};

static const char DEFAULT_IGNORE[] = ".git";

/* An OK finding needs no action, so it does not fail a run unless asked to. */
static const risk_level DEFAULT_FAIL_ON = RISK_REVIEW;

static cli_parse_result add_ignore(cli_options *options, const char *pattern) {
    const pqscan_status status = string_list_add(options->ignores, pattern);
    return (status == PQSCAN_OK) ? CLI_PARSE_OK : CLI_PARSE_NOMEM;
}

/* strtoul() would accept spaces and a sign, and turn -1 into a huge number. */
static bool parse_bounded(const char *text, unsigned long max, unsigned long *out) {
    char *end = NULL;
    errno = 0;
    const unsigned long value = strtoul(text, &end, DECIMAL);
    if (!isdigit((unsigned char)text[0]) || *end != '\0' || errno != 0 || value > max) {
        return false;
    }
    *out = value;
    return true;
}

static cli_parse_result set_max_seconds(cli_options *options, const char *text) {
    unsigned long value = 0;
    if (!parse_bounded(text, INT_MAX, &value)) {
        (void)fputs("pqscan: --max-time: expected a number of seconds\n", stderr);
        return CLI_PARSE_USAGE_ERROR;
    }
    options->max_seconds = (unsigned)value;
    return CLI_PARSE_OK;
}

static cli_parse_result set_as_of_year(cli_options *options, const char *text) {
    unsigned long value = 0;
    if (!parse_bounded(text, PRIORITY_MAX_YEAR, &value) || value < PRIORITY_MIN_YEAR) {
        (void)fputs("pqscan: --as-of: expected a year from 1970 to 9999\n", stderr);
        return CLI_PARSE_USAGE_ERROR;
    }
    options->as_of_year = (int)value;
    return CLI_PARSE_OK;
}

static cli_parse_result set_format(cli_options *options, const char *name) {
    options->format = reporter_find(name);
    if (options->format == NULL) {
        (void)fputs("pqscan: --format: unknown format, see --help\n", stderr);
        return CLI_PARSE_USAGE_ERROR;
    }
    return CLI_PARSE_OK;
}

static cli_parse_result set_fail_on(cli_options *options, const char *name) {
    if (!risk_level_parse(name, &options->fail_on)) {
        (void)fputs("pqscan: --fail-on: expected OK, REVIEW, QUANTUM_VULNERABLE or "
                    "CLASSICALLY_WEAK\n",
                    stderr);
        return CLI_PARSE_USAGE_ERROR;
    }
    return CLI_PARSE_OK;
}

static cli_parse_result apply_option(int option, cli_options *options) {
    switch (option) {
    case 'h':
        options->show_help = true;
        return CLI_PARSE_OK;
    case 'V':
        options->show_version = true;
        return CLI_PARSE_OK;
    case 'i':
        return add_ignore(options, optarg);
    case 'f':
        return set_format(options, optarg);
    case OPTION_FAIL_ON:
        return set_fail_on(options, optarg);
    case OPTION_MAX_TIME:
        return set_max_seconds(options, optarg);
    case 'r':
        options->rules_path = optarg;
        return CLI_PARSE_OK;
    case OPTION_PROJECT:
        options->project_path = optarg;
        return CLI_PARSE_OK;
    case OPTION_AS_OF:
        return set_as_of_year(options, optarg);
    case OPTION_DIFF:
        options->diff_path = optarg;
        return CLI_PARSE_OK;
    case OPTION_WRITE_BASELINE:
        options->baseline_out = optarg;
        return CLI_PARSE_OK;
    default:
        return CLI_PARSE_USAGE_ERROR;
    }
}

static cli_parse_result check_baseline_options(const cli_options *options) {
    if (options->diff_path != NULL && options->baseline_out != NULL) {
        (void)fputs("pqscan: --diff and --write-baseline cannot be used together\n", stderr);
        return CLI_PARSE_USAGE_ERROR;
    }
    return CLI_PARSE_OK;
}

cli_parse_result cli_options_parse(int argc, char **argv, cli_options *options) {
    *options = (cli_options){
        .as_of_year = CLI_AS_OF_NOW,
        .max_seconds = CLI_DEFAULT_MAX_SECONDS,
        .format = &text_reporter,
        .fail_on = DEFAULT_FAIL_ON,
    };
    options->ignores = string_list_create();
    if (options->ignores == NULL) {
        return CLI_PARSE_NOMEM;
    }
    cli_parse_result result = add_ignore(options, DEFAULT_IGNORE);

    /* Zero is the reset that both glibc and the BSD getopt in macOS understand. */
    optind = 0;
    int option = getopt_long(argc, argv, SHORT_OPTIONS, LONG_OPTIONS, NULL);
    while (result == CLI_PARSE_OK && option != -1) {
        result = apply_option(option, options);
        option = getopt_long(argc, argv, SHORT_OPTIONS, LONG_OPTIONS, NULL);
    }
    if (result == CLI_PARSE_OK) {
        result = check_baseline_options(options);
    }
    if (result == CLI_PARSE_OK) {
        options->paths = argv + optind;
        options->path_count = (size_t)(argc - optind);
    }
    return result;
}

void cli_options_destroy(cli_options *options) {
    string_list_destroy(options->ignores);
    options->ignores = NULL;
}
