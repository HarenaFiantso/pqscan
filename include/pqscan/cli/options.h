/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_CLI_OPTIONS_H
#define PQSCAN_CLI_OPTIONS_H

#include "pqscan/core/string_list.h"

#include <stdbool.h>
#include <stddef.h>

/** How long a run analyzes files unless told otherwise. A CI job must end on a hostile repo. */
enum { CLI_DEFAULT_MAX_SECONDS = 3600 };

/** The parsed command line. */
typedef struct cli_options {
    string_list *ignores; /**< Patterns, including the defaults. Owned by this struct. */
    char **paths;         /**< Paths to scan. Borrowed from argv. */
    size_t path_count;
    const char *rules_path; /**< File given to --rules, or NULL. Borrowed from argv. */
    unsigned max_seconds;   /**< How long to keep starting on new files. */
    bool show_help;
    bool show_version;
} cli_options;

/** Outcome of cli_options_parse(). */
typedef enum cli_parse_result {
    CLI_PARSE_OK = 0,
    CLI_PARSE_USAGE_ERROR,
    CLI_PARSE_NOMEM,
} cli_parse_result;

/**
 * @brief Parse a command line.
 *
 * Uses getopt_long(), so it reorders @p argv, overwrites getopt's global state, and
 * prints a message to stderr for an invalid option unless opterr is 0.
 *
 * @param argc The argument count.
 * @param argv The arguments. They must outlive @p options.
 * @param options Out: the result. Always pass it to cli_options_destroy(), even on failure.
 * @return CLI_PARSE_OK, CLI_PARSE_USAGE_ERROR or CLI_PARSE_NOMEM.
 */
cli_parse_result cli_options_parse(int argc, char **argv, cli_options *options);

/**
 * @brief Free what a cli_options owns. The struct itself belongs to the caller.
 *
 * @param options The options.
 */
void cli_options_destroy(cli_options *options);

#endif /* PQSCAN_CLI_OPTIONS_H */
