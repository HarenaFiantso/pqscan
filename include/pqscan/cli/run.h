/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_CLI_RUN_H
#define PQSCAN_CLI_RUN_H

/**
 * @brief Run pqscan: parse the command line, scan, and report.
 *
 * Writes the report to stdout, and warnings and errors to stderr. A path that cannot be
 * read during the scan is a warning, not an error.
 *
 * @param argc The argument count.
 * @param argv The arguments. Reordered by option parsing.
 * @return A pqscan_exit_code.
 */
int cli_run(int argc, char **argv);

#endif /* PQSCAN_CLI_RUN_H */
