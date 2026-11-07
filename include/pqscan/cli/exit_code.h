/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_CLI_EXIT_CODE_H
#define PQSCAN_CLI_EXIT_CODE_H

/** The exit codes of the pqscan binary, which scripts and CI gates rely on. */
typedef enum pqscan_exit_code {
    PQSCAN_EXIT_CLEAN = 0,
    PQSCAN_EXIT_FINDINGS = 1,
    PQSCAN_EXIT_USAGE = 2,
    PQSCAN_EXIT_INTERNAL = 3,
} pqscan_exit_code;

#endif /* PQSCAN_CLI_EXIT_CODE_H */
