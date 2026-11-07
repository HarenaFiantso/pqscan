/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_CLI_DIAGNOSTIC_H
#define PQSCAN_CLI_DIAGNOSTIC_H

/**
 * @brief Write one "<prefix><subject>: <detail>" line to stderr.
 *
 * @param prefix A fixed string of this program, written as is.
 * @param subject What the line is about, such as a path, written with safe_text_write().
 * @param detail What happened, which may quote the input, written the same way.
 */
void cli_print_diagnostic(const char *prefix, const char *subject, const char *detail);

#endif /* PQSCAN_CLI_DIAGNOSTIC_H */
