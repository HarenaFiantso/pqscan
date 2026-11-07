/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/cli/diagnostic.h"

#include "pqscan/core/safe_text.h"

#include <stdio.h>

/* Nothing can be done about a stderr that fails, so a failed write is ignored on purpose. */
void cli_print_diagnostic(const char *prefix, const char *subject, const char *detail) {
    (void)fputs(prefix, stderr);
    (void)safe_text_write(stderr, subject);
    (void)fputs(": ", stderr);
    (void)safe_text_write(stderr, detail);
    (void)fputc('\n', stderr);
}
