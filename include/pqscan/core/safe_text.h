/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_CORE_SAFE_TEXT_H
#define PQSCAN_CORE_SAFE_TEXT_H

#include "pqscan/core/status.h"

#include <stdio.h>

/**
 * @brief Write text from a scanned repository so that it can only ever be read as text.
 *
 * File names are chosen by whoever wrote the repository, and any byte but "/" and NUL can be
 * part of one. Written as is, a line break forges a line of the report, and an escape sequence
 * or a bidirectional mark rewrites what the terminal shows. Those bytes, and any byte that is
 * not valid UTF-8, come out as \xNN, and a backslash as a double backslash, so that the output
 * can be mapped back to the exact name. Valid UTF-8 is kept, so most names read as they are.
 *
 * @param out The stream.
 * @param text The text, NUL-terminated.
 * @return PQSCAN_OK, or PQSCAN_ERR_IO if a write fails.
 */
pqscan_status safe_text_write(FILE *out, const char *text);

#endif /* PQSCAN_CORE_SAFE_TEXT_H */
