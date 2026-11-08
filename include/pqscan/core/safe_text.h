/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_CORE_SAFE_TEXT_H
#define PQSCAN_CORE_SAFE_TEXT_H

#include "pqscan/core/status.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

/**
 * @brief Receives one piece of safe text.
 *
 * @param bytes The piece. Not NUL-terminated, and valid only during the call.
 * @param len The number of bytes.
 * @param context The context given to safe_text_visit().
 * @return true to continue, false to stop.
 */
typedef bool (*safe_text_sink)(const char *bytes, size_t len, void *context);

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

/**
 * @brief Pass the safe form of a text to a sink, for output that has its own encoding.
 *
 * The pieces, put together, are exactly what safe_text_write() writes.
 *
 * @param text The text, NUL-terminated.
 * @param sink Receives each piece, in order.
 * @param context Passed to @p sink, unchanged.
 * @return true if the sink accepted every piece.
 */
bool safe_text_visit(const char *text, safe_text_sink sink, void *context);

/**
 * @brief Compare a text with a safe form read back from an earlier report, without building the
 *        safe form of the text.
 *
 * The safe form maps back to exactly one text, so two texts are equal if and only if their safe
 * forms are. Comparing the forms lets a file written with safe_text be matched against raw names.
 *
 * @param text The raw text, NUL-terminated.
 * @param safe A safe form, NUL-terminated.
 * @return Less than, equal to or greater than zero as the safe form of @p text sorts before, the
 *         same as or after @p safe, in the order of strcmp().
 */
int safe_text_compare(const char *text, const char *safe);

#endif /* PQSCAN_CORE_SAFE_TEXT_H */
