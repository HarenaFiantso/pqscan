/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_REPORT_JSON_WRITER_H
#define PQSCAN_REPORT_JSON_WRITER_H

#include "pqscan/core/status.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

/** Containers nested deeper than this make the writer fail. Reports have a fixed shape. */
enum { JSON_WRITER_MAX_DEPTH = 16 };

/**
 * Writes JSON to a stream as it goes, so a report never needs a second copy in memory.
 *
 * A failure sticks: every later call does nothing, and json_writer_finish() returns it. That
 * lets a report read as a list of values, with one check at the end. Text goes through
 * safe_text, so a value is always valid UTF-8 whatever the bytes of a file name are.
 *
 * The struct is public so that it can live on the stack. Treat its fields as private.
 */
typedef struct json_writer {
    FILE *out;
    size_t depth;
    bool has_items[JSON_WRITER_MAX_DEPTH]; /* Whether each open container needs a comma. */
    bool after_key;                        /* The next value completes a "key": pair. */
    pqscan_status status;
} json_writer;

/**
 * @brief Start a document.
 *
 * @param json The writer. It holds no resources, so it has no destroy function.
 * @param out The stream. Stays owned by the caller, and must outlive the writer.
 */
void json_writer_init(json_writer *json, FILE *out);

/**
 * @brief End a document: write the final line break and flush the stream.
 *
 * @param json The writer.
 * @return PQSCAN_OK, or PQSCAN_ERR_IO if any call since json_writer_init() failed.
 */
pqscan_status json_writer_finish(json_writer *json);

/** @brief Open an object. Pair with json_end_object(). @param json The writer. */
void json_begin_object(json_writer *json);

/** @brief Close the innermost object. @param json The writer. */
void json_end_object(json_writer *json);

/** @brief Open an array. Pair with json_end_array(). @param json The writer. */
void json_begin_array(json_writer *json);

/** @brief Close the innermost array. @param json The writer. */
void json_end_array(json_writer *json);

/**
 * @brief Name the next value of the innermost object.
 *
 * @param json The writer.
 * @param key The name, which goes through safe_text like any other text.
 */
void json_key(json_writer *json, const char *key);

/**
 * @brief Write a string value.
 *
 * @param json The writer.
 * @param text The text, NUL-terminated.
 */
void json_string(json_writer *json, const char *text);

/**
 * @brief Write an unsigned number.
 *
 * @param json The writer.
 * @param value The value.
 */
void json_uint(json_writer *json, size_t value);

/**
 * @brief Write true or false.
 *
 * @param json The writer.
 * @param value The value.
 */
void json_bool(json_writer *json, bool value);

/** @brief Write null. @param json The writer. */
void json_null(json_writer *json);

/**
 * @brief Open a string value that is built from several parts.
 *
 * Pair with json_end_string(). Between the two, only json_append() and json_append_raw() may
 * be called.
 *
 * @param json The writer.
 */
void json_begin_string(json_writer *json);

/**
 * @brief Add text to the open string. It goes through safe_text.
 *
 * @param json The writer.
 * @param text The text, NUL-terminated.
 */
void json_append(json_writer *json, const char *text);

/**
 * @brief Add bytes to the open string as they are, for text that an encoding made safe.
 *
 * @param json The writer.
 * @param bytes Printable ASCII, without a quote or a backslash.
 * @param len The number of bytes.
 */
void json_append_raw(json_writer *json, const char *bytes, size_t len);

/** @brief Close the open string. @param json The writer. */
void json_end_string(json_writer *json);

/**
 * @brief Write a "key": "text" pair.
 *
 * @param json The writer.
 * @param key The name.
 * @param text The text, NUL-terminated.
 */
void json_field_string(json_writer *json, const char *key, const char *text);

/**
 * @brief Write a "key": number pair.
 *
 * @param json The writer.
 * @param key The name.
 * @param value The value.
 */
void json_field_uint(json_writer *json, const char *key, size_t value);

#endif /* PQSCAN_REPORT_JSON_WRITER_H */
