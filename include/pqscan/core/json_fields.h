/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_CORE_JSON_FIELDS_H
#define PQSCAN_CORE_JSON_FIELDS_H

#include "pqscan/core/status.h"

#include <stddef.h>

/* Only pointers to it cross this interface, so callers need not see cJSON. */
struct cJSON;

/** Room for a message about one field of one entry. */
enum { JSON_ERROR_SIZE = 256 };

/** The longest name json_read_name() accepts. */
enum { JSON_MAX_NAME_LENGTH = 128 };

/** Why a JSON input file was refused. */
typedef struct json_error {
    char message[JSON_ERROR_SIZE]; /**< Names the place, such as "rules[3].kind: ...". */
} json_error;

/** Where a reader is in a document, so that every message can name the entry at fault. */
typedef struct json_place {
    json_error *error;     /**< Receives the message of a refusal. */
    pqscan_status refusal; /**< What a refusal returns, such as PQSCAN_ERR_RULES. */
    const char *section;   /**< The array being read, or NULL at the top of the document. */
    size_t index;          /**< The entry of that array. */
} json_place;

/** A string field of one JSON object. */
typedef struct json_name_field {
    const struct cJSON *object;
    const char *name;
} json_name_field;

/** A number field of one JSON object, with what it accepts. */
typedef struct json_int_field {
    const struct cJSON *object;
    const char *name;
    int min;
    int max;
    int fallback; /**< The value when the field is absent. */
} json_int_field;

/**
 * @brief Parse a whole document. Anything but whitespace after the value refuses it.
 *
 * @param text The text. It need not be NUL-terminated.
 * @param len The length of @p text.
 * @param error Out: on failure, the line where parsing stopped.
 * @return The document, owned by the caller and freed with cJSON_Delete(), or NULL if the
 *         text is not JSON or memory ran out.
 */
struct cJSON *json_parse_document(const char *text, size_t len, json_error *error);

/**
 * @brief Refuse a field, writing "section[index].field: reason" to the place's error.
 *
 * @param place Where the reader is.
 * @param field The field at fault.
 * @param reason What is wrong with it.
 * @return The place's refusal status.
 */
pqscan_status json_reject(const json_place *place, const char *field, const char *reason);

/**
 * @brief Refuse an object that has a field not in a list, or the same field twice.
 *
 * @param place Where the reader is.
 * @param object The object.
 * @param allowed The names it may have, ending in NULL.
 * @return PQSCAN_OK, or the place's refusal status.
 */
pqscan_status json_check_fields(const json_place *place, const struct cJSON *object,
                                const char *const *allowed);

/**
 * @brief Read a required name: 1 to JSON_MAX_NAME_LENGTH printable ASCII characters, so that
 *        reports and messages can print it without escaping.
 *
 * @param place Where the reader is.
 * @param field The field.
 * @param out On success, the name, borrowed from the document. Untouched on failure.
 * @return PQSCAN_OK, or the place's refusal status.
 */
pqscan_status json_read_name(const json_place *place, const json_name_field *field,
                             const char **out);

/**
 * @brief Read an optional integer within the field's range.
 *
 * @param place Where the reader is.
 * @param field The field, its range and its fallback.
 * @param out On success, the value or the fallback. Untouched on failure.
 * @return PQSCAN_OK, or the place's refusal status.
 */
pqscan_status json_read_int(const json_place *place, const json_int_field *field, int *out);

/**
 * @brief Require "schema_version" to be present and equal to a given version.
 *
 * @param place Where the reader is. Its section must be NULL.
 * @param document The top-level object.
 * @param version The only version accepted.
 * @return PQSCAN_OK, or the place's refusal status.
 */
pqscan_status json_check_schema_version(const json_place *place, const struct cJSON *document,
                                        int version);

#endif /* PQSCAN_CORE_JSON_FIELDS_H */
