/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/json_fields.h"

#include "pqscan/core/status.h"

#include <cJSON.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

enum { FIRST_PRINTABLE = 0x20, LAST_PRINTABLE = 0x7e };

static size_t line_of(const char *text, const char *position) {
    size_t line = 1;
    for (const char *byte = text; byte < position; byte++) {
        line += (*byte == '\n') ? 1 : 0;
    }
    return line;
}

static const char *skip_whitespace(const char *start, const char *stop) {
    const char *byte = start;
    while (byte < stop && (*byte == ' ' || *byte == '\t' || *byte == '\n' || *byte == '\r')) {
        byte++;
    }
    return byte;
}

/* Trailing bytes are checked here because cJSON's own check needs NUL-terminated text. */
cJSON *json_parse_document(const char *text, size_t len, json_error *error) {
    const char *stop = text + len;
    const char *end = text;
    cJSON *document = cJSON_ParseWithLengthOpts(text, len, &end, false);
    if (document != NULL) {
        end = skip_whitespace(end, stop);
        if (end == stop) {
            return document;
        }
    }
    cJSON_Delete(document);
    (void)snprintf(error->message, JSON_ERROR_SIZE, "line %zu: invalid JSON", line_of(text, end));
    return NULL;
}

pqscan_status json_reject(const json_place *place, const char *field, const char *reason) {
    if (place->section == NULL) {
        (void)snprintf(place->error->message, JSON_ERROR_SIZE, "%s: %s", field, reason);
    } else {
        (void)snprintf(place->error->message, JSON_ERROR_SIZE, "%s[%zu].%s: %s", place->section,
                       place->index, field, reason);
    }
    return place->refusal;
}

static bool is_listed(const char *const *allowed, const char *name) {
    for (const char *const *field = allowed; *field != NULL; field++) {
        if (strcmp(*field, name) == 0) {
            return true;
        }
    }
    return false;
}

/* cJSON keeps both copies of a repeated key and its lookup returns the first. */
pqscan_status json_check_fields(const json_place *place, const cJSON *object,
                                const char *const *allowed) {
    for (const cJSON *child = object->child; child != NULL; child = child->next) {
        if (!is_listed(allowed, child->string)) {
            return json_reject(place, child->string, "unknown field");
        }
        if (cJSON_GetObjectItemCaseSensitive(object, child->string) != child) {
            return json_reject(place, child->string, "repeated field");
        }
    }
    return PQSCAN_OK;
}

static bool is_printable_name(const char *name) {
    const size_t len = strlen(name);
    if (len == 0 || len > JSON_MAX_NAME_LENGTH) {
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        const unsigned char byte = (unsigned char)name[i];
        if (byte < FIRST_PRINTABLE || byte > LAST_PRINTABLE) {
            return false;
        }
    }
    return true;
}

pqscan_status json_read_name(const json_place *place, const json_name_field *field,
                             const char **out) {
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(field->object, field->name);
    if (!cJSON_IsString(item)) {
        return json_reject(place, field->name, "expected a string");
    }
    if (!is_printable_name(item->valuestring)) {
        return json_reject(place, field->name, "expected 1 to 128 printable ASCII characters");
    }
    *out = item->valuestring;
    return PQSCAN_OK;
}

/* The range check comes first: casting a double outside int's range is undefined. */
static bool is_int_in_range(double value, const json_int_field *field) {
    return value >= (double)field->min && value <= (double)field->max &&
           (double)(int)value == value;
}

pqscan_status json_read_int(const json_place *place, const json_int_field *field, int *out) {
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(field->object, field->name);
    if (item == NULL) {
        *out = field->fallback;
        return PQSCAN_OK;
    }
    if (!cJSON_IsNumber(item) || !is_int_in_range(item->valuedouble, field)) {
        return json_reject(place, field->name, "expected an integer in range");
    }
    *out = (int)item->valuedouble;
    return PQSCAN_OK;
}

/* The fallback is outside the range, so an absent field is told apart from a wrong one. */
pqscan_status json_check_schema_version(const json_place *place, const cJSON *document,
                                        int version) {
    const json_int_field field = {document, "schema_version", version, version, version - 1};
    int found = 0;
    const pqscan_status status = json_read_int(place, &field, &found);
    if (status == PQSCAN_OK && found != version) {
        return json_reject(place, field.name, "missing");
    }
    return status;
}
