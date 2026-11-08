/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/report/json_writer.h"

#include "pqscan/core/safe_text.h"
#include "pqscan/core/status.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

static const size_t INDENT_WIDTH = 2;

static void put_bytes(json_writer *json, const char *bytes, size_t len) {
    if (json->status == PQSCAN_OK && fwrite(bytes, 1, len, json->out) != len) {
        json->status = PQSCAN_ERR_IO;
    }
}

static void put_text(json_writer *json, const char *text) { put_bytes(json, text, strlen(text)); }

static void put_line_break(json_writer *json) {
    put_text(json, "\n");
    for (size_t i = 0; i < json->depth * INDENT_WIDTH; i++) {
        put_text(json, " ");
    }
}

/* Puts what separates a new item from the one before it. A value that follows a key has
 * already been placed by json_key(). */
static void start_item(json_writer *json) {
    if (json->after_key) {
        json->after_key = false;
        return;
    }
    if (json->depth == 0) {
        return;
    }
    const size_t innermost = json->depth - 1;
    put_text(json, json->has_items[innermost] ? "," : "");
    json->has_items[innermost] = true;
    put_line_break(json);
}

static void open_container(json_writer *json, const char *bracket) {
    start_item(json);
    put_text(json, bracket);
    if (json->depth == JSON_WRITER_MAX_DEPTH) {
        json->status = PQSCAN_ERR_IO;
        return;
    }
    json->has_items[json->depth] = false;
    json->depth++;
}

static void close_container(json_writer *json, const char *bracket) {
    if (json->depth == 0) {
        json->status = PQSCAN_ERR_IO;
        return;
    }
    json->depth--;
    if (json->has_items[json->depth]) {
        put_line_break(json);
    }
    put_text(json, bracket);
}

/* What is left to escape after safe_text: only these two can still end or change a string. */
static bool put_json_escaped(const char *bytes, size_t len, void *context) {
    json_writer *json = context;
    for (size_t i = 0; i < len; i++) {
        if (bytes[i] == '"' || bytes[i] == '\\') {
            put_text(json, "\\");
        }
        put_bytes(json, &bytes[i], 1);
    }
    return json->status == PQSCAN_OK;
}

void json_writer_init(json_writer *json, FILE *out) {
    *json = (json_writer){.out = out, .status = PQSCAN_OK};
}

pqscan_status json_writer_finish(json_writer *json) {
    put_text(json, "\n");
    if (json->status == PQSCAN_OK && fflush(json->out) != 0) {
        json->status = PQSCAN_ERR_IO;
    }
    return json->status;
}

void json_begin_object(json_writer *json) { open_container(json, "{"); }

void json_end_object(json_writer *json) { close_container(json, "}"); }

void json_begin_array(json_writer *json) { open_container(json, "["); }

void json_end_array(json_writer *json) { close_container(json, "]"); }

void json_key(json_writer *json, const char *key) {
    start_item(json);
    put_text(json, "\"");
    json_append(json, key);
    put_text(json, "\": ");
    json->after_key = true;
}

void json_begin_string(json_writer *json) {
    start_item(json);
    put_text(json, "\"");
}

void json_append(json_writer *json, const char *text) {
    if (json->status == PQSCAN_OK) {
        (void)safe_text_visit(text, put_json_escaped, json);
    }
}

void json_append_raw(json_writer *json, const char *bytes, size_t len) {
    put_bytes(json, bytes, len);
}

void json_end_string(json_writer *json) { put_text(json, "\""); }

void json_string(json_writer *json, const char *text) {
    json_begin_string(json);
    json_append(json, text);
    json_end_string(json);
}

void json_uint(json_writer *json, size_t value) {
    start_item(json);
    if (json->status == PQSCAN_OK && fprintf(json->out, "%zu", value) < 0) {
        json->status = PQSCAN_ERR_IO;
    }
}

void json_int(json_writer *json, int value) {
    start_item(json);
    if (json->status == PQSCAN_OK && fprintf(json->out, "%d", value) < 0) {
        json->status = PQSCAN_ERR_IO;
    }
}

void json_bool(json_writer *json, bool value) {
    start_item(json);
    put_text(json, value ? "true" : "false");
}

void json_null(json_writer *json) {
    start_item(json);
    put_text(json, "null");
}

void json_field_string(json_writer *json, const char *key, const char *text) {
    json_key(json, key);
    json_string(json, text);
}

void json_field_uint(json_writer *json, const char *key, size_t value) {
    json_key(json, key);
    json_uint(json, value);
}

void json_field_int(json_writer *json, const char *key, int value) {
    json_key(json, key);
    json_int(json, value);
}
