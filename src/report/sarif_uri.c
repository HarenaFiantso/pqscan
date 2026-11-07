/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/report/sarif_uri.h"

#include "pqscan/report/json_writer.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

/* Large enough for "%XX" and its NUL. */
enum { ENCODED_BYTE_SIZE = 4 };

static const char FILE_SCHEME[] = "file://";
static const char CURRENT_DIRECTORY[] = ".";

/* A colon has to be encoded too: in "a:b.c" it would turn the first segment into a scheme. */
static bool is_plain_in_uri(char byte) {
    const bool letter = (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z');
    const bool digit = byte >= '0' && byte <= '9';
    return letter || digit || (byte != '\0' && strchr("-._~/", byte) != NULL);
}

static void write_uri_byte(json_writer *json, char byte) {
    if (is_plain_in_uri(byte)) {
        json_append_raw(json, &byte, 1);
        return;
    }
    char encoded[ENCODED_BYTE_SIZE];
    const int len = snprintf(encoded, sizeof(encoded), "%%%02X", (unsigned)(unsigned char)byte);
    json_append_raw(json, encoded, (size_t)len);
}

static const char *skip_current_directory(const char *path) {
    const char *rest = path;
    while (rest[0] == '.' && rest[1] == '/') {
        rest += strspn(rest + 1, "/") + 1;
    }
    return (*rest == '\0') ? CURRENT_DIRECTORY : rest;
}

void sarif_write_uri(json_writer *json, const char *path) {
    json_begin_string(json);
    if (path[0] == '/') {
        json_append_raw(json, FILE_SCHEME, strlen(FILE_SCHEME));
    }
    for (const char *rest = skip_current_directory(path); *rest != '\0'; rest++) {
        write_uri_byte(json, *rest);
    }
    json_end_string(json);
}
