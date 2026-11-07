/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/report/sarif_uri.h"

#include "pqscan/report/json_writer.h"

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

enum { HIGH_NIBBLE_SHIFT = 4, LOW_NIBBLE_MASK = 0x0F };

static const char HEX_DIGITS[] = "0123456789ABCDEF";
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
    const unsigned char value = (unsigned char)byte;
    const char encoded[] = {'%', HEX_DIGITS[value >> HIGH_NIBBLE_SHIFT],
                            HEX_DIGITS[value & LOW_NIBBLE_MASK]};
    json_append_raw(json, encoded, sizeof(encoded));
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
