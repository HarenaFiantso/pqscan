/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/scan/source_scanner.h"

#include "pqscan/core/finding.h"
#include "pqscan/core/status.h"
#include "pqscan/scan/file_reader.h"
#include "pqscan/scan/openssl_identifiers.h"
#include "pqscan/scan/scanner.h"
#include "pqscan/walk/file_type.h"

#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

typedef struct source_cursor {
    const char *path;
    size_t line;
    finding_list *findings;
} source_cursor;

/* Bytes above 0x7F are not identifier characters, which also makes non-UTF-8 input harmless. */
static bool is_identifier_char(char byte) {
    return isalnum((unsigned char)byte) != 0 || byte == '_';
}

static size_t find_token_end(const file_contents *file, size_t start) {
    size_t end = start;
    while (end < file->len && is_identifier_char(file->data[end])) {
        end++;
    }
    return end;
}

static pqscan_status report_token(const source_cursor *cursor, const char *token, size_t len) {
    if (isdigit((unsigned char)token[0]) != 0) {
        return PQSCAN_OK;
    }
    const crypto_identifier *known = openssl_identifier_find(token, len);
    if (known == NULL) {
        return PQSCAN_OK;
    }
    const finding item = {cursor->path, cursor->line, known->algorithm, known->risk};
    return finding_list_add(cursor->findings, &item);
}

static pqscan_status scan_tokens(source_cursor *cursor, const file_contents *file) {
    size_t position = 0;
    while (position < file->len) {
        const char byte = file->data[position];
        if (!is_identifier_char(byte)) {
            cursor->line += (byte == '\n') ? 1 : 0;
            position++;
            continue;
        }
        const size_t end = find_token_end(file, position);
        const pqscan_status status = report_token(cursor, file->data + position, end - position);
        if (status != PQSCAN_OK) {
            return status;
        }
        position = end;
    }
    return PQSCAN_OK;
}

static pqscan_status scan_source(const char *path, const file_contents *file,
                                 finding_list *findings) {
    if (memchr(file->data, '\0', file->len) != NULL) {
        return PQSCAN_ERR_BINARY;
    }
    source_cursor cursor = {path, 1, findings};
    return scan_tokens(&cursor, file);
}

const scanner source_scanner = {"source", file_type_is_source, scan_source};
