/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/scan/pem_blocks.h"

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

static const char BEGIN_MARKER[] = "-----BEGIN ";
static const char END_MARKER[] = "-----END ";
static const char DASHES[] = "-----";

void pem_finder_init(pem_finder *finder, const char *text, size_t len) {
    const pem_finder start = {text, len, 0, 1};
    *finder = start;
}

static bool starts_with(const pem_finder *finder, size_t pos, const char *prefix) {
    const size_t prefix_len = strlen(prefix);
    return finder->len - pos >= prefix_len && memcmp(finder->text + pos, prefix, prefix_len) == 0;
}

/* Where the line holding pos ends, including its newline. */
static size_t line_end(const pem_finder *finder, size_t pos) {
    const char *newline = memchr(finder->text + pos, '\n', finder->len - pos);
    return (newline != NULL) ? (size_t)(newline - finder->text) + 1 : finder->len;
}

static void next_line(pem_finder *finder) {
    finder->pos = line_end(finder, finder->pos);
    finder->line++;
}

/* The label runs from the marker to the closing dashes, which must be on the same line. */
static size_t label_len(const pem_finder *finder, size_t label_start, size_t stop) {
    const size_t dashes_len = strlen(DASHES);
    for (size_t pos = label_start; pos + dashes_len <= stop; pos++) {
        if (memcmp(finder->text + pos, DASHES, dashes_len) == 0) {
            return pos - label_start;
        }
    }
    return stop - label_start;
}

/* Leaves pos after the END line, or at the next BEGIN line, or at the end of the text. */
static void skip_block_body(pem_finder *finder) {
    next_line(finder);
    while (finder->pos < finder->len && !starts_with(finder, finder->pos, BEGIN_MARKER)) {
        const bool is_end = starts_with(finder, finder->pos, END_MARKER);
        next_line(finder);
        if (is_end) {
            return;
        }
    }
}

static void read_block(pem_finder *finder, pem_block *block) {
    const size_t start = finder->pos;
    const size_t label_start = start + strlen(BEGIN_MARKER);
    block->label = finder->text + label_start;
    block->label_len = label_len(finder, label_start, line_end(finder, start));
    block->line = finder->line;
    skip_block_body(finder);
    block->text = finder->text + start;
    block->len = finder->pos - start;
}

bool pem_finder_next(pem_finder *finder, pem_block *block) {
    while (finder->pos < finder->len) {
        if (starts_with(finder, finder->pos, BEGIN_MARKER)) {
            read_block(finder, block);
            return true;
        }
        next_line(finder);
    }
    return false;
}
