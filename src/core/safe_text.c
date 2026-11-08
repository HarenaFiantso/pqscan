/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/safe_text.h"

#include "pqscan/core/status.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

enum {
    FIRST_PRINTABLE = 0x20,
    LAST_ASCII = 0x7f, /* DEL, which is not printable. */
};

static const uint32_t CONTINUATION_MASK = 0xC0U;
static const uint32_t CONTINUATION_BITS = 0x80U;
static const uint32_t CONTINUATION_PAYLOAD = 0x3FU;
static const unsigned CONTINUATION_SHIFT = 6U;

/* What a lead byte announces. Each sequence must encode at least min_code_point, because a
 * longer encoding of a small value is how filters get bypassed. */
typedef struct utf8_form {
    uint32_t lead_mask;
    uint32_t lead_bits;
    size_t len;
    uint32_t min_code_point;
} utf8_form;

static const utf8_form FORMS[] = {
    {0xE0U, 0xC0U, 2, 0x80U},
    {0xF0U, 0xE0U, 3, 0x800U},
    {0xF8U, 0xF0U, 4, 0x10000U},
};

/* C1 controls include the 8-bit CSI. The rest can rearrange or split what a terminal shows. */
typedef struct code_point_range {
    uint32_t first;
    uint32_t last;
} code_point_range;

static const code_point_range UNSAFE_RANGES[] = {
    {0x80, 0x9F},     /* C1 controls. */
    {0x2028, 0x202E}, /* Line and paragraph separators, and bidirectional embeddings. */
    {0x2066, 0x2069}, /* Bidirectional isolates. */
    {0xD800, 0xDFFF}, /* Surrogates, which UTF-8 does not encode. */
    {0x110000, UINT32_MAX},
};

static bool is_unsafe(uint32_t code_point) {
    for (size_t i = 0; i < sizeof(UNSAFE_RANGES) / sizeof(UNSAFE_RANGES[0]); i++) {
        if (code_point >= UNSAFE_RANGES[i].first && code_point <= UNSAFE_RANGES[i].last) {
            return true;
        }
    }
    return false;
}

/* The text ends in NUL, which is no continuation byte, so this never reads past it. */
static bool decode(const unsigned char *text, const utf8_form *form, uint32_t *out) {
    uint32_t code_point = (uint32_t)text[0] & ~form->lead_mask;
    for (size_t i = 1; i < form->len; i++) {
        const uint32_t byte = text[i];
        if ((byte & CONTINUATION_MASK) != CONTINUATION_BITS) {
            return false;
        }
        code_point = (code_point << CONTINUATION_SHIFT) | (byte & CONTINUATION_PAYLOAD);
    }
    *out = code_point;
    return code_point >= form->min_code_point;
}

/* The length of the safe multi-byte character at text, or 0 if there is none. */
static size_t safe_sequence_len(const unsigned char *text) {
    for (size_t i = 0; i < sizeof(FORMS) / sizeof(FORMS[0]); i++) {
        uint32_t code_point = 0;
        if (((uint32_t)text[0] & FORMS[i].lead_mask) == FORMS[i].lead_bits) {
            const bool valid = decode(text, &FORMS[i], &code_point);
            return (valid && !is_unsafe(code_point)) ? FORMS[i].len : 0;
        }
    }
    return 0;
}

static bool is_plain_ascii(unsigned char byte) {
    return byte >= FIRST_PRINTABLE && byte < LAST_ASCII && byte != '\\';
}

/* Large enough for "\\xNN" and its NUL. */
enum { ESCAPED_BYTE_SIZE = 5 };

static bool send_escaped(unsigned char byte, safe_text_sink sink, void *context) {
    if (byte == '\\') {
        return sink("\\\\", 2, context);
    }
    char escaped[ESCAPED_BYTE_SIZE];
    const int len = snprintf(escaped, sizeof(escaped), "\\x%02x", (unsigned)byte);
    return len > 0 && sink(escaped, (size_t)len, context);
}

/* Sends the next character of the text. Tells how many bytes it took, or 0 if the sink stopped. */
static size_t send_next(const unsigned char *text, safe_text_sink sink, void *context) {
    const size_t len = is_plain_ascii(*text) ? 1 : safe_sequence_len(text);
    if (len == 0) {
        return send_escaped(*text, sink, context) ? 1 : 0;
    }
    return sink((const char *)text, len, context) ? len : 0;
}

bool safe_text_visit(const char *text, safe_text_sink sink, void *context) {
    const unsigned char *rest = (const unsigned char *)text;
    while (*rest != '\0') {
        const size_t len = send_next(rest, sink, context);
        if (len == 0) {
            return false;
        }
        rest += len;
    }
    return true;
}

static bool write_to_stream(const char *bytes, size_t len, void *context) {
    return fwrite(bytes, 1, len, (FILE *)context) == len;
}

pqscan_status safe_text_write(FILE *out, const char *text) {
    return safe_text_visit(text, write_to_stream, out) ? PQSCAN_OK : PQSCAN_ERR_IO;
}

/* Where a comparison is in the safe form it is matched against. */
typedef struct comparison {
    const unsigned char *rest;
    int order;
} comparison;

/* The pieces never hold a NUL, so the end of rest is a mismatch, found before reading past it. */
static bool compare_piece(const char *bytes, size_t len, void *context) {
    comparison *state = context;
    for (size_t i = 0; i < len; i++) {
        const unsigned char ours = (unsigned char)bytes[i];
        if (ours != state->rest[i]) {
            state->order = (ours < state->rest[i]) ? -1 : 1;
            return false;
        }
    }
    state->rest += len;
    return true;
}

int safe_text_compare(const char *text, const char *safe) {
    comparison state = {(const unsigned char *)safe, 0};
    if (!safe_text_visit(text, compare_piece, &state)) {
        return state.order;
    }
    return (*state.rest == '\0') ? 0 : -1;
}
