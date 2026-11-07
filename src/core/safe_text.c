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
    CONTINUATION_MASK = 0xC0,
    CONTINUATION_BITS = 0x80,
    CONTINUATION_PAYLOAD = 0x3F,
    CONTINUATION_SHIFT = 6,
};

/* What a lead byte announces. Each sequence must encode at least min_code_point, because a
 * longer encoding of a small value is how filters get bypassed. */
typedef struct utf8_form {
    unsigned char lead_mask;
    unsigned char lead_bits;
    size_t len;
    uint32_t min_code_point;
} utf8_form;

static const utf8_form FORMS[] = {
    {0xE0, 0xC0, 2, 0x80},
    {0xF0, 0xE0, 3, 0x800},
    {0xF8, 0xF0, 4, 0x10000},
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
    uint32_t code_point = text[0] & (unsigned char)~form->lead_mask;
    for (size_t i = 1; i < form->len; i++) {
        if ((text[i] & CONTINUATION_MASK) != CONTINUATION_BITS) {
            return false;
        }
        code_point = (code_point << CONTINUATION_SHIFT) | (text[i] & CONTINUATION_PAYLOAD);
    }
    *out = code_point;
    return code_point >= form->min_code_point;
}

/* The length of the safe multi-byte character at text, or 0 if there is none. */
static size_t safe_sequence_len(const unsigned char *text) {
    for (size_t i = 0; i < sizeof(FORMS) / sizeof(FORMS[0]); i++) {
        uint32_t code_point = 0;
        if ((text[0] & FORMS[i].lead_mask) == FORMS[i].lead_bits) {
            const bool valid = decode(text, &FORMS[i], &code_point);
            return (valid && !is_unsafe(code_point)) ? FORMS[i].len : 0;
        }
    }
    return 0;
}

static bool write_escaped(FILE *out, unsigned char byte) {
    return (byte == '\\') ? fputs("\\\\", out) != EOF : fprintf(out, "\\x%02x", byte) > 0;
}

static bool is_plain_ascii(unsigned char byte) {
    return byte >= FIRST_PRINTABLE && byte < LAST_ASCII && byte != '\\';
}

pqscan_status safe_text_write(FILE *out, const char *text) {
    const unsigned char *rest = (const unsigned char *)text;
    while (*rest != '\0') {
        const size_t len = is_plain_ascii(*rest) ? 1 : safe_sequence_len(rest);
        const bool written =
            (len > 0) ? fwrite(rest, 1, len, out) == len : write_escaped(out, *rest);
        if (!written) {
            return PQSCAN_ERR_IO;
        }
        rest += (len > 0) ? len : 1;
    }
    return PQSCAN_OK;
}
