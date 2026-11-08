/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/scan/config_lexer.h"

#include <stdbool.h>
#include <stddef.h>

enum { QUOTE_LEN = 1 };

/* Where a quoted run ends, when it does. */
typedef struct quote_end {
    size_t pos;      /* Just after the closing quote. */
    size_t newlines; /* How many lines the run spans beyond the first. */
} quote_end;

void config_lexer_init(config_lexer *lexer, const char *text, size_t len) {
    const config_lexer start = {text, len, 0, 1, false, false};
    *lexer = start;
}

static bool is_blank(char byte) {
    return byte == ' ' || byte == '\t' || byte == '\r' || byte == '\v' || byte == '\f';
}

static bool ends_statement(char byte) {
    return byte == '\n' || byte == ';' || byte == '{' || byte == '}';
}

static bool is_quote(char byte) { return byte == '"' || byte == '\''; }

static bool at_end(const config_lexer *lexer) { return lexer->pos >= lexer->len; }

static char current(const config_lexer *lexer) { return lexer->text[lexer->pos]; }

/* The length of a backslash-newline at pos, with an optional \r between, or 0 if none is. */
static size_t continuation_len(const config_lexer *lexer, size_t pos) {
    const char *text = lexer->text;
    if (text[pos] != '\\') {
        return 0;
    }
    if (pos + 1 < lexer->len && text[pos + 1] == '\n') {
        return 2;
    }
    const bool crlf = pos + 2 < lexer->len && text[pos + 1] == '\r' && text[pos + 2] == '\n';
    return crlf ? 3 : 0;
}

static void skip_blanks(config_lexer *lexer) {
    while (!at_end(lexer)) {
        const size_t joined = continuation_len(lexer, lexer->pos);
        if (joined > 0) {
            lexer->pos += joined;
            lexer->line++;
        } else if (is_blank(current(lexer))) {
            lexer->pos++;
        } else {
            return;
        }
    }
}

/* The newline itself is left, because it still ends the statement. */
static void skip_comment(config_lexer *lexer) {
    while (!at_end(lexer) && current(lexer) != '\n') {
        lexer->pos++;
    }
}

static bool *unclosed_flag(config_lexer *lexer, char quote) {
    return (quote == '"') ? &lexer->double_quote_unclosed : &lexer->single_quote_unclosed;
}

/* Once a search for a closing quote fails, every later one would fail too, so it is not
 * repeated. That keeps a file full of stray quotes linear to read. */
static bool find_closing_quote(config_lexer *lexer, quote_end *end) {
    const char quote = current(lexer);
    bool *unclosed = unclosed_flag(lexer, quote);
    size_t newlines = 0;
    for (size_t pos = lexer->pos + QUOTE_LEN; !*unclosed && pos < lexer->len; pos++) {
        const char byte = lexer->text[pos];
        if (byte == quote) {
            end->pos = pos + QUOTE_LEN;
            end->newlines = newlines;
            return true;
        }
        if (byte == '\\' && pos + 1 < lexer->len) {
            pos++;
        }
        newlines += (lexer->text[pos] == '\n') ? 1 : 0;
    }
    *unclosed = true;
    return false;
}

static bool ends_word(const config_lexer *lexer, bool is_name) {
    const char byte = current(lexer);
    return is_blank(byte) || ends_statement(byte) || byte == '#' || (is_name && byte == '=') ||
           continuation_len(lexer, lexer->pos) > 0;
}

/* Returns whether the word was one quoted run from start to end. The first byte is always
 * taken, so that a name starting with '=' cannot leave the lexer where it was. */
static bool read_word_bytes(config_lexer *lexer, bool is_name) {
    const size_t start = lexer->pos;
    bool whole_quoted = false;
    while (!at_end(lexer) && (lexer->pos == start || !ends_word(lexer, is_name))) {
        quote_end end;
        if (is_quote(current(lexer)) && find_closing_quote(lexer, &end)) {
            whole_quoted = lexer->pos == start;
            lexer->pos = end.pos;
            lexer->line += end.newlines;
        } else {
            whole_quoted = false;
            lexer->pos++;
        }
    }
    return whole_quoted;
}

static void read_word(config_lexer *lexer, config_statement *statement) {
    const size_t start = lexer->pos;
    const size_t line = lexer->line;
    const bool quoted = read_word_bytes(lexer, statement->count == 0);
    if (statement->count == CONFIG_MAX_WORDS) {
        return;
    }
    const size_t trim = quoted ? QUOTE_LEN : 0;
    const config_word word = {
        lexer->text + start + trim,
        lexer->pos - start - (2 * trim),
        line,
    };
    statement->words[statement->count++] = word;
}

/* Returns true when the statement read so far is complete. */
static bool read_token(config_lexer *lexer, config_statement *statement, bool *saw_equals) {
    const char byte = current(lexer);
    if (ends_statement(byte)) {
        lexer->line += (byte == '\n') ? 1 : 0;
        lexer->pos++;
        return statement->count > 0;
    }
    if (byte == '#') {
        skip_comment(lexer);
    } else if (byte == '=' && statement->count == 1 && !*saw_equals) {
        *saw_equals = true;
        lexer->pos++;
    } else {
        read_word(lexer, statement);
    }
    return false;
}

bool config_lexer_next(config_lexer *lexer, config_statement *statement) {
    statement->count = 0;
    bool saw_equals = false;
    for (;;) {
        skip_blanks(lexer);
        if (at_end(lexer)) {
            return statement->count > 0;
        }
        if (read_token(lexer, statement, &saw_equals)) {
            return true;
        }
    }
}
