/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_SCAN_CONFIG_LEXER_H
#define PQSCAN_SCAN_CONFIG_LEXER_H

#include <stdbool.h>
#include <stddef.h>

/** Words after these in one statement are dropped. No setting pqscan reads needs as many. */
enum { CONFIG_MAX_WORDS = 8 };

/** One word of a statement. It points into the scanned text, which must outlive it. */
typedef struct config_word {
    const char *text; /**< Not NUL-terminated. Quotes around the whole word are left out. */
    size_t len;
    size_t line; /**< The line the word starts on, from 1. */
} config_word;

/** A directive and its arguments, such as "ssl_ciphers HIGH:!aNULL". */
typedef struct config_statement {
    config_word words[CONFIG_MAX_WORDS];
    size_t count; /**< At least 1. */
} config_statement;

/**
 * Splits the text of an OpenSSL, nginx, Apache or OpenSSH configuration file into statements.
 *
 * One lexer reads all four, because what pqscan needs from each is the same: a name, then
 * words. A statement ends at a newline, ';', '{' or '}' outside quotes. '#' starts a comment,
 * a backslash before a newline joins two lines, and '=' may separate the name from the rest.
 * Single and double quotes group a word, which may then span lines, and a backslash escapes
 * the next byte inside them. A quote that is never closed counts as an ordinary byte.
 *
 * The lexer does not allocate. Its fields are private.
 */
typedef struct config_lexer {
    const char *text;
    size_t len;
    size_t pos;
    size_t line;
    bool double_quote_unclosed;
    bool single_quote_unclosed;
} config_lexer;

/**
 * @brief Start reading a text.
 *
 * @param lexer The lexer.
 * @param text The text, which must outlive the lexer and every statement it returns. It need
 *             not be NUL-terminated, and is never read past @p len.
 * @param len The length of the text.
 */
void config_lexer_init(config_lexer *lexer, const char *text, size_t len);

/**
 * @brief Read the next statement that has at least one word.
 *
 * @param lexer The lexer.
 * @param statement Out: the statement, whose words point into the text.
 * @return true if a statement was read, false at the end of the text.
 */
bool config_lexer_next(config_lexer *lexer, config_statement *statement);

#endif /* PQSCAN_SCAN_CONFIG_LEXER_H */
