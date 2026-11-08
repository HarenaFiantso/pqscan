/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/scan/config_lexer.h"
#include "unity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    DESCRIPTION_SIZE = 512,
    LINE_LABEL_SIZE = 32,
    HUGE_LINE_SIZE = 1024 * 1024,
    STRAY_QUOTES = 100000,
};

/* Where a description is written. */
typedef struct output {
    char *text;
    size_t size;
} output;

void setUp(void) {}

void tearDown(void) {}

static void append(const output *out, const char *text, size_t len) {
    const size_t used = strlen(out->text);
    TEST_ASSERT_TRUE_MESSAGE(used + len < out->size, "description too long");
    memcpy(out->text + used, text, len);
    out->text[used + len] = '\0';
}

static void append_statement(const output *out, const config_statement *statement) {
    TEST_ASSERT_GREATER_THAN_size_t(0, statement->count);
    char line[LINE_LABEL_SIZE];
    const int written = snprintf(line, sizeof(line), "%s%zu:", (out->text[0] != '\0') ? " " : "",
                                 statement->words[0].line);
    TEST_ASSERT_GREATER_THAN_INT(0, written);
    append(out, line, (size_t)written);
    for (size_t i = 0; i < statement->count; i++) {
        if (i > 0) {
            append(out, "|", 1);
        }
        append(out, statement->words[i].text, statement->words[i].len);
    }
}

/* Describes each statement as "line:word|word" and joins them with spaces. */
static void describe(const char *text, size_t len, const output *out) {
    config_lexer lexer;
    config_lexer_init(&lexer, text, len);
    config_statement statement;
    out->text[0] = '\0';
    while (config_lexer_next(&lexer, &statement)) {
        append_statement(out, &statement);
    }
}

static void assert_statements(const char *text, const char *expected) {
    char description[DESCRIPTION_SIZE];
    const output out = {description, sizeof(description)};
    describe(text, strlen(text), &out);
    TEST_ASSERT_EQUAL_STRING(expected, description);
}

static void test_an_empty_text_has_no_statement(void) {
    assert_statements("", "");
    assert_statements("\n\n   \t\r\n", "");
    assert_statements(";;{}", "");
}

static void test_reads_a_name_and_its_words(void) {
    assert_statements("KexAlgorithms curve25519-sha256,ssh-rsa\n",
                      "1:KexAlgorithms|curve25519-sha256,ssh-rsa");
}

static void test_an_equals_sign_may_follow_the_name(void) {
    assert_statements("CipherString = DEFAULT:@SECLEVEL=2\n", "1:CipherString|DEFAULT:@SECLEVEL=2");
    assert_statements("Ciphers=aes128-ctr\n", "1:Ciphers|aes128-ctr");
    assert_statements("a = = b\n", "1:a|=|b");
    assert_statements("=x\n", "1:=x");
}

static void test_newlines_and_semicolons_and_braces_end_statements(void) {
    assert_statements("a 1\nb 2; c 3\n", "1:a|1 2:b|2 2:c|3");
    assert_statements("server { ssl_ciphers HIGH; }", "1:server 1:ssl_ciphers|HIGH");
}

static void test_counts_lines_from_one(void) {
    assert_statements("\n\n  Ciphers 3des-cbc\r\n\r\nMACs hmac-md5",
                      "3:Ciphers|3des-cbc 5:MACs|hmac-md5");
}

static void test_skips_comments(void) {
    assert_statements("# Ciphers 3des-cbc\nMACs hmac-sha1 # hmac-md5\n", "2:MACs|hmac-sha1");
    assert_statements("Groups = X25519#P-256\n", "1:Groups|X25519");
}

static void test_quotes_group_a_word_and_are_left_out(void) {
    assert_statements("ssl_ciphers 'ECDHE RSA';\n", "1:ssl_ciphers|ECDHE RSA");
    assert_statements("SSLCipherSuite \"HIGH:!aNULL # not a comment\"\n",
                      "1:SSLCipherSuite|HIGH:!aNULL # not a comment");
    assert_statements("a \"\"\n", "1:a|");
}

static void test_a_quote_inside_a_word_is_kept(void) {
    assert_statements("a x\"y z\"w\n", "1:a|x\"y z\"w");
    assert_statements("a \"x\"y\n", "1:a|\"x\"y");
}

static void test_a_quoted_word_may_span_lines(void) {
    assert_statements("ssl_ciphers \"ECDHE:\n  RSA\";\nnext 1\n",
                      "1:ssl_ciphers|ECDHE:\n  RSA 3:next|1");
}

static void test_a_backslash_escapes_inside_quotes(void) {
    assert_statements("a \"x\\\"y\" b\n", "1:a|x\\\"y|b");
}

static void test_an_unclosed_quote_is_an_ordinary_byte(void) {
    assert_statements("a \"x\nb y\n", "1:a|\"x 2:b|y");
    assert_statements("a it's\nb y\n", "1:a|it's 2:b|y");
}

static void test_a_backslash_before_a_newline_joins_lines(void) {
    assert_statements("SSLCipherSuite ECDHE:\\\n  RSA\nnext 1\n",
                      "1:SSLCipherSuite|ECDHE:|RSA 3:next|1");
    assert_statements("a \\\r\n b\n", "1:a|b");
    assert_statements("a b\\", "1:a|b\\");
}

static void test_keeps_at_most_the_word_limit(void) {
    assert_statements("a 1 2 3 4 5 6 7 8 9 10\nb\n", "1:a|1|2|3|4|5|6|7 2:b");
}

static void test_never_reads_past_the_length(void) {
    const char text[] = "Ciphers aes128-ctr\"";
    char description[DESCRIPTION_SIZE];
    const output out = {description, sizeof(description)};
    describe(text, strlen("Ciphers aes"), &out);
    TEST_ASSERT_EQUAL_STRING("1:Ciphers|aes", description);
}

static void test_a_nul_is_an_ordinary_byte(void) {
    const char text[] = "a b\0c\nd\n";
    config_lexer lexer;
    config_lexer_init(&lexer, text, sizeof(text) - 1);
    config_statement statement;
    TEST_ASSERT_TRUE(config_lexer_next(&lexer, &statement));
    TEST_ASSERT_EQUAL_size_t(2, statement.count);
    TEST_ASSERT_EQUAL_size_t(3, statement.words[1].len);
    TEST_ASSERT_TRUE(config_lexer_next(&lexer, &statement));
    TEST_ASSERT_FALSE(config_lexer_next(&lexer, &statement));
}

static void test_reads_a_huge_line(void) {
    char *text = malloc(HUGE_LINE_SIZE + 1);
    TEST_ASSERT_NOT_NULL(text);
    memset(text, 'x', HUGE_LINE_SIZE);
    memcpy(text, "Ciphers ", strlen("Ciphers "));
    text[HUGE_LINE_SIZE] = '\0';
    config_lexer lexer;
    config_lexer_init(&lexer, text, HUGE_LINE_SIZE);
    config_statement statement;
    TEST_ASSERT_TRUE(config_lexer_next(&lexer, &statement));
    TEST_ASSERT_EQUAL_size_t(HUGE_LINE_SIZE - strlen("Ciphers "), statement.words[1].len);
    TEST_ASSERT_FALSE(config_lexer_next(&lexer, &statement));
    free(text);
}

/* Each stray quote would rescan the rest of the file if a failed search were repeated. */
static void test_stray_quotes_stay_linear(void) {
    char *text = malloc(STRAY_QUOTES);
    TEST_ASSERT_NOT_NULL(text);
    for (size_t i = 0; i < STRAY_QUOTES; i++) {
        text[i] = (i % 2 == 0) ? '"' : ' ';
    }
    config_lexer lexer;
    config_lexer_init(&lexer, text, STRAY_QUOTES);
    config_statement statement;
    TEST_ASSERT_TRUE(config_lexer_next(&lexer, &statement));
    TEST_ASSERT_EQUAL_size_t(CONFIG_MAX_WORDS, statement.count);
    TEST_ASSERT_FALSE(config_lexer_next(&lexer, &statement));
    free(text);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_an_empty_text_has_no_statement);
    RUN_TEST(test_reads_a_name_and_its_words);
    RUN_TEST(test_an_equals_sign_may_follow_the_name);
    RUN_TEST(test_newlines_and_semicolons_and_braces_end_statements);
    RUN_TEST(test_counts_lines_from_one);
    RUN_TEST(test_skips_comments);
    RUN_TEST(test_quotes_group_a_word_and_are_left_out);
    RUN_TEST(test_a_quote_inside_a_word_is_kept);
    RUN_TEST(test_a_quoted_word_may_span_lines);
    RUN_TEST(test_a_backslash_escapes_inside_quotes);
    RUN_TEST(test_an_unclosed_quote_is_an_ordinary_byte);
    RUN_TEST(test_a_backslash_before_a_newline_joins_lines);
    RUN_TEST(test_keeps_at_most_the_word_limit);
    RUN_TEST(test_never_reads_past_the_length);
    RUN_TEST(test_a_nul_is_an_ordinary_byte);
    RUN_TEST(test_reads_a_huge_line);
    RUN_TEST(test_stray_quotes_stay_linear);
    return UNITY_END();
}
