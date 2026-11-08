/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/scan/pem_blocks.h"
#include "unity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { DESCRIPTION_SIZE = 512, MANY_BLOCKS = 10000 };

void setUp(void) {}

void tearDown(void) {}

/* Where a description is written. */
typedef struct output {
    char *text;
    size_t size;
} output;

/* Describes each block as "line:label[length]" and joins them with spaces. */
static void describe(const char *text, size_t len, const output *out) {
    pem_finder finder;
    pem_finder_init(&finder, text, len);
    pem_block block;
    size_t used = 0;
    out->text[0] = '\0';
    while (pem_finder_next(&finder, &block)) {
        TEST_ASSERT_TRUE(block.text >= text && block.text + block.len <= text + len);
        const int written =
            snprintf(out->text + used, out->size - used, "%s%zu:%.*s[%zu]", (used > 0) ? " " : "",
                     block.line, (int)block.label_len, block.label, block.len);
        TEST_ASSERT_TRUE(written > 0 && (size_t)written < out->size - used);
        used += (size_t)written;
    }
}

static void assert_blocks(const char *text, const char *expected) {
    char description[DESCRIPTION_SIZE];
    const output out = {description, sizeof(description)};
    describe(text, strlen(text), &out);
    TEST_ASSERT_EQUAL_STRING(expected, description);
}

static const char CERTIFICATE[] = "-----BEGIN CERTIFICATE-----\n"
                                  "AAAA\n"
                                  "-----END CERTIFICATE-----\n";

static void test_a_text_without_blocks_has_none(void) {
    assert_blocks("", "");
    assert_blocks("hello\n-----BEGIN", "");
    assert_blocks(" -----BEGIN CERTIFICATE-----\n", "");
}

static void test_finds_one_block_from_begin_to_end_line(void) {
    assert_blocks(CERTIFICATE, "1:CERTIFICATE[59]");
}

static void test_finds_every_block_of_a_bundle_with_its_line(void) {
    assert_blocks("subject=CN = example\n"
                  "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
                  "\n"
                  "-----BEGIN EC PRIVATE KEY-----\nBBBB\n-----END EC PRIVATE KEY-----\n",
                  "2:CERTIFICATE[59] 6:EC PRIVATE KEY[65]");
}

static void test_keeps_headers_inside_the_block(void) {
    assert_blocks("-----BEGIN RSA PRIVATE KEY-----\n"
                  "Proc-Type: 4,ENCRYPTED\n"
                  "\n"
                  "AAAA\n"
                  "-----END RSA PRIVATE KEY-----\n",
                  "1:RSA PRIVATE KEY[91]");
}

static void test_a_block_without_end_stops_before_the_next(void) {
    assert_blocks("-----BEGIN CERTIFICATE-----\nAAAA\n"
                  "-----BEGIN PUBLIC KEY-----\nBBBB\n-----END PUBLIC KEY-----\n",
                  "1:CERTIFICATE[33] 3:PUBLIC KEY[57]");
}

static void test_a_truncated_block_runs_to_the_end(void) {
    assert_blocks("-----BEGIN CERTIFICATE-----\nAAA", "1:CERTIFICATE[31]");
    assert_blocks("-----BEGIN CERTIFICATE-----", "1:CERTIFICATE[27]");
}

static void test_a_label_without_closing_dashes_runs_to_the_end_of_its_line(void) {
    assert_blocks("-----BEGIN CERT\nAAAA\n-----END CERT\n", "1:CERT\n[35]");
}

static void test_reads_crlf_files(void) {
    assert_blocks("x\r\n-----BEGIN CERTIFICATE-----\r\nAAAA\r\n-----END CERTIFICATE-----\r\n",
                  "2:CERTIFICATE[62]");
}

static void test_never_reads_past_the_length(void) {
    char description[DESCRIPTION_SIZE];
    const output out = {description, sizeof(description)};
    describe(CERTIFICATE, strlen("-----BEGIN CERTIFICATE-----\nAA"), &out);
    TEST_ASSERT_EQUAL_STRING("1:CERTIFICATE[30]", description);
}

static void test_a_nul_is_an_ordinary_byte(void) {
    const char text[] = "\0\n-----BEGIN X-----\n\0\n-----END X-----\n";
    char description[DESCRIPTION_SIZE];
    const output out = {description, sizeof(description)};
    describe(text, sizeof(text) - 1, &out);
    TEST_ASSERT_EQUAL_STRING("2:X[36]", description);
}

static void test_finds_many_blocks(void) {
    const size_t block_len = strlen(CERTIFICATE);
    const size_t len = MANY_BLOCKS * block_len;
    char *text = malloc(len + 1);
    TEST_ASSERT_NOT_NULL(text);
    /* Each copy's NUL is overwritten by the next, and the last one ends the text. */
    for (size_t i = 0; i < MANY_BLOCKS; i++) {
        memcpy(text + (i * block_len), CERTIFICATE, sizeof(CERTIFICATE));
    }
    pem_finder finder;
    pem_finder_init(&finder, text, len);
    pem_block block;
    size_t count = 0;
    size_t last_line = 0;
    while (pem_finder_next(&finder, &block)) {
        count++;
        last_line = block.line;
    }
    TEST_ASSERT_EQUAL_size_t(MANY_BLOCKS, count);
    TEST_ASSERT_EQUAL_size_t((3 * (MANY_BLOCKS - 1)) + 1, last_line);
    free(text);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_a_text_without_blocks_has_none);
    RUN_TEST(test_finds_one_block_from_begin_to_end_line);
    RUN_TEST(test_finds_every_block_of_a_bundle_with_its_line);
    RUN_TEST(test_keeps_headers_inside_the_block);
    RUN_TEST(test_a_block_without_end_stops_before_the_next);
    RUN_TEST(test_a_truncated_block_runs_to_the_end);
    RUN_TEST(test_a_label_without_closing_dashes_runs_to_the_end_of_its_line);
    RUN_TEST(test_reads_crlf_files);
    RUN_TEST(test_never_reads_past_the_length);
    RUN_TEST(test_a_nul_is_an_ordinary_byte);
    RUN_TEST(test_finds_many_blocks);
    return UNITY_END();
}
