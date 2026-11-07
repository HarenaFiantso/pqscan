/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/status.h"
#include "pqscan/report/json_writer.h"
#include "pqscan/report/sarif_uri.h"
#include "unity.h"

#include <stdio.h>

enum { OUTPUT_SIZE = 128 };

void setUp(void) {}

void tearDown(void) {}

/* The expected text is the URI without its JSON quotes. */
static void assert_uri(const char *path, const char *expected) {
    FILE *out = tmpfile();
    TEST_ASSERT_NOT_NULL(out);
    json_writer json;
    json_writer_init(&json, out);
    sarif_write_uri(&json, path);
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, json_writer_finish(&json));
    const int seek_result = fseek(out, 0, SEEK_SET);
    TEST_ASSERT_EQUAL_INT(0, seek_result);
    char output[OUTPUT_SIZE];
    const size_t len = fread(output, 1, sizeof(output) - 1, out);
    output[len] = '\0';
    const int closed = fclose(out);
    TEST_ASSERT_EQUAL_INT(0, closed);

    char quoted[OUTPUT_SIZE];
    const int written = snprintf(quoted, sizeof(quoted), "\"%s\"\n", expected);
    TEST_ASSERT_GREATER_THAN_INT(0, written);
    TEST_ASSERT_EQUAL_STRING(quoted, output);
}

static void test_a_plain_path_is_unchanged(void) {
    assert_uri("src/a-b_c.d~/e.c", "src/a-b_c.d~/e.c");
}

static void test_the_current_directory_is_dropped(void) {
    assert_uri("./src/a.c", "src/a.c");
    assert_uri("././a.c", "a.c");
    assert_uri(".//a.c", "a.c");
    assert_uri("..//a.c", "..//a.c");
    assert_uri(".hidden/a.c", ".hidden/a.c");
}

static void test_nothing_left_is_the_current_directory(void) {
    assert_uri("./", ".");
    assert_uri(".", ".");
}

static void test_an_absolute_path_is_a_file_uri(void) {
    assert_uri("/home/a.c", "file:///home/a.c");
    assert_uri("//a.c", "file:////a.c");
}

static void test_a_colon_cannot_become_a_scheme(void) { assert_uri("a:b.c", "a%3Ab.c"); }

static void test_uri_delimiters_are_encoded(void) {
    assert_uri("a b#c?d%e.c", "a%20b%23c%3Fd%25e.c");
}

static void test_a_file_name_cannot_leave_its_string(void) {
    assert_uri("a\"b\\c\n.c", "a%22b%5Cc%0A.c");
}

static void test_bytes_above_ascii_are_kept_exactly(void) {
    assert_uri("caf\xc3\xa9.c", "caf%C3%A9.c");
    assert_uri("a\xff.c", "a%FF.c");
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_a_plain_path_is_unchanged);
    RUN_TEST(test_the_current_directory_is_dropped);
    RUN_TEST(test_nothing_left_is_the_current_directory);
    RUN_TEST(test_an_absolute_path_is_a_file_uri);
    RUN_TEST(test_a_colon_cannot_become_a_scheme);
    RUN_TEST(test_uri_delimiters_are_encoded);
    RUN_TEST(test_a_file_name_cannot_leave_its_string);
    RUN_TEST(test_bytes_above_ascii_are_kept_exactly);
    return UNITY_END();
}
