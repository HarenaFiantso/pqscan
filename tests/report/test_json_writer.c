/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/status.h"
#include "pqscan/report/json_writer.h"
#include "unity.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

enum { OUTPUT_SIZE = 512 };

static json_writer json;
static FILE *out;

void setUp(void) {
    out = tmpfile();
    TEST_ASSERT_NOT_NULL(out);
    json_writer_init(&json, out);
}

void tearDown(void) {
    const int closed = fclose(out);
    TEST_ASSERT_EQUAL_INT(0, closed);
}

static void assert_output(const char *expected) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, json_writer_finish(&json));
    const int seek_result = fseek(out, 0, SEEK_SET);
    TEST_ASSERT_EQUAL_INT(0, seek_result);
    char output[OUTPUT_SIZE];
    const size_t len = fread(output, 1, sizeof(output) - 1, out);
    output[len] = '\0';
    TEST_ASSERT_EQUAL_STRING(expected, output);
}

static void test_empty_containers_stay_on_one_line(void) {
    json_begin_object(&json);
    json_key(&json, "a");
    json_begin_array(&json);
    json_end_array(&json);
    json_key(&json, "b");
    json_begin_object(&json);
    json_end_object(&json);
    json_end_object(&json);
    assert_output("{\n  \"a\": [],\n  \"b\": {}\n}\n");
}

static void test_items_are_separated_and_indented(void) {
    json_begin_array(&json);
    json_uint(&json, 1);
    json_bool(&json, true);
    json_bool(&json, false);
    json_null(&json);
    json_string(&json, "x");
    json_begin_object(&json);
    json_field_uint(&json, "n", 2);
    json_field_string(&json, "s", "y");
    json_end_object(&json);
    json_end_array(&json);
    assert_output("[\n  1,\n  true,\n  false,\n  null,\n  \"x\",\n  {\n    \"n\": 2,\n"
                  "    \"s\": \"y\"\n  }\n]\n");
}

static void test_quotes_and_backslashes_cannot_end_a_string(void) {
    json_string(&json, "a\"b\\c");
    assert_output("\"a\\\"b\\\\\\\\c\"\n");
}

static void test_control_bytes_keep_their_safe_text_form(void) {
    json_string(&json, "a\nb\x1b");
    assert_output("\"a\\\\x0ab\\\\x1b\"\n");
}

static void test_invalid_utf8_cannot_reach_the_document(void) {
    json_string(&json, "a\xff.c");
    assert_output("\"a\\\\xff.c\"\n");
}

static void test_valid_utf8_is_kept(void) {
    json_string(&json, "caf\xc3\xa9");
    assert_output("\"caf\xc3\xa9\"\n");
}

static void test_a_key_is_escaped_too(void) {
    json_begin_object(&json);
    json_key(&json, "a\"");
    json_null(&json);
    json_end_object(&json);
    assert_output("{\n  \"a\\\"\": null\n}\n");
}

static void test_a_string_can_be_built_in_parts(void) {
    json_begin_array(&json);
    json_begin_string(&json);
    json_append(&json, "a\"");
    json_append_raw(&json, "%20", 3);
    json_append(&json, "\n");
    json_end_string(&json);
    json_string(&json, "next");
    json_end_array(&json);
    assert_output("[\n  \"a\\\"%20\\\\x0a\",\n  \"next\"\n]\n");
}

static void test_a_big_number_is_written_exactly(void) {
    json_uint(&json, (size_t)-1);
    char expected[OUTPUT_SIZE];
    const int len = snprintf(expected, sizeof(expected), "%zu\n", (size_t)-1);
    TEST_ASSERT_GREATER_THAN_INT(0, len);
    assert_output(expected);
}

static void test_a_negative_number_keeps_its_sign(void) {
    json_begin_array(&json);
    json_int(&json, -1);
    json_int(&json, INT_MIN);
    json_end_array(&json);
    char expected[OUTPUT_SIZE];
    const int len = snprintf(expected, sizeof(expected), "[\n  -1,\n  %d\n]\n", INT_MIN);
    TEST_ASSERT_GREATER_THAN_INT(0, len);
    assert_output(expected);
}

static void test_nesting_too_deep_fails(void) {
    for (int i = 0; i <= JSON_WRITER_MAX_DEPTH; i++) {
        json_begin_array(&json);
    }
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_IO, json_writer_finish(&json));
}

static void test_closing_too_much_fails(void) {
    json_end_object(&json);
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_IO, json_writer_finish(&json));
}

static void test_a_failed_write_sticks(void) {
    FILE *read_only = fopen("/dev/null", "r");
    TEST_ASSERT_NOT_NULL(read_only);
    json_writer failing;
    json_writer_init(&failing, read_only);
    json_begin_object(&failing);
    json_field_string(&failing, "a", "b");
    json_field_uint(&failing, "c", 1);
    json_end_object(&failing);
    const pqscan_status status = json_writer_finish(&failing);
    const int closed = fclose(read_only);
    TEST_ASSERT_EQUAL_INT(0, closed);
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_IO, status);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_empty_containers_stay_on_one_line);
    RUN_TEST(test_items_are_separated_and_indented);
    RUN_TEST(test_quotes_and_backslashes_cannot_end_a_string);
    RUN_TEST(test_control_bytes_keep_their_safe_text_form);
    RUN_TEST(test_invalid_utf8_cannot_reach_the_document);
    RUN_TEST(test_valid_utf8_is_kept);
    RUN_TEST(test_a_key_is_escaped_too);
    RUN_TEST(test_a_string_can_be_built_in_parts);
    RUN_TEST(test_a_big_number_is_written_exactly);
    RUN_TEST(test_a_negative_number_keeps_its_sign);
    RUN_TEST(test_nesting_too_deep_fails);
    RUN_TEST(test_closing_too_much_fails);
    RUN_TEST(test_a_failed_write_sticks);
    return UNITY_END();
}
