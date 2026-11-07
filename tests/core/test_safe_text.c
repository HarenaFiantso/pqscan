/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/safe_text.h"
#include "pqscan/core/status.h"
#include "unity.h"

#include <stddef.h>
#include <stdio.h>

enum { OUTPUT_SIZE = 128 };

void setUp(void) {}

void tearDown(void) {}

static void assert_written(const char *text, const char *expected) {
    FILE *file = tmpfile();
    TEST_ASSERT_NOT_NULL(file);
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, safe_text_write(file, text));
    const int rewound = fseek(file, 0, SEEK_SET);
    TEST_ASSERT_EQUAL_INT(0, rewound);
    char output[OUTPUT_SIZE];
    const size_t len = fread(output, 1, sizeof(output) - 1, file);
    output[len] = '\0';
    const int closed = fclose(file);
    TEST_ASSERT_EQUAL_INT(0, closed);
    TEST_ASSERT_EQUAL_STRING(expected, output);
}

static void test_plain_paths_are_unchanged(void) {
    assert_written("src/a-b_c.d/e f.c", "src/a-b_c.d/e f.c");
    assert_written("", "");
}

static void test_a_line_break_cannot_forge_a_line(void) {
    assert_written("a\nb.c:1: AES-256 (OK)\n.c", "a\\x0ab.c:1: AES-256 (OK)\\x0a.c");
    assert_written("a\rb", "a\\x0db");
}

static void test_terminal_controls_are_escaped(void) {
    assert_written("\x1b[2Khide.c", "\\x1b[2Khide.c");
    assert_written("a\x7f", "a\\x7f");
    assert_written("a\tb", "a\\x09b");
}

static void test_a_backslash_cannot_pass_for_an_escape(void) {
    assert_written("a\\x0a.c", "a\\\\x0a.c");
}

static void test_valid_utf8_is_kept(void) {
    assert_written("caf\xc3\xa9.c", "caf\xc3\xa9.c");
    assert_written("\xe6\x97\xa5\xe6\x9c\xac.c", "\xe6\x97\xa5\xe6\x9c\xac.c");
    assert_written("\xf0\x9f\x94\x91.c", "\xf0\x9f\x94\x91.c");
}

static void test_invalid_utf8_is_escaped(void) {
    assert_written("\xff", "\\xff");
    assert_written("a\xc3", "a\\xc3");
    assert_written("\xc0\xaf", "\\xc0\\xaf");                   /* Overlong "/". */
    assert_written("\xe0\x80\xaf", "\\xe0\\x80\\xaf");          /* Overlong "/". */
    assert_written("\xed\xa0\x80", "\\xed\\xa0\\x80");          /* A surrogate. */
    assert_written("\xf4\x90\x80\x80", "\\xf4\\x90\\x80\\x80"); /* Past U+10FFFF. */
}

static void test_utf8_terminal_controls_are_escaped(void) {
    assert_written("\xc2\x9b"
                   "2K",
                   "\\xc2\\x9b2K"); /* U+009B, CSI on many terminals. */
}

/* These literals hold the very marks the check warns about, which is what is being tested. */
static void test_utf8_reordering_marks_are_escaped(void) {
    // NOLINTNEXTLINE(misc-misleading-bidirectional)
    assert_written("\xe2\x80\xae.c", "\\xe2\\x80\\xae.c"); /* U+202E, right-to-left override. */
    // NOLINTNEXTLINE(misc-misleading-bidirectional)
    assert_written("\xe2\x81\xa6.c", "\\xe2\\x81\\xa6.c"); /* U+2066, left-to-right isolate. */
    assert_written("\xe2\x80\xa8.c", "\\xe2\\x80\\xa8.c"); /* U+2028, line separator. */
}

static void test_reports_a_failed_write(void) {
    FILE *read_only = fopen("/dev/null", "r");
    TEST_ASSERT_NOT_NULL(read_only);
    const pqscan_status status = safe_text_write(read_only, "a");
    const pqscan_status flushed = (fflush(read_only) == 0) ? status : PQSCAN_ERR_IO;
    const int closed = fclose(read_only);
    TEST_ASSERT_EQUAL_INT(0, closed);
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_IO, flushed);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_plain_paths_are_unchanged);
    RUN_TEST(test_a_line_break_cannot_forge_a_line);
    RUN_TEST(test_terminal_controls_are_escaped);
    RUN_TEST(test_a_backslash_cannot_pass_for_an_escape);
    RUN_TEST(test_valid_utf8_is_kept);
    RUN_TEST(test_invalid_utf8_is_escaped);
    RUN_TEST(test_utf8_terminal_controls_are_escaped);
    RUN_TEST(test_utf8_reordering_marks_are_escaped);
    RUN_TEST(test_reports_a_failed_write);
    return UNITY_END();
}
