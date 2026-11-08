/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/relative_path.h"
#include "unity.h"

void setUp(void) {}

void tearDown(void) {}

static void test_a_plain_path_is_unchanged(void) {
    TEST_ASSERT_EQUAL_STRING("src/a.c", relative_path_of("src/a.c"));
}

static void test_leading_current_directories_are_skipped(void) {
    TEST_ASSERT_EQUAL_STRING("src/a.c", relative_path_of("./src/a.c"));
    TEST_ASSERT_EQUAL_STRING("a.c", relative_path_of("././a.c"));
    TEST_ASSERT_EQUAL_STRING("a.c", relative_path_of(".//a.c"));
}

static void test_only_the_current_directory_is_skipped(void) {
    TEST_ASSERT_EQUAL_STRING("../a.c", relative_path_of("../a.c"));
    TEST_ASSERT_EQUAL_STRING(".hidden/a.c", relative_path_of(".hidden/a.c"));
    TEST_ASSERT_EQUAL_STRING("src/./a.c", relative_path_of("src/./a.c"));
    TEST_ASSERT_EQUAL_STRING("/a.c", relative_path_of("/a.c"));
}

static void test_nothing_may_be_left(void) {
    TEST_ASSERT_EQUAL_STRING("", relative_path_of("./"));
    TEST_ASSERT_EQUAL_STRING(".", relative_path_of("."));
    TEST_ASSERT_EQUAL_STRING("", relative_path_of(""));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_a_plain_path_is_unchanged);
    RUN_TEST(test_leading_current_directories_are_skipped);
    RUN_TEST(test_only_the_current_directory_is_skipped);
    RUN_TEST(test_nothing_may_be_left);
    return UNITY_END();
}
