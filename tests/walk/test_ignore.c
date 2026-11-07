/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/status.h"
#include "pqscan/core/string_list.h"
#include "pqscan/walk/ignore.h"
#include "unity.h"

static string_list *patterns;

void setUp(void) {
    patterns = string_list_create();
    TEST_ASSERT_NOT_NULL(patterns);
}

void tearDown(void) { string_list_destroy(patterns); }

static void add_pattern(const char *pattern) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, string_list_add(patterns, pattern));
}

static void test_no_patterns_match_nothing(void) {
    TEST_ASSERT_FALSE(ignore_matches(patterns, "a.c"));
}

static void test_matches_the_last_component(void) {
    add_pattern("vendor");
    TEST_ASSERT_TRUE(ignore_matches(patterns, "src/vendor"));
    TEST_ASSERT_FALSE(ignore_matches(patterns, "src/vendored"));
}

static void test_supports_globs(void) {
    add_pattern("*.gen.c");
    TEST_ASSERT_TRUE(ignore_matches(patterns, "src/a.gen.c"));
    TEST_ASSERT_FALSE(ignore_matches(patterns, "src/a.c"));
}

static void test_matches_the_whole_path(void) {
    add_pattern("src/vendor/*");
    TEST_ASSERT_TRUE(ignore_matches(patterns, "src/vendor/deep/a.c"));
    TEST_ASSERT_FALSE(ignore_matches(patterns, "lib/src/vendor/a.c"));
}

static void test_ignores_a_leading_current_directory(void) {
    add_pattern("src/*");
    TEST_ASSERT_TRUE(ignore_matches(patterns, "./src/a.c"));
    TEST_ASSERT_TRUE(ignore_matches(patterns, "././src/a.c"));
}

static void test_any_pattern_can_match(void) {
    add_pattern("first");
    add_pattern("second");
    TEST_ASSERT_TRUE(ignore_matches(patterns, "second"));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_no_patterns_match_nothing);
    RUN_TEST(test_matches_the_last_component);
    RUN_TEST(test_supports_globs);
    RUN_TEST(test_matches_the_whole_path);
    RUN_TEST(test_ignores_a_leading_current_directory);
    RUN_TEST(test_any_pattern_can_match);
    return UNITY_END();
}
