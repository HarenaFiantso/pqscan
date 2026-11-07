/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/cli/options.h"
#include "pqscan/core/string_list.h"
#include "unity.h"

#include <stddef.h>
#include <unistd.h>

static cli_options options;

void setUp(void) { opterr = 0; }

void tearDown(void) { cli_options_destroy(&options); }

#define ARG_COUNT(argv) ((int)(sizeof(argv) / sizeof((argv)[0])))

static void test_only_the_program_name_gives_no_paths(void) {
    char *argv[] = {"pqscan"};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_OK, cli_options_parse(ARG_COUNT(argv), argv, &options));
    TEST_ASSERT_EQUAL_size_t(0, options.path_count);
    TEST_ASSERT_FALSE(options.show_help);
    TEST_ASSERT_FALSE(options.show_version);
}

static void test_parses_paths(void) {
    char *argv[] = {"pqscan", "src", "lib"};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_OK, cli_options_parse(ARG_COUNT(argv), argv, &options));
    TEST_ASSERT_EQUAL_size_t(2, options.path_count);
    TEST_ASSERT_EQUAL_STRING("src", options.paths[0]);
    TEST_ASSERT_EQUAL_STRING("lib", options.paths[1]);
}

static void test_git_directory_is_ignored_by_default(void) {
    char *argv[] = {"pqscan", "src"};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_OK, cli_options_parse(ARG_COUNT(argv), argv, &options));
    TEST_ASSERT_EQUAL_size_t(1, string_list_count(options.ignores));
    TEST_ASSERT_EQUAL_STRING(".git", string_list_get(options.ignores, 0));
}

static void test_parses_help_and_version_flags(void) {
    char *long_argv[] = {"pqscan", "--help", "--version"};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_OK,
                          cli_options_parse(ARG_COUNT(long_argv), long_argv, &options));
    TEST_ASSERT_TRUE(options.show_help);
    TEST_ASSERT_TRUE(options.show_version);
    cli_options_destroy(&options);

    char *short_argv[] = {"pqscan", "-h", "-V"};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_OK,
                          cli_options_parse(ARG_COUNT(short_argv), short_argv, &options));
    TEST_ASSERT_TRUE(options.show_help);
    TEST_ASSERT_TRUE(options.show_version);
}

static void test_ignore_is_repeatable(void) {
    char *argv[] = {"pqscan", "--ignore", "a", "-i", "b", "--ignore=c", "src"};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_OK, cli_options_parse(ARG_COUNT(argv), argv, &options));
    TEST_ASSERT_EQUAL_size_t(4, string_list_count(options.ignores));
    TEST_ASSERT_EQUAL_STRING("c", string_list_get(options.ignores, 3));
    TEST_ASSERT_EQUAL_size_t(1, options.path_count);
}

static void test_options_may_follow_paths(void) {
    char *argv[] = {"pqscan", "src", "--ignore", "a"};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_OK, cli_options_parse(ARG_COUNT(argv), argv, &options));
    TEST_ASSERT_EQUAL_size_t(1, options.path_count);
    TEST_ASSERT_EQUAL_STRING("src", options.paths[0]);
    TEST_ASSERT_EQUAL_size_t(2, string_list_count(options.ignores));
}

static void test_double_dash_ends_options(void) {
    char *argv[] = {"pqscan", "--", "--help"};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_OK, cli_options_parse(ARG_COUNT(argv), argv, &options));
    TEST_ASSERT_FALSE(options.show_help);
    TEST_ASSERT_EQUAL_STRING("--help", options.paths[0]);
}

static void test_unknown_option_is_a_usage_error(void) {
    char *argv[] = {"pqscan", "--nope", "src"};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_USAGE_ERROR,
                          cli_options_parse(ARG_COUNT(argv), argv, &options));
}

static void test_ignore_without_a_pattern_is_a_usage_error(void) {
    char *argv[] = {"pqscan", "--ignore"};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_USAGE_ERROR,
                          cli_options_parse(ARG_COUNT(argv), argv, &options));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_only_the_program_name_gives_no_paths);
    RUN_TEST(test_parses_paths);
    RUN_TEST(test_git_directory_is_ignored_by_default);
    RUN_TEST(test_parses_help_and_version_flags);
    RUN_TEST(test_ignore_is_repeatable);
    RUN_TEST(test_options_may_follow_paths);
    RUN_TEST(test_double_dash_ends_options);
    RUN_TEST(test_unknown_option_is_a_usage_error);
    RUN_TEST(test_ignore_without_a_pattern_is_a_usage_error);
    return UNITY_END();
}
