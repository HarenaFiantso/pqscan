/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/cli/options.h"
#include "pqscan/core/string_list.h"
#include "unity.h"

#include <getopt.h>
#include <stddef.h>

static cli_options options;

void setUp(void) { opterr = 0; }

void tearDown(void) { cli_options_destroy(&options); }

/* Like a real argv, the arrays below end in NULL, which getopt_long may rely on. */
#define ARG_COUNT(argv) ((int)(sizeof(argv) / sizeof((argv)[0])) - 1)

static void test_only_the_program_name_gives_no_paths(void) {
    char *argv[] = {"pqscan", NULL};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_OK, cli_options_parse(ARG_COUNT(argv), argv, &options));
    TEST_ASSERT_EQUAL_size_t(0, options.path_count);
    TEST_ASSERT_FALSE(options.show_help);
    TEST_ASSERT_FALSE(options.show_version);
}

static void test_parses_paths(void) {
    char *argv[] = {"pqscan", "src", "lib", NULL};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_OK, cli_options_parse(ARG_COUNT(argv), argv, &options));
    TEST_ASSERT_EQUAL_size_t(2, options.path_count);
    TEST_ASSERT_EQUAL_STRING("src", options.paths[0]);
    TEST_ASSERT_EQUAL_STRING("lib", options.paths[1]);
}

static void test_git_directory_is_ignored_by_default(void) {
    char *argv[] = {"pqscan", "src", NULL};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_OK, cli_options_parse(ARG_COUNT(argv), argv, &options));
    TEST_ASSERT_EQUAL_size_t(1, string_list_count(options.ignores));
    TEST_ASSERT_EQUAL_STRING(".git", string_list_get(options.ignores, 0));
}

static void test_the_time_budget_has_a_default(void) {
    char *argv[] = {"pqscan", "src", NULL};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_OK, cli_options_parse(ARG_COUNT(argv), argv, &options));
    TEST_ASSERT_EQUAL_UINT(CLI_DEFAULT_MAX_SECONDS, options.max_seconds);
}

static void test_parses_the_time_budget(void) {
    char *argv[] = {"pqscan", "--max-time", "90", "src", NULL};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_OK, cli_options_parse(ARG_COUNT(argv), argv, &options));
    TEST_ASSERT_EQUAL_UINT(90, options.max_seconds);
}

static void assert_refuses_budget(char *value) {
    char *argv[] = {"pqscan", "--max-time", value, "src", NULL};
    TEST_ASSERT_EQUAL_INT_MESSAGE(CLI_PARSE_USAGE_ERROR,
                                  cli_options_parse(ARG_COUNT(argv), argv, &options), value);
    cli_options_destroy(&options);
}

static void test_refuses_a_bad_time_budget(void) {
    assert_refuses_budget("");
    assert_refuses_budget("ten");
    assert_refuses_budget("10s");
    assert_refuses_budget("-1");
    assert_refuses_budget(" 1");
    assert_refuses_budget("99999999999999999999");
    assert_refuses_budget("2147483648");
}

static void test_parses_help_and_version_flags(void) {
    char *long_argv[] = {"pqscan", "--help", "--version", NULL};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_OK,
                          cli_options_parse(ARG_COUNT(long_argv), long_argv, &options));
    TEST_ASSERT_TRUE(options.show_help);
    TEST_ASSERT_TRUE(options.show_version);
    cli_options_destroy(&options);

    char *short_argv[] = {"pqscan", "-h", "-V", NULL};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_OK,
                          cli_options_parse(ARG_COUNT(short_argv), short_argv, &options));
    TEST_ASSERT_TRUE(options.show_help);
    TEST_ASSERT_TRUE(options.show_version);
}

static void test_rules_path_is_absent_by_default(void) {
    char *argv[] = {"pqscan", "src", NULL};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_OK, cli_options_parse(ARG_COUNT(argv), argv, &options));
    TEST_ASSERT_NULL(options.rules_path);
}

static void test_parses_the_rules_path(void) {
    char *long_argv[] = {"pqscan", "--rules", "a.json", "src", NULL};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_OK,
                          cli_options_parse(ARG_COUNT(long_argv), long_argv, &options));
    TEST_ASSERT_EQUAL_STRING("a.json", options.rules_path);
    TEST_ASSERT_EQUAL_size_t(1, options.path_count);
    cli_options_destroy(&options);

    char *short_argv[] = {"pqscan", "-r", "b.json", "src", NULL};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_OK,
                          cli_options_parse(ARG_COUNT(short_argv), short_argv, &options));
    TEST_ASSERT_EQUAL_STRING("b.json", options.rules_path);
}

static void test_the_last_rules_path_wins(void) {
    char *argv[] = {"pqscan", "--rules=a.json", "--rules=b.json", "src", NULL};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_OK, cli_options_parse(ARG_COUNT(argv), argv, &options));
    TEST_ASSERT_EQUAL_STRING("b.json", options.rules_path);
}

static void test_rules_without_a_path_is_a_usage_error(void) {
    char *argv[] = {"pqscan", "src", "--rules", NULL};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_USAGE_ERROR,
                          cli_options_parse(ARG_COUNT(argv), argv, &options));
}

static void test_ignore_is_repeatable(void) {
    char *argv[] = {"pqscan", "--ignore", "a", "-i", "b", "--ignore=c", "src", NULL};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_OK, cli_options_parse(ARG_COUNT(argv), argv, &options));
    TEST_ASSERT_EQUAL_size_t(4, string_list_count(options.ignores));
    TEST_ASSERT_EQUAL_STRING("c", string_list_get(options.ignores, 3));
    TEST_ASSERT_EQUAL_size_t(1, options.path_count);
}

static void test_options_may_follow_paths(void) {
    char *argv[] = {"pqscan", "src", "--ignore", "a", NULL};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_OK, cli_options_parse(ARG_COUNT(argv), argv, &options));
    TEST_ASSERT_EQUAL_size_t(1, options.path_count);
    TEST_ASSERT_EQUAL_STRING("src", options.paths[0]);
    TEST_ASSERT_EQUAL_size_t(2, string_list_count(options.ignores));
}

static void test_double_dash_ends_options(void) {
    char *argv[] = {"pqscan", "--", "--help", NULL};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_OK, cli_options_parse(ARG_COUNT(argv), argv, &options));
    TEST_ASSERT_FALSE(options.show_help);
    TEST_ASSERT_EQUAL_STRING("--help", options.paths[0]);
}

static void test_unknown_option_is_a_usage_error(void) {
    char *argv[] = {"pqscan", "--nope", "src", NULL};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_USAGE_ERROR,
                          cli_options_parse(ARG_COUNT(argv), argv, &options));
}

static void test_ignore_without_a_pattern_is_a_usage_error(void) {
    char *argv[] = {"pqscan", "--ignore", NULL};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_USAGE_ERROR,
                          cli_options_parse(ARG_COUNT(argv), argv, &options));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_only_the_program_name_gives_no_paths);
    RUN_TEST(test_parses_paths);
    RUN_TEST(test_git_directory_is_ignored_by_default);
    RUN_TEST(test_the_time_budget_has_a_default);
    RUN_TEST(test_parses_the_time_budget);
    RUN_TEST(test_refuses_a_bad_time_budget);
    RUN_TEST(test_parses_help_and_version_flags);
    RUN_TEST(test_rules_path_is_absent_by_default);
    RUN_TEST(test_parses_the_rules_path);
    RUN_TEST(test_the_last_rules_path_wins);
    RUN_TEST(test_rules_without_a_path_is_a_usage_error);
    RUN_TEST(test_ignore_is_repeatable);
    RUN_TEST(test_options_may_follow_paths);
    RUN_TEST(test_double_dash_ends_options);
    RUN_TEST(test_unknown_option_is_a_usage_error);
    RUN_TEST(test_ignore_without_a_pattern_is_a_usage_error);
    return UNITY_END();
}
