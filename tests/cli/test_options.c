/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/cli/options.h"
#include "pqscan/core/string_list.h"
#include "pqscan/risk/priority.h"
#include "pqscan/risk/risk.h"
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

static void test_the_report_defaults_to_text_failing_on_review(void) {
    char *argv[] = {"pqscan", "src", NULL};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_OK, cli_options_parse(ARG_COUNT(argv), argv, &options));
    TEST_ASSERT_EQUAL_STRING("text", options.format->name);
    TEST_ASSERT_EQUAL_INT(RISK_REVIEW, options.fail_on);
}

static void test_parses_the_format(void) {
    char *argv[] = {"pqscan", "-f", "text", "src", NULL};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_OK, cli_options_parse(ARG_COUNT(argv), argv, &options));
    TEST_ASSERT_EQUAL_STRING("text", options.format->name);
}

static void test_refuses_an_unknown_format(void) {
    char *argv[] = {"pqscan", "--format", "xml", "src", NULL};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_USAGE_ERROR,
                          cli_options_parse(ARG_COUNT(argv), argv, &options));
}

static void test_parses_the_threshold(void) {
    char *argv[] = {"pqscan", "--fail-on", "QUANTUM_VULNERABLE", "src", NULL};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_OK, cli_options_parse(ARG_COUNT(argv), argv, &options));
    TEST_ASSERT_EQUAL_INT(RISK_QUANTUM_VULNERABLE, options.fail_on);
}

static void test_refuses_an_unknown_threshold(void) {
    char *argv[] = {"pqscan", "--fail-on", "review", "src", NULL};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_USAGE_ERROR,
                          cli_options_parse(ARG_COUNT(argv), argv, &options));
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

static void test_the_project_and_year_are_absent_by_default(void) {
    char *argv[] = {"pqscan", "src", NULL};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_OK, cli_options_parse(ARG_COUNT(argv), argv, &options));
    TEST_ASSERT_NULL(options.project_path);
    TEST_ASSERT_EQUAL_INT(CLI_AS_OF_NOW, options.as_of_year);
}

static void test_parses_the_project_and_year(void) {
    char *argv[] = {"pqscan", "--project", "p.json", "--as-of=2031", "src", NULL};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_OK, cli_options_parse(ARG_COUNT(argv), argv, &options));
    TEST_ASSERT_EQUAL_STRING("p.json", options.project_path);
    TEST_ASSERT_EQUAL_INT(IR8547_DEPRECATED_AFTER + 1, options.as_of_year);
}

static void test_accepts_the_ends_of_the_year_range(void) {
    char *first[] = {"pqscan", "--as-of", "1970", "src", NULL};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_OK, cli_options_parse(ARG_COUNT(first), first, &options));
    TEST_ASSERT_EQUAL_INT(PRIORITY_MIN_YEAR, options.as_of_year);
    cli_options_destroy(&options);
    char *last[] = {"pqscan", "--as-of", "9999", "src", NULL};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_OK, cli_options_parse(ARG_COUNT(last), last, &options));
    TEST_ASSERT_EQUAL_INT(PRIORITY_MAX_YEAR, options.as_of_year);
}

static void assert_bad_year(char *value) {
    char *argv[] = {"pqscan", "--as-of", value, "src", NULL};
    TEST_ASSERT_EQUAL_INT_MESSAGE(CLI_PARSE_USAGE_ERROR,
                                  cli_options_parse(ARG_COUNT(argv), argv, &options), value);
    cli_options_destroy(&options);
}

static void test_refuses_a_bad_year(void) {
    assert_bad_year("soon");
    assert_bad_year("");
    assert_bad_year("1969");
    assert_bad_year("10000");
    assert_bad_year("-2030");
    assert_bad_year(" 2030");
    assert_bad_year("2030 ");
    assert_bad_year("99999999999999999999999");
}

static void test_baselines_are_absent_by_default(void) {
    char *argv[] = {"pqscan", "src", NULL};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_OK, cli_options_parse(ARG_COUNT(argv), argv, &options));
    TEST_ASSERT_NULL(options.diff_path);
    TEST_ASSERT_NULL(options.baseline_out);
}

static void test_parses_the_baseline_to_diff_against(void) {
    char *argv[] = {"pqscan", "--diff", "base.json", "src", NULL};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_OK, cli_options_parse(ARG_COUNT(argv), argv, &options));
    TEST_ASSERT_EQUAL_STRING("base.json", options.diff_path);
    TEST_ASSERT_NULL(options.baseline_out);
}

static void test_parses_the_baseline_to_write(void) {
    char *argv[] = {"pqscan", "src", "--write-baseline", "base.json", NULL};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_OK, cli_options_parse(ARG_COUNT(argv), argv, &options));
    TEST_ASSERT_EQUAL_STRING("base.json", options.baseline_out);
    TEST_ASSERT_NULL(options.diff_path);
    TEST_ASSERT_EQUAL_size_t(1, options.path_count);
}

static void test_a_run_cannot_both_use_and_write_a_baseline(void) {
    char *argv[] = {"pqscan", "--diff", "a.json", "--write-baseline", "b.json", "src", NULL};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_USAGE_ERROR,
                          cli_options_parse(ARG_COUNT(argv), argv, &options));
}

static void test_baselines_without_a_file_are_a_usage_error(void) {
    char *diff[] = {"pqscan", "src", "--diff", NULL};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_USAGE_ERROR,
                          cli_options_parse(ARG_COUNT(diff), diff, &options));
    cli_options_destroy(&options);
    char *write[] = {"pqscan", "src", "--write-baseline", NULL};
    TEST_ASSERT_EQUAL_INT(CLI_PARSE_USAGE_ERROR,
                          cli_options_parse(ARG_COUNT(write), write, &options));
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
    RUN_TEST(test_the_project_and_year_are_absent_by_default);
    RUN_TEST(test_parses_the_project_and_year);
    RUN_TEST(test_accepts_the_ends_of_the_year_range);
    RUN_TEST(test_refuses_a_bad_year);
    RUN_TEST(test_baselines_are_absent_by_default);
    RUN_TEST(test_parses_the_baseline_to_diff_against);
    RUN_TEST(test_parses_the_baseline_to_write);
    RUN_TEST(test_a_run_cannot_both_use_and_write_a_baseline);
    RUN_TEST(test_baselines_without_a_file_are_a_usage_error);
    RUN_TEST(test_the_report_defaults_to_text_failing_on_review);
    RUN_TEST(test_parses_the_format);
    RUN_TEST(test_refuses_an_unknown_format);
    RUN_TEST(test_parses_the_threshold);
    RUN_TEST(test_refuses_an_unknown_threshold);
    RUN_TEST(test_options_may_follow_paths);
    RUN_TEST(test_double_dash_ends_options);
    RUN_TEST(test_unknown_option_is_a_usage_error);
    RUN_TEST(test_ignore_without_a_pattern_is_a_usage_error);
    return UNITY_END();
}
