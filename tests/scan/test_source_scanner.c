/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/finding.h"
#include "pqscan/core/status.h"
#include "pqscan/risk/risk.h"
#include "pqscan/scan/file_reader.h"
#include "pqscan/scan/source_scanner.h"
#include "unity.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

enum { HUGE_LINE_SIZE = 1024 * 1024, EXPECTED_LINE = 4 };

static finding_list *findings;

void setUp(void) {
    findings = finding_list_create();
    TEST_ASSERT_NOT_NULL(findings);
}

void tearDown(void) { finding_list_destroy(findings); }

static pqscan_status scan_bytes(char *data, size_t len) {
    const file_contents file = {data, len};
    return source_scanner.scan("a.c", &file, findings);
}

static void scan_text(char *text) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, scan_bytes(text, strlen(text)));
}

static void assert_finding_count(size_t expected) {
    TEST_ASSERT_EQUAL_size_t(expected, finding_list_count(findings));
}

static void test_accepts_only_source_files(void) {
    TEST_ASSERT_TRUE(source_scanner.accepts("a.c"));
    TEST_ASSERT_FALSE(source_scanner.accepts("a.txt"));
}

static void test_empty_file_has_no_findings(void) {
    scan_text("");
    assert_finding_count(0);
}

static void test_reports_path_line_algorithm_and_risk(void) {
    scan_text("\n\n\nRSA *r = RSA_new();\n");
    assert_finding_count(1);
    const finding *item = finding_list_get(findings, 0);
    TEST_ASSERT_EQUAL_STRING("a.c", item->path);
    TEST_ASSERT_EQUAL_size_t(EXPECTED_LINE, item->line);
    TEST_ASSERT_EQUAL_STRING("RSA", item->algorithm);
    TEST_ASSERT_EQUAL_INT(RISK_QUANTUM_VULNERABLE, item->risk);
}

static void test_counts_lines_with_crlf_endings(void) {
    scan_text("\r\n\r\n\r\nDH_new();\r\n");
    TEST_ASSERT_EQUAL_size_t(EXPECTED_LINE, finding_list_get(findings, 0)->line);
}

static void test_reports_each_match_on_a_line(void) {
    scan_text("EVP_md5(); EVP_sha1();\n");
    assert_finding_count(2);
    TEST_ASSERT_EQUAL_STRING("MD5", finding_list_get(findings, 0)->algorithm);
    TEST_ASSERT_EQUAL_STRING("SHA-1", finding_list_get(findings, 1)->algorithm);
}

static void test_matches_at_the_edges_of_the_file(void) {
    scan_text("RSA_new");
    assert_finding_count(1);
}

static void test_skips_longer_identifiers(void) {
    scan_text("MY_RSA_new RSA_new_x xRSA_new _RSA_new RSA_new1\n");
    assert_finding_count(0);
}

static void test_skips_tokens_starting_with_a_digit(void) {
    scan_text("1RSA_new\n");
    assert_finding_count(0);
}

static void test_non_utf8_bytes_separate_identifiers(void) {
    scan_text("\xE9RSA_new\xFF\n");
    assert_finding_count(1);
}

static void test_naive_scan_also_reports_comments_and_strings(void) {
    scan_text("/* RSA_new */ const char *s = \"DSA_new\";\n");
    assert_finding_count(2);
}

static void test_skips_files_containing_nul_bytes(void) {
    char data[] = {'R', 'S', 'A', '_', 'n', 'e', 'w', '\0', ' '};
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_BINARY, scan_bytes(data, sizeof(data)));
    assert_finding_count(0);
}

static void test_finds_a_match_after_a_huge_line(void) {
    static const char suffix[] = "\nRSA_new";
    const size_t len = HUGE_LINE_SIZE + strlen(suffix);
    char *data = malloc(len + 1);
    TEST_ASSERT_NOT_NULL(data);
    memset(data, 'x', HUGE_LINE_SIZE);
    memcpy(data + HUGE_LINE_SIZE, suffix, sizeof(suffix));

    const pqscan_status status = scan_bytes(data, len);
    free(data);
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, status);
    assert_finding_count(1);
    TEST_ASSERT_EQUAL_size_t(2, finding_list_get(findings, 0)->line);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_accepts_only_source_files);
    RUN_TEST(test_empty_file_has_no_findings);
    RUN_TEST(test_reports_path_line_algorithm_and_risk);
    RUN_TEST(test_counts_lines_with_crlf_endings);
    RUN_TEST(test_reports_each_match_on_a_line);
    RUN_TEST(test_matches_at_the_edges_of_the_file);
    RUN_TEST(test_skips_longer_identifiers);
    RUN_TEST(test_skips_tokens_starting_with_a_digit);
    RUN_TEST(test_non_utf8_bytes_separate_identifiers);
    RUN_TEST(test_naive_scan_also_reports_comments_and_strings);
    RUN_TEST(test_skips_files_containing_nul_bytes);
    RUN_TEST(test_finds_a_match_after_a_huge_line);
    return UNITY_END();
}
