/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/finding.h"
#include "pqscan/core/status.h"
#include "pqscan/report/text_report.h"
#include "pqscan/risk/risk.h"
#include "unity.h"

#include <stdio.h>
#include <string.h>

enum { OUTPUT_SIZE = 256, SAMPLE_LINE = 12 };

static finding_list *findings;
static FILE *out;

void setUp(void) {
    findings = finding_list_create();
    TEST_ASSERT_NOT_NULL(findings);
    out = tmpfile();
    TEST_ASSERT_NOT_NULL(out);
}

void tearDown(void) {
    const int closed = fclose(out);
    TEST_ASSERT_EQUAL_INT(0, closed);
    finding_list_destroy(findings);
}

static void read_back(char *buffer, size_t size) {
    const int seek_result = fseek(out, 0, SEEK_SET);
    TEST_ASSERT_EQUAL_INT(0, seek_result);
    const size_t len = fread(buffer, 1, size - 1, out);
    buffer[len] = '\0';
}

static void test_no_findings_write_nothing(void) {
    char output[OUTPUT_SIZE];
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, text_reporter.write(findings, out));
    read_back(output, sizeof(output));
    TEST_ASSERT_EQUAL_STRING("", output);
}

static void test_writes_one_line_per_finding(void) {
    const finding first = {"src/a.c", SAMPLE_LINE, "RSA", RISK_QUANTUM_VULNERABLE};
    const finding second = {"b.h", 1, "MD5", RISK_CLASSICALLY_WEAK};
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, finding_list_add(findings, &first));
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, finding_list_add(findings, &second));

    char output[OUTPUT_SIZE];
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, text_reporter.write(findings, out));
    read_back(output, sizeof(output));
    TEST_ASSERT_EQUAL_STRING("src/a.c:12: RSA (QUANTUM_VULNERABLE)\n"
                             "b.h:1: MD5 (CLASSICALLY_WEAK)\n",
                             output);
}

static void test_reports_a_failed_write(void) {
    const finding item = {"a.c", 1, "RSA", RISK_QUANTUM_VULNERABLE};
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, finding_list_add(findings, &item));

    FILE *read_only = fopen("/dev/null", "r");
    TEST_ASSERT_NOT_NULL(read_only);
    const pqscan_status status = text_reporter.write(findings, read_only);
    const int closed = fclose(read_only);
    TEST_ASSERT_EQUAL_INT(0, closed);
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_IO, status);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_no_findings_write_nothing);
    RUN_TEST(test_writes_one_line_per_finding);
    RUN_TEST(test_reports_a_failed_write);
    return UNITY_END();
}
