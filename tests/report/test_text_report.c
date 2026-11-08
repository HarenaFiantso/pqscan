/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/finding.h"
#include "pqscan/core/key_size.h"
#include "pqscan/core/primitive.h"
#include "pqscan/core/skip_list.h"
#include "pqscan/core/status.h"
#include "pqscan/core/utc_time.h"
#include "pqscan/report/reporter.h"
#include "pqscan/report/text_report.h"
#include "pqscan/risk/priority.h"
#include "pqscan/risk/risk.h"
#include "unity.h"

#include <stdio.h>
#include <string.h>

enum {
    OUTPUT_SIZE = 256,
    SAMPLE_LINE = 12,
    SAMPLE_BITS = 2048,
    SAMPLE_YEAR = 2031,
    SAMPLE_PRIORITY = 89,
};

static const key_size NO_KEY_SIZE = {KEY_SIZE_NOT_APPLICABLE, 0};

static finding_list *findings;
static skip_list *skipped;
static scan_report report;
static FILE *out;

void setUp(void) {
    findings = finding_list_create();
    TEST_ASSERT_NOT_NULL(findings);
    skipped = skip_list_create();
    TEST_ASSERT_NOT_NULL(skipped);
    report = (scan_report){findings, skipped};
    out = tmpfile();
    TEST_ASSERT_NOT_NULL(out);
}

void tearDown(void) {
    const int closed = fclose(out);
    TEST_ASSERT_EQUAL_INT(0, closed);
    skip_list_destroy(skipped);
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
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, text_reporter.write(&report, out));
    read_back(output, sizeof(output));
    TEST_ASSERT_EQUAL_STRING("", output);
}

static void test_writes_one_line_per_finding(void) {
    const finding first = {
        "src/a.c",       SAMPLE_LINE,           "RSA", RISK_QUANTUM_VULNERABLE,
        NO_KEY_SIZE,     PRIMITIVE_UNSPECIFIED, "X",   utc_time_none(),
        priority_none(),
    };
    const finding second = {
        "b.h",
        1,
        "MD5",
        RISK_CLASSICALLY_WEAK,
        NO_KEY_SIZE,
        PRIMITIVE_UNSPECIFIED,
        "X",
        utc_time_none(),
        priority_none(),
    };
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, finding_list_add(findings, &first));
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, finding_list_add(findings, &second));

    char output[OUTPUT_SIZE];
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, text_reporter.write(&report, out));
    read_back(output, sizeof(output));
    TEST_ASSERT_EQUAL_STRING("src/a.c:12: RSA (QUANTUM_VULNERABLE, priority 0)\n"
                             "b.h:1: MD5 (CLASSICALLY_WEAK, priority 0)\n"
                             "2 findings: 1 CLASSICALLY_WEAK, 1 QUANTUM_VULNERABLE\n",
                             output);
}

static void test_appends_the_key_size_to_the_algorithm(void) {
    const finding known = {
        "a.c",
        1,
        "RSA",
        RISK_QUANTUM_VULNERABLE,
        {KEY_SIZE_KNOWN, SAMPLE_BITS},
        PRIMITIVE_UNSPECIFIED,
        "X",
        utc_time_none(),
        priority_none(),
    };
    const finding unknown = {
        "a.c",
        2,
        "RSA",
        RISK_QUANTUM_VULNERABLE,
        {KEY_SIZE_UNKNOWN, 0},
        PRIMITIVE_UNSPECIFIED,
        "X",
        utc_time_none(),
        priority_none(),
    };
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, finding_list_add(findings, &known));
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, finding_list_add(findings, &unknown));

    char output[OUTPUT_SIZE];
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, text_reporter.write(&report, out));
    read_back(output, sizeof(output));
    TEST_ASSERT_EQUAL_STRING("a.c:1: RSA-2048 (QUANTUM_VULNERABLE, priority 0)\n"
                             "a.c:2: RSA-unknown (QUANTUM_VULNERABLE, priority 0)\n"
                             "2 findings: 2 QUANTUM_VULNERABLE\n",
                             output);
}

static void test_a_certificate_finding_names_the_file_and_its_expiry(void) {
    const finding item = {
        "server.der",
        0,
        "RSA",
        RISK_QUANTUM_VULNERABLE,
        {KEY_SIZE_KNOWN, SAMPLE_BITS},
        PRIMITIVE_SIGNATURE,
        "rsaEncryption",
        {true, SAMPLE_YEAR, 5, 1, 12, 0, 0},
        priority_none(),
    };
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, finding_list_add(findings, &item));

    char output[OUTPUT_SIZE];
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, text_reporter.write(&report, out));
    read_back(output, sizeof(output));
    TEST_ASSERT_EQUAL_STRING(
        "server.der: RSA-2048 (QUANTUM_VULNERABLE, priority 0, expires 2031-05-01)\n"
        "1 finding: 1 QUANTUM_VULNERABLE\n",
        output);
}

static void test_a_file_name_cannot_forge_a_line(void) {
    const finding item = {
        "evil\nfake.c:1: AES-256 (OK)\n\x1b[2K.c",
        7,
        "RSA",
        RISK_QUANTUM_VULNERABLE,
        NO_KEY_SIZE,
        PRIMITIVE_UNSPECIFIED,
        "X",
        utc_time_none(),
        priority_none(),
    };
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, finding_list_add(findings, &item));

    char output[OUTPUT_SIZE];
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, text_reporter.write(&report, out));
    read_back(output, sizeof(output));
    TEST_ASSERT_EQUAL_STRING("evil\\x0afake.c:1: AES-256 (OK)\\x0a\\x1b[2K.c:7: RSA "
                             "(QUANTUM_VULNERABLE, priority 0)\n"
                             "1 finding: 1 QUANTUM_VULNERABLE\n",
                             output);
}

static void test_an_algorithm_name_cannot_forge_a_line(void) {
    const finding item = {
        "a.c",
        1,
        "X\nb.c:1: AES-256",
        RISK_OK,
        NO_KEY_SIZE,
        PRIMITIVE_UNSPECIFIED,
        "x",
        utc_time_none(),
        priority_none(),
    };
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, finding_list_add(findings, &item));

    char output[OUTPUT_SIZE];
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, text_reporter.write(&report, out));
    read_back(output, sizeof(output));
    TEST_ASSERT_EQUAL_STRING("a.c:1: X\\x0ab.c:1: AES-256 (OK, priority 0)\n1 finding: 1 OK\n",
                             output);
}

static void test_the_summary_runs_from_most_to_least_severe(void) {
    const risk_level levels[] = {
        RISK_OK, RISK_REVIEW, RISK_QUANTUM_VULNERABLE, RISK_CLASSICALLY_WEAK, RISK_REVIEW,
    };
    for (size_t i = 0; i < sizeof(levels) / sizeof(levels[0]); i++) {
        const finding item = {
            "a.c",     i + 1,           "X",
            levels[i], NO_KEY_SIZE,     PRIMITIVE_UNSPECIFIED,
            "x",       utc_time_none(), priority_none(),
        };
        TEST_ASSERT_EQUAL_INT(PQSCAN_OK, finding_list_add(findings, &item));
    }

    char output[OUTPUT_SIZE];
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, text_reporter.write(&report, out));
    read_back(output, sizeof(output));
    TEST_ASSERT_NOT_NULL(
        strstr(output, "5 findings: 1 CLASSICALLY_WEAK, 1 QUANTUM_VULNERABLE, 2 REVIEW, 1 OK\n"));
}

static void test_shows_the_priority_of_each_finding(void) {
    priority urgent = priority_none();
    urgent.score = SAMPLE_PRIORITY;
    const finding item = {
        "a.c", SAMPLE_LINE,     "RSA",  RISK_QUANTUM_VULNERABLE, NO_KEY_SIZE, PRIMITIVE_UNSPECIFIED,
        "X",   utc_time_none(), urgent,
    };
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, finding_list_add(findings, &item));

    char output[OUTPUT_SIZE];
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, text_reporter.write(&report, out));
    read_back(output, sizeof(output));
    TEST_ASSERT_EQUAL_STRING("a.c:12: RSA (QUANTUM_VULNERABLE, priority 89)\n"
                             "1 finding: 1 QUANTUM_VULNERABLE\n",
                             output);
}

static void test_reports_a_failed_write(void) {
    const finding item = {
        "a.c",
        1,
        "RSA",
        RISK_QUANTUM_VULNERABLE,
        NO_KEY_SIZE,
        PRIMITIVE_UNSPECIFIED,
        "X",
        utc_time_none(),
        priority_none(),
    };
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, finding_list_add(findings, &item));

    FILE *read_only = fopen("/dev/null", "r");
    TEST_ASSERT_NOT_NULL(read_only);
    const pqscan_status status = text_reporter.write(&report, read_only);
    const int closed = fclose(read_only);
    TEST_ASSERT_EQUAL_INT(0, closed);
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_IO, status);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_no_findings_write_nothing);
    RUN_TEST(test_writes_one_line_per_finding);
    RUN_TEST(test_appends_the_key_size_to_the_algorithm);
    RUN_TEST(test_a_certificate_finding_names_the_file_and_its_expiry);
    RUN_TEST(test_a_file_name_cannot_forge_a_line);
    RUN_TEST(test_an_algorithm_name_cannot_forge_a_line);
    RUN_TEST(test_the_summary_runs_from_most_to_least_severe);
    RUN_TEST(test_shows_the_priority_of_each_finding);
    RUN_TEST(test_reports_a_failed_write);
    return UNITY_END();
}
