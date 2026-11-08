/* SPDX-License-Identifier: Apache-2.0 */
#include "cJSON.h"
#include "pqscan/core/finding.h"
#include "pqscan/core/key_size.h"
#include "pqscan/core/primitive.h"
#include "pqscan/core/skip_list.h"
#include "pqscan/core/status.h"
#include "pqscan/core/utc_time.h"
#include "pqscan/core/version.h"
#include "pqscan/report/json_report.h"
#include "pqscan/report/reporter.h"
#include "pqscan/risk/priority.h"
#include "pqscan/risk/risk.h"
#include "unity.h"

#include <stdio.h>

enum { OUTPUT_SIZE = 4096, SAMPLE_LINE = 12, SAMPLE_BITS = 2048, SAMPLE_YEAR = 2031 };

/* A payments component scored in 2026: 50 + 10 for a migration ending in 2033, + 29. */
enum {
    AS_OF = 2026,
    QUANTUM_YEAR = 2035,
    LONG_SECRET = 25,
    MIGRATION = 7,
    PAYMENTS_SCORE = 89,
    LATE_AS_OF = 2040,
};

static const key_size NO_KEY_SIZE = {KEY_SIZE_NOT_APPLICABLE, 0};

static finding_list *findings;
static skip_list *skipped;
static cJSON *document;

void setUp(void) {
    findings = finding_list_create();
    TEST_ASSERT_NOT_NULL(findings);
    skipped = skip_list_create();
    TEST_ASSERT_NOT_NULL(skipped);
    document = NULL;
}

void tearDown(void) {
    cJSON_Delete(document);
    skip_list_destroy(skipped);
    finding_list_destroy(findings);
}

static void add_finding(const char *path, key_size size, risk_level risk) {
    const finding item = {
        path,       SAMPLE_LINE,     "RSA",           risk, size, PRIMITIVE_SIGNATURE,
        "RSA_sign", utc_time_none(), priority_none(),
    };
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, finding_list_add(findings, &item));
}

static void write_and_parse(void) {
    FILE *out = tmpfile();
    TEST_ASSERT_NOT_NULL(out);
    const scan_report report = {findings, skipped};
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, json_reporter.write(&report, out));
    const int seek_result = fseek(out, 0, SEEK_SET);
    TEST_ASSERT_EQUAL_INT(0, seek_result);
    static char output[OUTPUT_SIZE];
    const size_t len = fread(output, 1, sizeof(output) - 1, out);
    output[len] = '\0';
    const int closed = fclose(out);
    TEST_ASSERT_EQUAL_INT(0, closed);
    document = cJSON_Parse(output);
    TEST_ASSERT_NOT_NULL_MESSAGE(document, output);
}

static const cJSON *field(const cJSON *object, const char *name) {
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(object, name);
    TEST_ASSERT_NOT_NULL_MESSAGE(item, name);
    return item;
}

static const cJSON *first_finding(void) {
    return cJSON_GetArrayItem(field(document, "findings"), 0);
}

static void test_an_empty_report_is_complete(void) {
    write_and_parse();
    TEST_ASSERT_EQUAL_INT(2, field(document, "schema_version")->valueint);
    TEST_ASSERT_TRUE(cJSON_IsTrue(field(document, "complete")));
    TEST_ASSERT_EQUAL_INT(0, cJSON_GetArraySize(field(document, "findings")));
    TEST_ASSERT_EQUAL_INT(0, cJSON_GetArraySize(field(document, "unanalyzed")));
    TEST_ASSERT_EQUAL_INT(0, field(field(document, "summary"), "total")->valueint);
}

static void test_names_the_tool(void) {
    write_and_parse();
    const cJSON *tool = field(document, "tool");
    TEST_ASSERT_EQUAL_STRING("pqscan", field(tool, "name")->valuestring);
    TEST_ASSERT_EQUAL_STRING(pqscan_version(), field(tool, "version")->valuestring);
}

static void test_a_finding_has_every_field(void) {
    add_finding("src/a.c", (key_size){KEY_SIZE_KNOWN, SAMPLE_BITS}, RISK_QUANTUM_VULNERABLE);
    write_and_parse();
    const cJSON *item = first_finding();
    TEST_ASSERT_EQUAL_STRING("src/a.c", field(item, "path")->valuestring);
    TEST_ASSERT_EQUAL_INT(SAMPLE_LINE, field(item, "line")->valueint);
    TEST_ASSERT_EQUAL_STRING("RSA_sign", field(item, "symbol")->valuestring);
    TEST_ASSERT_EQUAL_STRING("RSA", field(item, "algorithm")->valuestring);
    TEST_ASSERT_EQUAL_INT(SAMPLE_BITS, field(item, "key_size")->valueint);
    TEST_ASSERT_EQUAL_STRING("signature", field(item, "primitive")->valuestring);
    TEST_ASSERT_EQUAL_STRING("QUANTUM_VULNERABLE", field(item, "risk")->valuestring);
    TEST_ASSERT_TRUE(cJSON_IsNull(field(item, "expires")));
}

static void test_a_certificate_finding_has_no_line_and_an_expiry(void) {
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
    write_and_parse();
    TEST_ASSERT_TRUE(cJSON_IsNull(field(first_finding(), "line")));
    TEST_ASSERT_EQUAL_STRING("2031-05-01T12:00:00Z",
                             field(first_finding(), "expires")->valuestring);
}

static void test_an_unresolved_key_size_says_unknown(void) {
    add_finding("a.c", (key_size){KEY_SIZE_UNKNOWN, 0}, RISK_QUANTUM_VULNERABLE);
    write_and_parse();
    TEST_ASSERT_EQUAL_STRING("unknown", field(first_finding(), "key_size")->valuestring);
}

static void test_no_key_size_is_null(void) {
    add_finding("a.c", NO_KEY_SIZE, RISK_CLASSICALLY_WEAK);
    write_and_parse();
    TEST_ASSERT_TRUE(cJSON_IsNull(field(first_finding(), "key_size")));
}

static void test_the_summary_counts_by_risk(void) {
    add_finding("a.c", NO_KEY_SIZE, RISK_REVIEW);
    add_finding("b.c", NO_KEY_SIZE, RISK_REVIEW);
    add_finding("c.c", NO_KEY_SIZE, RISK_CLASSICALLY_WEAK);
    write_and_parse();
    const cJSON *summary = field(document, "summary");
    const cJSON *by_risk = field(summary, "by_risk");
    TEST_ASSERT_EQUAL_INT(3, field(summary, "total")->valueint);
    TEST_ASSERT_EQUAL_INT(0, field(by_risk, "OK")->valueint);
    TEST_ASSERT_EQUAL_INT(2, field(by_risk, "REVIEW")->valueint);
    TEST_ASSERT_EQUAL_INT(0, field(by_risk, "QUANTUM_VULNERABLE")->valueint);
    TEST_ASSERT_EQUAL_INT(1, field(by_risk, "CLASSICALLY_WEAK")->valueint);
}

static void test_says_what_was_not_analyzed(void) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, skip_list_add(skipped, "b.c", PQSCAN_ERR_BINARY));
    write_and_parse();
    TEST_ASSERT_TRUE(cJSON_IsFalse(field(document, "complete")));
    const cJSON *entry = cJSON_GetArrayItem(field(document, "unanalyzed"), 0);
    TEST_ASSERT_EQUAL_STRING("b.c", field(entry, "path")->valuestring);
    TEST_ASSERT_EQUAL_STRING(pqscan_status_message(PQSCAN_ERR_BINARY),
                             field(entry, "reason")->valuestring);
}

static void test_a_hostile_file_name_stays_inside_its_string(void) {
    add_finding("evil\",\"risk\":\"OK\n\xff\xc3.c", NO_KEY_SIZE, RISK_REVIEW);
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, skip_list_add(skipped, "\"\\\x1b", PQSCAN_ERR_IO));
    write_and_parse();
    TEST_ASSERT_EQUAL_STRING("evil\",\"risk\":\"OK\\x0a\\xff\\xc3.c",
                             field(first_finding(), "path")->valuestring);
    TEST_ASSERT_EQUAL_STRING("REVIEW", field(first_finding(), "risk")->valuestring);
    const cJSON *entry = cJSON_GetArrayItem(field(document, "unanalyzed"), 0);
    TEST_ASSERT_EQUAL_STRING("\"\\\\\\x1b", field(entry, "path")->valuestring);
}

static void add_scored(risk_level risk, int as_of_year) {
    const data_lifetime lifetime = {"payments", LONG_SECRET, MIGRATION};
    const priority_basis basis = {as_of_year, QUANTUM_YEAR};
    const finding item = {
        "pay.c",    SAMPLE_LINE,     "RSA",
        risk,       NO_KEY_SIZE,     PRIMITIVE_SIGNATURE,
        "RSA_sign", utc_time_none(), priority_assess(risk, &lifetime, &basis),
    };
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, finding_list_add(findings, &item));
}

static void test_a_quantum_vulnerable_finding_explains_its_priority(void) {
    add_scored(RISK_QUANTUM_VULNERABLE, AS_OF);
    write_and_parse();
    const cJSON *rank = field(first_finding(), "priority");
    TEST_ASSERT_EQUAL_INT(PAYMENTS_SCORE, field(rank, "score")->valueint);
    TEST_ASSERT_EQUAL_STRING("payments", field(rank, "component")->valuestring);
    const cJSON *timeline = field(rank, "quantum_timeline");
    TEST_ASSERT_EQUAL_INT(LONG_SECRET, field(timeline, "secrecy_years")->valueint);
    TEST_ASSERT_EQUAL_INT(MIGRATION, field(timeline, "migration_years")->valueint);
    TEST_ASSERT_EQUAL_INT(QUANTUM_YEAR - AS_OF, field(timeline, "years_to_quantum")->valueint);
    TEST_ASSERT_TRUE(cJSON_IsTrue(field(timeline, "exposed")));
    TEST_ASSERT_EQUAL_INT(AS_OF + MIGRATION, field(timeline, "migration_ends")->valueint);
    TEST_ASSERT_EQUAL_STRING("deprecated", field(timeline, "ir8547")->valuestring);
}

static void test_years_to_quantum_go_negative_once_it_has_passed(void) {
    add_scored(RISK_QUANTUM_VULNERABLE, LATE_AS_OF);
    write_and_parse();
    const cJSON *timeline = field(field(first_finding(), "priority"), "quantum_timeline");
    TEST_ASSERT_EQUAL_INT(QUANTUM_YEAR - LATE_AS_OF, field(timeline, "years_to_quantum")->valueint);
    TEST_ASSERT_EQUAL_STRING("disallowed", field(timeline, "ir8547")->valuestring);
}

static void test_other_levels_have_no_quantum_timeline(void) {
    add_scored(RISK_CLASSICALLY_WEAK, AS_OF);
    write_and_parse();
    const cJSON *rank = field(first_finding(), "priority");
    TEST_ASSERT_EQUAL_INT(PRIORITY_MAX_SCORE, field(rank, "score")->valueint);
    TEST_ASSERT_TRUE(cJSON_IsNull(field(rank, "quantum_timeline")));
}

static void test_a_finding_no_component_claims_has_a_null_component(void) {
    add_finding("a.c", NO_KEY_SIZE, RISK_OK);
    write_and_parse();
    TEST_ASSERT_TRUE(cJSON_IsNull(field(field(first_finding(), "priority"), "component")));
}

static void test_reports_a_failed_write(void) {
    FILE *read_only = fopen("/dev/null", "r");
    TEST_ASSERT_NOT_NULL(read_only);
    const scan_report report = {findings, skipped};
    const pqscan_status status = json_reporter.write(&report, read_only);
    const int closed = fclose(read_only);
    TEST_ASSERT_EQUAL_INT(0, closed);
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_IO, status);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_an_empty_report_is_complete);
    RUN_TEST(test_names_the_tool);
    RUN_TEST(test_a_finding_has_every_field);
    RUN_TEST(test_a_certificate_finding_has_no_line_and_an_expiry);
    RUN_TEST(test_an_unresolved_key_size_says_unknown);
    RUN_TEST(test_no_key_size_is_null);
    RUN_TEST(test_the_summary_counts_by_risk);
    RUN_TEST(test_says_what_was_not_analyzed);
    RUN_TEST(test_a_hostile_file_name_stays_inside_its_string);
    RUN_TEST(test_a_quantum_vulnerable_finding_explains_its_priority);
    RUN_TEST(test_years_to_quantum_go_negative_once_it_has_passed);
    RUN_TEST(test_other_levels_have_no_quantum_timeline);
    RUN_TEST(test_a_finding_no_component_claims_has_a_null_component);
    RUN_TEST(test_reports_a_failed_write);
    return UNITY_END();
}
