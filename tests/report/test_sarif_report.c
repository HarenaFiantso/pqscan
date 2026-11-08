/* SPDX-License-Identifier: Apache-2.0 */
#include "cJSON.h"
#include "pqscan/core/finding.h"
#include "pqscan/core/key_size.h"
#include "pqscan/core/primitive.h"
#include "pqscan/core/skip_list.h"
#include "pqscan/core/status.h"
#include "pqscan/core/utc_time.h"
#include "pqscan/core/version.h"
#include "pqscan/report/reporter.h"
#include "pqscan/report/sarif_report.h"
#include "pqscan/risk/priority.h"
#include "pqscan/risk/risk.h"
#include "unity.h"

#include <stdio.h>

enum {
    OUTPUT_SIZE = 8192,
    SAMPLE_LINE = 12,
    SAMPLE_BITS = 2048,
    SHORT_BITS = 1024,
    SAMPLE_YEAR = 2031,
};

static const key_size NO_KEY_SIZE = {KEY_SIZE_NOT_APPLICABLE, 0};

static const finding CERTIFICATE_KEY = {
    "server.der",
    0,
    "RSA",
    RISK_QUANTUM_VULNERABLE,
    {KEY_SIZE_KNOWN, SAMPLE_BITS},
    PRIMITIVE_SIGNATURE,
    "rsaEncryption",
    {true, SAMPLE_YEAR, 5, 1, 12, 0, 0},
    {0, NULL, {false, 0, 0, 0, 0, IR8547_ACCEPTABLE}},
};

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

static void add_finding(const char *algorithm, key_size size, risk_level risk) {
    const finding item = {
        "./src/a.c",  SAMPLE_LINE,     algorithm,       risk, size, PRIMITIVE_SIGNATURE,
        "the_symbol", utc_time_none(), priority_none(),
    };
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, finding_list_add(findings, &item));
}

static void write_and_parse(void) {
    FILE *out = tmpfile();
    TEST_ASSERT_NOT_NULL(out);
    const scan_report report = {findings, skipped};
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, sarif_reporter.write(&report, out));
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

static const cJSON *run(void) { return cJSON_GetArrayItem(field(document, "runs"), 0); }

static const cJSON *driver(void) { return field(field(run(), "tool"), "driver"); }

static const cJSON *result(int index) { return cJSON_GetArrayItem(field(run(), "results"), index); }

static const cJSON *invocation(void) { return cJSON_GetArrayItem(field(run(), "invocations"), 0); }

static void test_an_empty_log_still_has_a_run(void) {
    write_and_parse();
    TEST_ASSERT_EQUAL_STRING("2.1.0", field(document, "version")->valuestring);
    TEST_ASSERT_EQUAL_INT(1, cJSON_GetArraySize(field(document, "runs")));
    TEST_ASSERT_EQUAL_INT(0, cJSON_GetArraySize(field(run(), "results")));
    TEST_ASSERT_EQUAL_INT(0, cJSON_GetArraySize(field(driver(), "rules")));
    TEST_ASSERT_TRUE(cJSON_IsTrue(field(invocation(), "executionSuccessful")));
}

static void test_names_the_tool(void) {
    write_and_parse();
    TEST_ASSERT_EQUAL_STRING("pqscan", field(driver(), "name")->valuestring);
    TEST_ASSERT_EQUAL_STRING(pqscan_version(), field(driver(), "version")->valuestring);
}

static void test_a_result_points_at_its_rule_and_line(void) {
    add_finding("RSA", (key_size){KEY_SIZE_KNOWN, SAMPLE_BITS}, RISK_QUANTUM_VULNERABLE);
    write_and_parse();
    const cJSON *first = result(0);
    TEST_ASSERT_EQUAL_STRING("pqscan/RSA", field(first, "ruleId")->valuestring);
    TEST_ASSERT_EQUAL_STRING("error", field(first, "level")->valuestring);
    TEST_ASSERT_EQUAL_STRING("the_symbol uses RSA-2048: QUANTUM_VULNERABLE",
                             field(field(first, "message"), "text")->valuestring);

    const cJSON *location = cJSON_GetArrayItem(field(first, "locations"), 0);
    const cJSON *physical = field(location, "physicalLocation");
    TEST_ASSERT_EQUAL_STRING("src/a.c",
                             field(field(physical, "artifactLocation"), "uri")->valuestring);
    TEST_ASSERT_EQUAL_INT(SAMPLE_LINE, field(field(physical, "region"), "startLine")->valueint);
}

static void test_a_certificate_result_has_no_region_and_an_expiry(void) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, finding_list_add(findings, &CERTIFICATE_KEY));
    write_and_parse();
    const cJSON *location = cJSON_GetArrayItem(field(result(0), "locations"), 0);
    const cJSON *physical = field(location, "physicalLocation");
    TEST_ASSERT_NULL(cJSON_GetObjectItemCaseSensitive(physical, "region"));
    TEST_ASSERT_EQUAL_STRING("2031-05-01T12:00:00Z",
                             field(field(result(0), "properties"), "expires")->valuestring);
}

static void test_a_result_without_expiry_has_no_properties(void) {
    add_finding("RSA", NO_KEY_SIZE, RISK_QUANTUM_VULNERABLE);
    write_and_parse();
    TEST_ASSERT_NULL(cJSON_GetObjectItemCaseSensitive(result(0), "properties"));
}

static void test_the_message_tells_an_unresolved_key_size(void) {
    add_finding("RSA", (key_size){KEY_SIZE_UNKNOWN, 0}, RISK_QUANTUM_VULNERABLE);
    write_and_parse();
    TEST_ASSERT_EQUAL_STRING("the_symbol uses RSA-unknown: QUANTUM_VULNERABLE",
                             field(field(result(0), "message"), "text")->valuestring);
}

static void test_levels_follow_the_risk(void) {
    add_finding("A", NO_KEY_SIZE, RISK_OK);
    add_finding("B", NO_KEY_SIZE, RISK_REVIEW);
    add_finding("C", NO_KEY_SIZE, RISK_QUANTUM_VULNERABLE);
    add_finding("D", NO_KEY_SIZE, RISK_CLASSICALLY_WEAK);
    write_and_parse();
    TEST_ASSERT_EQUAL_STRING("note", field(result(0), "level")->valuestring);
    TEST_ASSERT_EQUAL_STRING("warning", field(result(1), "level")->valuestring);
    TEST_ASSERT_EQUAL_STRING("error", field(result(2), "level")->valuestring);
    TEST_ASSERT_EQUAL_STRING("error", field(result(3), "level")->valuestring);
}

static void test_each_algorithm_has_one_sorted_rule(void) {
    add_finding("RSA", NO_KEY_SIZE, RISK_QUANTUM_VULNERABLE);
    add_finding("DH", NO_KEY_SIZE, RISK_QUANTUM_VULNERABLE);
    add_finding("RSA", NO_KEY_SIZE, RISK_QUANTUM_VULNERABLE);
    write_and_parse();
    const cJSON *rules = field(driver(), "rules");
    TEST_ASSERT_EQUAL_INT(2, cJSON_GetArraySize(rules));
    TEST_ASSERT_EQUAL_STRING("pqscan/DH", field(cJSON_GetArrayItem(rules, 0), "id")->valuestring);
    TEST_ASSERT_EQUAL_STRING("pqscan/RSA", field(cJSON_GetArrayItem(rules, 1), "id")->valuestring);
}

static void test_a_rule_shows_its_worst_use(void) {
    add_finding("RSA", (key_size){KEY_SIZE_KNOWN, SAMPLE_BITS}, RISK_QUANTUM_VULNERABLE);
    add_finding("RSA", (key_size){KEY_SIZE_KNOWN, SHORT_BITS}, RISK_CLASSICALLY_WEAK);
    add_finding("RSA", (key_size){KEY_SIZE_KNOWN, SAMPLE_BITS}, RISK_QUANTUM_VULNERABLE);
    write_and_parse();
    const cJSON *rule = cJSON_GetArrayItem(field(driver(), "rules"), 0);
    TEST_ASSERT_EQUAL_STRING("9.0",
                             field(field(rule, "properties"), "security-severity")->valuestring);
}

static void test_results_keep_the_scan_order(void) {
    add_finding("RSA", NO_KEY_SIZE, RISK_QUANTUM_VULNERABLE);
    add_finding("DH", NO_KEY_SIZE, RISK_QUANTUM_VULNERABLE);
    write_and_parse();
    TEST_ASSERT_EQUAL_STRING("pqscan/RSA", field(result(0), "ruleId")->valuestring);
    TEST_ASSERT_EQUAL_STRING("pqscan/DH", field(result(1), "ruleId")->valuestring);
}

static void test_says_what_was_not_analyzed(void) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, skip_list_add(skipped, "b c.c", PQSCAN_ERR_BINARY));
    write_and_parse();
    TEST_ASSERT_TRUE(cJSON_IsFalse(field(invocation(), "executionSuccessful")));
    const cJSON *notification =
        cJSON_GetArrayItem(field(invocation(), "toolExecutionNotifications"), 0);
    TEST_ASSERT_EQUAL_STRING("warning", field(notification, "level")->valuestring);
    TEST_ASSERT_EQUAL_STRING(pqscan_status_message(PQSCAN_ERR_BINARY),
                             field(field(notification, "message"), "text")->valuestring);
    const cJSON *location = cJSON_GetArrayItem(field(notification, "locations"), 0);
    const cJSON *physical = field(location, "physicalLocation");
    TEST_ASSERT_EQUAL_STRING("b%20c.c",
                             field(field(physical, "artifactLocation"), "uri")->valuestring);
    TEST_ASSERT_FALSE(cJSON_HasObjectItem(physical, "region"));
}

static void test_a_hostile_file_name_stays_inside_its_string(void) {
    const finding item = {
        "evil\",\"level\":\"none\n\xff.c",
        1,
        "RSA",
        RISK_CLASSICALLY_WEAK,
        NO_KEY_SIZE,
        PRIMITIVE_SIGNATURE,
        "x",
        utc_time_none(),
        priority_none(),
    };
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, finding_list_add(findings, &item));
    write_and_parse();
    const cJSON *location = cJSON_GetArrayItem(field(result(0), "locations"), 0);
    const cJSON *physical = field(location, "physicalLocation");
    TEST_ASSERT_EQUAL_STRING("evil%22%2C%22level%22%3A%22none%0A%FF.c",
                             field(field(physical, "artifactLocation"), "uri")->valuestring);
    TEST_ASSERT_EQUAL_STRING("error", field(result(0), "level")->valuestring);
}

static void test_reports_a_failed_write(void) {
    FILE *read_only = fopen("/dev/null", "r");
    TEST_ASSERT_NOT_NULL(read_only);
    const scan_report report = {findings, skipped};
    const pqscan_status status = sarif_reporter.write(&report, read_only);
    const int closed = fclose(read_only);
    TEST_ASSERT_EQUAL_INT(0, closed);
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_IO, status);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_an_empty_log_still_has_a_run);
    RUN_TEST(test_names_the_tool);
    RUN_TEST(test_a_result_points_at_its_rule_and_line);
    RUN_TEST(test_a_certificate_result_has_no_region_and_an_expiry);
    RUN_TEST(test_a_result_without_expiry_has_no_properties);
    RUN_TEST(test_the_message_tells_an_unresolved_key_size);
    RUN_TEST(test_levels_follow_the_risk);
    RUN_TEST(test_each_algorithm_has_one_sorted_rule);
    RUN_TEST(test_a_rule_shows_its_worst_use);
    RUN_TEST(test_results_keep_the_scan_order);
    RUN_TEST(test_says_what_was_not_analyzed);
    RUN_TEST(test_a_hostile_file_name_stays_inside_its_string);
    RUN_TEST(test_reports_a_failed_write);
    return UNITY_END();
}
