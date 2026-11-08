/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/finding.h"
#include "pqscan/core/json_fields.h"
#include "pqscan/core/key_size.h"
#include "pqscan/core/primitive.h"
#include "pqscan/core/status.h"
#include "pqscan/core/utc_time.h"
#include "pqscan/risk/prioritize.h"
#include "pqscan/risk/priority.h"
#include "pqscan/risk/project_file.h"
#include "pqscan/risk/risk.h"
#include "unity.h"

#include <stddef.h>
#include <string.h>

enum {
    THIS_YEAR = 2026,
    /* 50 + 10 for a migration ending in 2033, + 10 + 25 + 7 - 9 capped at 29. */
    PAYMENTS_SCORE = 89,
    /* 50, nothing from IR 8547 in 2026, and 10 + 0 + 0 - 9. */
    UNCLAIMED_SCORE = 51,
    REVIEW_SCORE = 10,
    SIZE_BITS = 2048,
    LATER_LINE = 9,
};

static const char PROJECT[] =
    "{\"schema_version\": 1, \"components\": [\n"
    "  {\"name\": \"payments\", \"paths\": [\"pay/*\"], \"secrecy_years\": 25,"
    " \"migration_years\": 7}\n"
    "]}";

/* What a finding needs for these tests. The rest is fixed. */
typedef struct sample {
    const char *path;
    size_t line;
    risk_level risk;
} sample;

static finding_list *findings;
static project *target;

void setUp(void) {
    findings = finding_list_create();
    TEST_ASSERT_NOT_NULL(findings);
    json_error error;
    const project_source source = {PROJECT, strlen(PROJECT)};
    TEST_ASSERT_EQUAL_INT_MESSAGE(PQSCAN_OK, project_load(&source, &target, &error), error.message);
}

void tearDown(void) {
    finding_list_destroy(findings);
    project_destroy(target);
}

static void add_finding(const sample *item, const char *algorithm) {
    const finding added = {
        item->path,     item->line, algorithm,       item->risk,      {KEY_SIZE_NOT_APPLICABLE, 0},
        PRIMITIVE_HASH, algorithm,  utc_time_none(), priority_none(),
    };
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, finding_list_add(findings, &added));
}

static void add_sample(const char *path, size_t line, risk_level risk) {
    const sample item = {path, line, risk};
    add_finding(&item, "RSA");
}

static const finding *nth(size_t index) {
    const finding *item = finding_list_get(findings, index);
    TEST_ASSERT_NOT_NULL(item);
    return item;
}

static void assert_place(size_t index, const char *path, size_t line) {
    TEST_ASSERT_EQUAL_STRING(path, nth(index)->path);
    TEST_ASSERT_EQUAL_size_t(line, nth(index)->line);
}

static void test_scores_each_finding_with_its_component(void) {
    add_sample("pay/card.c", 1, RISK_QUANTUM_VULNERABLE);
    add_sample("lib/legacy.c", 1, RISK_QUANTUM_VULNERABLE);
    prioritize_findings(findings, target, THIS_YEAR);
    TEST_ASSERT_EQUAL_UINT(PAYMENTS_SCORE, nth(0)->priority.score);
    TEST_ASSERT_EQUAL_STRING("payments", nth(0)->priority.component);
    TEST_ASSERT_TRUE(quantum_timeline_exposed(&nth(0)->priority.timeline));
    TEST_ASSERT_EQUAL_UINT(UNCLAIMED_SCORE, nth(1)->priority.score);
    TEST_ASSERT_NULL(nth(1)->priority.component);
}

static void test_the_project_quantum_year_counts(void) {
    project *late = NULL;
    json_error error;
    static const char LATE[] = "{\"schema_version\": 1, \"quantum_year\": 2026}";
    const project_source source = {LATE, strlen(LATE)};
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, project_load(&source, &late, &error));
    add_sample("a.c", 1, RISK_QUANTUM_VULNERABLE);
    prioritize_findings(findings, late, THIS_YEAR);
    TEST_ASSERT_EQUAL_INT(0, nth(0)->priority.timeline.years_to_quantum);
    project_destroy(late);
}

static void test_sorts_the_most_urgent_first(void) {
    add_sample("lib/hash.c", 1, RISK_REVIEW);
    add_sample("lib/legacy.c", 1, RISK_QUANTUM_VULNERABLE);
    add_sample("pay/card.c", 1, RISK_QUANTUM_VULNERABLE);
    add_sample("z.c", 1, RISK_CLASSICALLY_WEAK);
    add_sample("a.c", 1, RISK_OK);
    prioritize_findings(findings, target, THIS_YEAR);
    sort_by_priority(findings);
    TEST_ASSERT_EQUAL_UINT(PRIORITY_MAX_SCORE, nth(0)->priority.score);
    TEST_ASSERT_EQUAL_UINT(PAYMENTS_SCORE, nth(1)->priority.score);
    TEST_ASSERT_EQUAL_UINT(UNCLAIMED_SCORE, nth(2)->priority.score);
    TEST_ASSERT_EQUAL_UINT(REVIEW_SCORE, nth(3)->priority.score);
    TEST_ASSERT_EQUAL_UINT(0, nth(4)->priority.score);
}

static void test_equal_scores_go_by_path_then_line(void) {
    add_sample("b.c", 2, RISK_QUANTUM_VULNERABLE);
    add_sample("b.c", 1, RISK_QUANTUM_VULNERABLE);
    add_sample("a.c", LATER_LINE, RISK_QUANTUM_VULNERABLE);
    prioritize_findings(findings, target, THIS_YEAR);
    sort_by_priority(findings);
    assert_place(0, "a.c", LATER_LINE);
    assert_place(1, "b.c", 1);
    assert_place(2, "b.c", 2);
}

static void test_findings_on_one_line_go_by_algorithm(void) {
    const sample place = {"a.c", 1, RISK_QUANTUM_VULNERABLE};
    add_finding(&place, "RSA");
    add_finding(&place, "ECDSA");
    prioritize_findings(findings, target, THIS_YEAR);
    sort_by_priority(findings);
    TEST_ASSERT_EQUAL_STRING("ECDSA", nth(0)->algorithm);
    TEST_ASSERT_EQUAL_STRING("RSA", nth(1)->algorithm);
}

static void test_findings_on_one_line_go_by_key_size(void) {
    const finding unknown = {
        "a.c",
        1,
        "RSA",
        RISK_QUANTUM_VULNERABLE,
        {KEY_SIZE_UNKNOWN, 0},
        PRIMITIVE_SIGNATURE,
        "RSA",
        utc_time_none(),
        priority_none(),
    };
    const finding known = {
        "a.c",
        1,
        "RSA",
        RISK_QUANTUM_VULNERABLE,
        {KEY_SIZE_KNOWN, SIZE_BITS},
        PRIMITIVE_SIGNATURE,
        "RSA",
        utc_time_none(),
        priority_none(),
    };
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, finding_list_add(findings, &known));
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, finding_list_add(findings, &unknown));
    prioritize_findings(findings, target, THIS_YEAR);
    sort_by_priority(findings);
    TEST_ASSERT_EQUAL_INT(KEY_SIZE_UNKNOWN, nth(0)->size.kind);
    TEST_ASSERT_EQUAL_INT(KEY_SIZE_KNOWN, nth(1)->size.kind);
}

static void test_an_empty_list_is_left_alone(void) {
    prioritize_findings(findings, target, THIS_YEAR);
    sort_by_priority(findings);
    TEST_ASSERT_EQUAL_size_t(0, finding_list_count(findings));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_scores_each_finding_with_its_component);
    RUN_TEST(test_the_project_quantum_year_counts);
    RUN_TEST(test_sorts_the_most_urgent_first);
    RUN_TEST(test_equal_scores_go_by_path_then_line);
    RUN_TEST(test_findings_on_one_line_go_by_algorithm);
    RUN_TEST(test_findings_on_one_line_go_by_key_size);
    RUN_TEST(test_an_empty_list_is_left_alone);
    return UNITY_END();
}
