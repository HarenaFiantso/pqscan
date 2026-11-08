/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/risk/priority.h"
#include "pqscan/risk/risk.h"
#include "unity.h"

#include <stddef.h>

enum {
    THIS_YEAR = 2026,
    QUANTUM_YEAR = 2035,
    YEARS_TO_QUANTUM = QUANTUM_YEAR - THIS_YEAR,
    LONG_SECRET = 25,
    MIGRATION = 5,
};

static const priority_basis BASIS = {THIS_YEAR, QUANTUM_YEAR};
static const data_lifetime NOTHING_DECLARED = {NULL, 0, 0};

void setUp(void) {}

void tearDown(void) {}

static unsigned score_of(risk_level risk, const data_lifetime *lifetime) {
    return priority_assess(risk, lifetime, &BASIS).score;
}

static unsigned quantum_score(int secrecy, int migration, int as_of_year) {
    const data_lifetime lifetime = {NULL, secrecy, migration};
    const priority_basis basis = {as_of_year, QUANTUM_YEAR};
    return priority_assess(RISK_QUANTUM_VULNERABLE, &lifetime, &basis).score;
}

static void test_a_new_finding_has_no_priority(void) {
    const priority none = priority_none();
    TEST_ASSERT_EQUAL_UINT(0, none.score);
    TEST_ASSERT_NULL(none.component);
    TEST_ASSERT_FALSE(none.timeline.applies);
}

static void test_levels_outside_the_quantum_timeline_have_fixed_scores(void) {
    const data_lifetime secret = {"vault", LONG_SECRET, MIGRATION};
    TEST_ASSERT_EQUAL_UINT(0, score_of(RISK_OK, &secret));
    TEST_ASSERT_EQUAL_UINT(10, score_of(RISK_REVIEW, &secret));
    TEST_ASSERT_EQUAL_UINT(PRIORITY_MAX_SCORE, score_of(RISK_CLASSICALLY_WEAK, &secret));
    TEST_ASSERT_FALSE(priority_assess(RISK_CLASSICALLY_WEAK, &secret, &BASIS).timeline.applies);
}

static void test_keeps_the_component_whatever_the_level(void) {
    const data_lifetime lifetime = {"payments", LONG_SECRET, MIGRATION};
    TEST_ASSERT_EQUAL_STRING("payments", priority_assess(RISK_OK, &lifetime, &BASIS).component);
    TEST_ASSERT_EQUAL_STRING("payments",
                             priority_assess(RISK_QUANTUM_VULNERABLE, &lifetime, &BASIS).component);
}

static void test_records_why_a_quantum_vulnerable_finding_scores_what_it_does(void) {
    const data_lifetime lifetime = {NULL, LONG_SECRET, MIGRATION};
    const quantum_timeline timeline =
        priority_assess(RISK_QUANTUM_VULNERABLE, &lifetime, &BASIS).timeline;
    TEST_ASSERT_TRUE(timeline.applies);
    TEST_ASSERT_EQUAL_INT(LONG_SECRET, timeline.secrecy_years);
    TEST_ASSERT_EQUAL_INT(MIGRATION, timeline.migration_years);
    TEST_ASSERT_EQUAL_INT(YEARS_TO_QUANTUM, timeline.years_to_quantum);
    TEST_ASSERT_EQUAL_INT(THIS_YEAR + MIGRATION, timeline.migration_end_year);
    TEST_ASSERT_EQUAL_INT(IR8547_DEPRECATED, timeline.status);
}

/* 50, nothing from IR 8547 in 2026, and 10 + 0 + 0 - 9 = 1. */
static void test_nothing_declared_scores_from_the_dates_alone(void) {
    TEST_ASSERT_EQUAL_UINT(51, score_of(RISK_QUANTUM_VULNERABLE, &NOTHING_DECLARED));
}

static void test_the_ir8547_status_is_taken_when_the_migration_ends(void) {
    TEST_ASSERT_EQUAL_INT(
        IR8547_ACCEPTABLE,
        priority_assess(RISK_QUANTUM_VULNERABLE, &NOTHING_DECLARED, &BASIS).timeline.status);
    const priority_basis in_2030 = {IR8547_DEPRECATED_AFTER, QUANTUM_YEAR};
    const data_lifetime one_year = {NULL, 0, 1};
    TEST_ASSERT_EQUAL_INT(
        IR8547_DEPRECATED,
        priority_assess(RISK_QUANTUM_VULNERABLE, &one_year, &in_2030).timeline.status);
    const priority_basis in_2035 = {IR8547_DISALLOWED_AFTER, QUANTUM_YEAR};
    TEST_ASSERT_EQUAL_INT(
        IR8547_DEPRECATED,
        priority_assess(RISK_QUANTUM_VULNERABLE, &NOTHING_DECLARED, &in_2035).timeline.status);
    TEST_ASSERT_EQUAL_INT(
        IR8547_DISALLOWED,
        priority_assess(RISK_QUANTUM_VULNERABLE, &one_year, &in_2035).timeline.status);
}

static void test_a_deadline_adds_ten_or_twenty_points(void) {
    TEST_ASSERT_EQUAL_UINT(50 + 0 + 3, quantum_score(0, 0, IR8547_DEPRECATED_AFTER - 2));
    TEST_ASSERT_EQUAL_UINT(50 + 10 + 6, quantum_score(0, 0, IR8547_DEPRECATED_AFTER + 1));
    TEST_ASSERT_EQUAL_UINT(50 + 20 + 11, quantum_score(0, 0, IR8547_DISALLOWED_AFTER + 1));
}

static void test_mosca_counts_every_year_of_exposure(void) {
    const data_lifetime on_the_edge = {NULL, YEARS_TO_QUANTUM - MIGRATION, MIGRATION};
    const data_lifetime one_year_over = {NULL, YEARS_TO_QUANTUM - MIGRATION + 1, MIGRATION};
    const priority edge = priority_assess(RISK_QUANTUM_VULNERABLE, &on_the_edge, &BASIS);
    const priority over = priority_assess(RISK_QUANTUM_VULNERABLE, &one_year_over, &BASIS);
    TEST_ASSERT_FALSE(quantum_timeline_exposed(&edge.timeline));
    TEST_ASSERT_TRUE(quantum_timeline_exposed(&over.timeline));
    TEST_ASSERT_EQUAL_UINT(50 + 10 + 10, edge.score);
    TEST_ASSERT_EQUAL_UINT(edge.score + 1, over.score);
}

static void test_exposure_points_are_capped_at_both_ends(void) {
    TEST_ASSERT_EQUAL_UINT(50, quantum_score(0, 0, PRIORITY_MIN_YEAR));
    TEST_ASSERT_EQUAL_UINT(50 + 10 + 29, quantum_score(LONG_SECRET, MIGRATION, THIS_YEAR));
    TEST_ASSERT_EQUAL_UINT(50 + 20 + 29,
                           quantum_score(PRIORITY_MAX_SPAN_YEARS, PRIORITY_MAX_SPAN_YEARS,
                                         PRIORITY_MAX_YEAR - PRIORITY_MAX_SPAN_YEARS));
}

static void test_a_quantum_vulnerable_finding_never_outranks_a_weak_one(void) {
    const unsigned highest = quantum_score(PRIORITY_MAX_SPAN_YEARS, PRIORITY_MAX_SPAN_YEARS,
                                           PRIORITY_MAX_YEAR - PRIORITY_MAX_SPAN_YEARS);
    TEST_ASSERT_LESS_THAN_UINT(PRIORITY_MAX_SCORE, highest);
}

static void test_a_past_quantum_year_counts_down(void) {
    const data_lifetime lifetime = {NULL, 0, 0};
    const priority_basis late = {QUANTUM_YEAR + 3, QUANTUM_YEAR};
    const priority result = priority_assess(RISK_QUANTUM_VULNERABLE, &lifetime, &late);
    TEST_ASSERT_EQUAL_INT(-3, result.timeline.years_to_quantum);
    TEST_ASSERT_TRUE(quantum_timeline_exposed(&result.timeline));
}

static void test_a_timeline_that_does_not_apply_is_never_exposed(void) {
    const priority none = priority_none();
    TEST_ASSERT_FALSE(quantum_timeline_exposed(&none.timeline));
}

static void test_names_the_ir8547_statuses(void) {
    TEST_ASSERT_EQUAL_STRING("acceptable", ir8547_status_name(IR8547_ACCEPTABLE));
    TEST_ASSERT_EQUAL_STRING("deprecated", ir8547_status_name(IR8547_DEPRECATED));
    TEST_ASSERT_EQUAL_STRING("disallowed", ir8547_status_name(IR8547_DISALLOWED));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_a_new_finding_has_no_priority);
    RUN_TEST(test_levels_outside_the_quantum_timeline_have_fixed_scores);
    RUN_TEST(test_keeps_the_component_whatever_the_level);
    RUN_TEST(test_records_why_a_quantum_vulnerable_finding_scores_what_it_does);
    RUN_TEST(test_nothing_declared_scores_from_the_dates_alone);
    RUN_TEST(test_the_ir8547_status_is_taken_when_the_migration_ends);
    RUN_TEST(test_a_deadline_adds_ten_or_twenty_points);
    RUN_TEST(test_mosca_counts_every_year_of_exposure);
    RUN_TEST(test_exposure_points_are_capped_at_both_ends);
    RUN_TEST(test_a_quantum_vulnerable_finding_never_outranks_a_weak_one);
    RUN_TEST(test_a_past_quantum_year_counts_down);
    RUN_TEST(test_a_timeline_that_does_not_apply_is_never_exposed);
    RUN_TEST(test_names_the_ir8547_statuses);
    return UNITY_END();
}
