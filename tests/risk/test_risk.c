/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/risk/risk.h"
#include "unity.h"

void setUp(void) {}

void tearDown(void) {}

static void test_names_match_the_report_format(void) {
    TEST_ASSERT_EQUAL_STRING("OK", risk_level_name(RISK_OK));
    TEST_ASSERT_EQUAL_STRING("REVIEW", risk_level_name(RISK_REVIEW));
    TEST_ASSERT_EQUAL_STRING("QUANTUM_VULNERABLE", risk_level_name(RISK_QUANTUM_VULNERABLE));
    TEST_ASSERT_EQUAL_STRING("CLASSICALLY_WEAK", risk_level_name(RISK_CLASSICALLY_WEAK));
}

static void test_values_are_ordered_by_severity(void) {
    TEST_ASSERT_LESS_THAN_INT(RISK_REVIEW, RISK_OK);
    TEST_ASSERT_LESS_THAN_INT(RISK_QUANTUM_VULNERABLE, RISK_REVIEW);
    TEST_ASSERT_LESS_THAN_INT(RISK_CLASSICALLY_WEAK, RISK_QUANTUM_VULNERABLE);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_names_match_the_report_format);
    RUN_TEST(test_values_are_ordered_by_severity);
    return UNITY_END();
}
