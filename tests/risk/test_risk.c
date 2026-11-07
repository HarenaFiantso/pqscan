/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/key_size.h"
#include "pqscan/risk/risk.h"
#include "unity.h"

#include <stddef.h>

enum { RSA_MINIMUM_BITS = 2048 };

static const algorithm_policy RSA_POLICY = {"RSA", RISK_QUANTUM_VULNERABLE, RSA_MINIMUM_BITS};
static const algorithm_policy MD5_POLICY = {"MD5", RISK_CLASSICALLY_WEAK, 0};
static const algorithm_policy AES_POLICY = {"AES", RISK_REVIEW, RSA_MINIMUM_BITS};

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

static void test_parses_every_report_name(void) {
    const risk_level levels[] = {
        RISK_OK,
        RISK_REVIEW,
        RISK_QUANTUM_VULNERABLE,
        RISK_CLASSICALLY_WEAK,
    };
    for (size_t i = 0; i < sizeof(levels) / sizeof(levels[0]); i++) {
        risk_level parsed = RISK_OK;
        TEST_ASSERT_TRUE(risk_level_parse(risk_level_name(levels[i]), &parsed));
        TEST_ASSERT_EQUAL_INT(levels[i], parsed);
    }
}

static void test_rejects_other_names_and_leaves_the_output_alone(void) {
    risk_level parsed = RISK_REVIEW;
    TEST_ASSERT_FALSE(risk_level_parse("ok", &parsed));
    TEST_ASSERT_FALSE(risk_level_parse("", &parsed));
    TEST_ASSERT_FALSE(risk_level_parse("UNKNOWN", &parsed));
    TEST_ASSERT_EQUAL_INT(RISK_REVIEW, parsed);
}

static risk_level classify_bits(const algorithm_policy *policy, unsigned bits) {
    const key_size size = {KEY_SIZE_KNOWN, bits};
    return risk_classify(policy, size);
}

static void test_a_short_key_is_classically_weak(void) {
    TEST_ASSERT_EQUAL_INT(RISK_CLASSICALLY_WEAK, classify_bits(&RSA_POLICY, RSA_MINIMUM_BITS - 1));
    TEST_ASSERT_EQUAL_INT(RISK_CLASSICALLY_WEAK, classify_bits(&RSA_POLICY, 0));
}

static void test_a_key_at_the_threshold_keeps_the_base_level(void) {
    TEST_ASSERT_EQUAL_INT(RISK_QUANTUM_VULNERABLE, classify_bits(&RSA_POLICY, RSA_MINIMUM_BITS));
    TEST_ASSERT_EQUAL_INT(RISK_QUANTUM_VULNERABLE,
                          classify_bits(&RSA_POLICY, RSA_MINIMUM_BITS + 1));
}

static void test_an_unresolved_size_keeps_the_base_level(void) {
    /* bits is ignored unless the kind says it is known. */
    const key_size unknown = {KEY_SIZE_UNKNOWN, 1};
    const key_size not_applicable = {KEY_SIZE_NOT_APPLICABLE, 1};
    TEST_ASSERT_EQUAL_INT(RISK_QUANTUM_VULNERABLE, risk_classify(&RSA_POLICY, unknown));
    TEST_ASSERT_EQUAL_INT(RISK_QUANTUM_VULNERABLE, risk_classify(&RSA_POLICY, not_applicable));
}

static void test_a_policy_without_threshold_ignores_the_size(void) {
    TEST_ASSERT_EQUAL_INT(RISK_CLASSICALLY_WEAK, classify_bits(&MD5_POLICY, 1));
    const algorithm_policy strong = {"AES", RISK_OK, 0};
    TEST_ASSERT_EQUAL_INT(RISK_OK, classify_bits(&strong, 1));
}

static void test_a_short_key_raises_any_lower_level(void) {
    TEST_ASSERT_EQUAL_INT(RISK_CLASSICALLY_WEAK, classify_bits(&AES_POLICY, 1));
    TEST_ASSERT_EQUAL_INT(RISK_REVIEW, classify_bits(&AES_POLICY, RSA_MINIMUM_BITS));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_names_match_the_report_format);
    RUN_TEST(test_values_are_ordered_by_severity);
    RUN_TEST(test_parses_every_report_name);
    RUN_TEST(test_rejects_other_names_and_leaves_the_output_alone);
    RUN_TEST(test_a_short_key_is_classically_weak);
    RUN_TEST(test_a_key_at_the_threshold_keeps_the_base_level);
    RUN_TEST(test_an_unresolved_size_keeps_the_base_level);
    RUN_TEST(test_a_policy_without_threshold_ignores_the_size);
    RUN_TEST(test_a_short_key_raises_any_lower_level);
    return UNITY_END();
}
