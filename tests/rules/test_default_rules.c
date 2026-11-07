/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/key_size.h"
#include "pqscan/core/primitive.h"
#include "pqscan/core/status.h"
#include "pqscan/risk/risk.h"
#include "pqscan/rules/default_rules.h"
#include "pqscan/rules/rule_loader.h"
#include "pqscan/rules/rule_set.h"
#include "unity.h"

#include <stddef.h>
#include <string.h>

enum { MINIMUM_FINITE_FIELD_BITS = 2048 };

static rule_set *rules;

void setUp(void) {
    rule_error error;
    const rule_source source = default_rules_source();
    TEST_ASSERT_EQUAL_INT_MESSAGE(PQSCAN_OK, rule_set_load(&source, &rules, &error), error.message);
}

void tearDown(void) { rule_set_destroy(rules); }

static const crypto_rule *find_mention(const char *name) {
    return rule_set_find_mention(rules, name, strlen(name));
}

static void assert_primitive(crypto_primitive expected, const char *name) {
    const crypto_rule *rule = find_mention(name);
    TEST_ASSERT_NOT_NULL_MESSAGE(rule, name);
    TEST_ASSERT_EQUAL_INT_MESSAGE(expected, rule->primitive, name);
}

static void test_short_finite_field_keys_are_classically_weak(void) {
    const char *const names[] = {"RSA", "DSA", "DH"};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        const algorithm_policy *policy = rule_set_find_algorithm(rules, names[i]);
        TEST_ASSERT_NOT_NULL_MESSAGE(policy, names[i]);
        const key_size just_below = {KEY_SIZE_KNOWN, MINIMUM_FINITE_FIELD_BITS - 1};
        const key_size at_minimum = {KEY_SIZE_KNOWN, MINIMUM_FINITE_FIELD_BITS};
        TEST_ASSERT_EQUAL_INT(RISK_CLASSICALLY_WEAK, risk_classify(policy, just_below));
        TEST_ASSERT_EQUAL_INT(RISK_QUANTUM_VULNERABLE, risk_classify(policy, at_minimum));
    }
}

static void test_risk_levels_match_the_documented_table(void) {
    TEST_ASSERT_EQUAL_INT(RISK_QUANTUM_VULNERABLE, rule_set_find_algorithm(rules, "EdDSA")->risk);
    TEST_ASSERT_EQUAL_INT(RISK_CLASSICALLY_WEAK, rule_set_find_algorithm(rules, "SHA-1")->risk);
    TEST_ASSERT_EQUAL_INT(RISK_CLASSICALLY_WEAK, rule_set_find_algorithm(rules, "3DES")->risk);
    TEST_ASSERT_EQUAL_INT(RISK_REVIEW, rule_set_find_algorithm(rules, "AES-128")->risk);
}

static void test_primitives_say_only_what_the_code_says(void) {
    assert_primitive(PRIMITIVE_SIGNATURE, "RSA_sign");
    assert_primitive(PRIMITIVE_SIGNATURE, "EVP_PKEY_ED25519");
    assert_primitive(PRIMITIVE_ENCRYPTION, "RSA_public_encrypt");
    assert_primitive(PRIMITIVE_KEY_EXCHANGE, "ECDH_compute_key");
    assert_primitive(PRIMITIVE_HASH, "EVP_md5");
    assert_primitive(PRIMITIVE_UNSPECIFIED, "RSA_new");
    assert_primitive(PRIMITIVE_UNSPECIFIED, "EVP_PKEY_EC");
}

static void test_one_shot_hashes_count_only_as_calls(void) {
    TEST_ASSERT_NULL(find_mention("MD5"));
    TEST_ASSERT_NULL(find_mention("SHA1"));
    TEST_ASSERT_NOT_NULL(rule_set_find_callee(rules, "MD5", strlen("MD5")));
    TEST_ASSERT_NOT_NULL(rule_set_find_callee(rules, "SHA1", strlen("SHA1")));
}

static void test_call_reads_the_right_arguments(void) {
    const char name[] = "EVP_PKEY_Q_keygen";
    const call_signature *keygen = rule_set_find_call(rules, name, strlen(name));
    TEST_ASSERT_NOT_NULL(keygen);
    TEST_ASSERT_EQUAL_INT(3, keygen->key_bits_argument);
    TEST_ASSERT_EQUAL_INT(2, keygen->algorithm_argument);
}

static void test_algorithm_names_ignore_case(void) {
    TEST_ASSERT_EQUAL_STRING("SHA-1", rule_set_find_string(rules, "sha1", 4)->algorithm->name);
    TEST_ASSERT_EQUAL_STRING("EdDSA", rule_set_find_string(rules, "ed25519", 7)->algorithm->name);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_short_finite_field_keys_are_classically_weak);
    RUN_TEST(test_risk_levels_match_the_documented_table);
    RUN_TEST(test_primitives_say_only_what_the_code_says);
    RUN_TEST(test_one_shot_hashes_count_only_as_calls);
    RUN_TEST(test_call_reads_the_right_arguments);
    RUN_TEST(test_algorithm_names_ignore_case);
    return UNITY_END();
}
