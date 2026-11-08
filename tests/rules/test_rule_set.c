/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/primitive.h"
#include "pqscan/core/status.h"
#include "pqscan/risk/risk.h"
#include "pqscan/rules/rule_set.h"
#include "unity.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

enum { NAME_SIZE = 16, THRESHOLD_BITS = 2048 };

static rule_set *set;
static const algorithm_policy *rsa;

void setUp(void) {
    set = rule_set_create();
    TEST_ASSERT_NOT_NULL(set);
    const algorithm_policy policy = {"RSA", RISK_QUANTUM_VULNERABLE, THRESHOLD_BITS};
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, rule_set_add_algorithm(set, &policy));
    rsa = rule_set_find_algorithm(set, "RSA");
    TEST_ASSERT_NOT_NULL(rsa);
}

void tearDown(void) { rule_set_destroy(set); }

static void add_rule(const char *pattern, rule_kind kind, bool call_only) {
    const crypto_rule rule = {pattern, kind, rsa, PRIMITIVE_SIGNATURE, call_only, 0};
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, rule_set_add_rule(set, &rule));
}

static void add_call(const char *name, int key_bits, int algorithm) {
    const call_signature call = {name, key_bits, algorithm};
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, rule_set_add_call(set, &call));
}

static void seal(void) {
    const char *duplicate = NULL;
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, rule_set_seal(set, &duplicate));
    TEST_ASSERT_NULL(duplicate);
}

static const crypto_rule *find_mention(const char *name) {
    return rule_set_find_mention(set, name, strlen(name));
}

static const crypto_rule *find_callee(const char *name) {
    return rule_set_find_callee(set, name, strlen(name));
}

static const crypto_rule *find_string(const char *text) {
    return rule_set_find_string(set, text, strlen(text));
}

static const crypto_rule *find_config_token(const char *text) {
    return rule_set_find_config_token(set, text, strlen(text));
}

static const call_signature *find_call(const char *name) {
    return rule_set_find_call(set, name, strlen(name));
}

static void assert_seal_finds_duplicate(const char *expected) {
    const char *duplicate = NULL;
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_RULES, rule_set_seal(set, &duplicate));
    TEST_ASSERT_NOT_NULL(duplicate);
    TEST_ASSERT_EQUAL_STRING(expected, duplicate);
}

static void test_destroy_accepts_null(void) { rule_set_destroy(NULL); }

static void test_an_empty_set_finds_nothing(void) {
    seal();
    TEST_ASSERT_NULL(find_mention("RSA_new"));
    TEST_ASSERT_NULL(find_callee("RSA_new"));
    TEST_ASSERT_NULL(find_string("RSA"));
    TEST_ASSERT_NULL(find_call("RSA_new"));
}

static void test_copies_every_string(void) {
    char pattern[NAME_SIZE] = "RSA_new";
    char call_name[NAME_SIZE] = "EVP_RSA_gen";
    add_rule(pattern, RULE_FUNCTION, false);
    add_call(call_name, 0, CALL_NO_ARGUMENT);
    memset(pattern, 'x', sizeof(pattern) - 1);
    memset(call_name, 'x', sizeof(call_name) - 1);
    seal();
    TEST_ASSERT_NOT_NULL(find_mention("RSA_new"));
    TEST_ASSERT_NOT_NULL(find_call("EVP_RSA_gen"));
}

static void test_algorithm_keeps_its_address_as_others_are_added(void) {
    for (int i = 0; i < RULE_SET_MAX_ALGORITHMS - 1; i++) {
        char name[NAME_SIZE];
        (void)snprintf(name, sizeof(name), "ALGO-%d", i);
        const algorithm_policy policy = {name, RISK_REVIEW, 0};
        TEST_ASSERT_EQUAL_INT(PQSCAN_OK, rule_set_add_algorithm(set, &policy));
    }
    TEST_ASSERT_EQUAL_PTR(rsa, rule_set_find_algorithm(set, "RSA"));
    TEST_ASSERT_EQUAL_STRING("ALGO-7", rule_set_find_algorithm(set, "ALGO-7")->name);
}

static void test_refuses_more_algorithms_than_the_limit(void) {
    for (int i = 0; i < RULE_SET_MAX_ALGORITHMS - 1; i++) {
        char name[NAME_SIZE];
        (void)snprintf(name, sizeof(name), "ALGO-%d", i);
        const algorithm_policy policy = {name, RISK_REVIEW, 0};
        TEST_ASSERT_EQUAL_INT(PQSCAN_OK, rule_set_add_algorithm(set, &policy));
    }
    const algorithm_policy extra = {"ONE-TOO-MANY", RISK_REVIEW, 0};
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_RULES, rule_set_add_algorithm(set, &extra));
}

static void test_refuses_a_duplicate_algorithm(void) {
    const algorithm_policy again = {"RSA", RISK_REVIEW, 0};
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_RULES, rule_set_add_algorithm(set, &again));
    TEST_ASSERT_EQUAL_INT(RISK_QUANTUM_VULNERABLE, rsa->risk);
}

static void test_unknown_algorithm_is_not_found(void) {
    TEST_ASSERT_NULL(rule_set_find_algorithm(set, "rsa"));
}

static void test_finds_rules_added_in_any_order(void) {
    const char *const names[] = {"Z_last", "A_first", "M_middle", "B_second"};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        add_rule(names[i], RULE_FUNCTION, false);
    }
    seal();
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        const crypto_rule *rule = find_mention(names[i]);
        TEST_ASSERT_NOT_NULL_MESSAGE(rule, names[i]);
        TEST_ASSERT_EQUAL_STRING(names[i], rule->pattern);
        TEST_ASSERT_EQUAL_PTR(rsa, rule->algorithm);
    }
}

static void test_a_prefix_or_longer_name_is_not_found(void) {
    add_rule("RSA_new", RULE_FUNCTION, false);
    seal();
    TEST_ASSERT_NULL(find_mention("RSA"));
    TEST_ASSERT_NULL(find_mention("RSA_newer"));
    TEST_ASSERT_NULL(find_mention(""));
}

static void test_names_need_not_be_terminated(void) {
    add_rule("RSA_new", RULE_FUNCTION, false);
    add_rule("RSA", RULE_STRING, false);
    add_call("RSA_new", CALL_NO_ARGUMENT, 0);
    seal();
    const char *text = "RSA_new(rsa)";
    TEST_ASSERT_NOT_NULL(rule_set_find_mention(set, text, strlen("RSA_new")));
    TEST_ASSERT_NOT_NULL(rule_set_find_callee(set, text, strlen("RSA_new")));
    TEST_ASSERT_NOT_NULL(rule_set_find_call(set, text, strlen("RSA_new")));
    TEST_ASSERT_NOT_NULL(rule_set_find_string(set, text, strlen("RSA")));
}

static void test_call_only_rules_match_callees_but_not_mentions(void) {
    add_rule("MD5", RULE_FUNCTION, true);
    add_rule("RSA_new", RULE_FUNCTION, false);
    seal();
    TEST_ASSERT_NULL(find_mention("MD5"));
    TEST_ASSERT_NOT_NULL(find_callee("MD5"));
    TEST_ASSERT_NOT_NULL(find_mention("RSA_new"));
    TEST_ASSERT_NOT_NULL(find_callee("RSA_new"));
}

static void test_strings_ignore_case(void) {
    add_rule("SHA-1", RULE_STRING, false);
    add_rule("ed25519", RULE_STRING, false);
    add_rule("Z_upper", RULE_STRING, false);
    seal();
    TEST_ASSERT_NOT_NULL(find_string("sha-1"));
    TEST_ASSERT_NOT_NULL(find_string("SHA-1"));
    TEST_ASSERT_NOT_NULL(find_string("ED25519"));
    TEST_ASSERT_NOT_NULL(find_string("z_UPPER"));
}

static void test_strings_match_whole_text_only(void) {
    add_rule("SHA-1", RULE_STRING, false);
    seal();
    TEST_ASSERT_NULL(find_string("SHA-"));
    TEST_ASSERT_NULL(find_string("SHA-11"));
}

static void test_strings_stay_apart_from_identifiers(void) {
    add_rule("SHA-1", RULE_STRING, false);
    seal();
    TEST_ASSERT_NULL(find_mention("SHA-1"));
    TEST_ASSERT_NULL(find_callee("SHA-1"));
}

static void test_a_nul_in_a_string_never_reads_past_the_pattern(void) {
    add_rule("RSA", RULE_STRING, false);
    seal();
    const char text[] = "RSA\0more";
    TEST_ASSERT_NULL(rule_set_find_string(set, text, sizeof(text) - 1));
}

static void test_a_nul_in_a_name_never_reads_past_the_pattern(void) {
    add_rule("RSA_new", RULE_FUNCTION, false);
    add_call("RSA_new", 1, CALL_NO_ARGUMENT);
    seal();
    const char text[] = "RSA_new\0abcdefgh";
    TEST_ASSERT_NULL(rule_set_find_callee(set, text, sizeof(text) - 1));
    TEST_ASSERT_NULL(rule_set_find_call(set, text, sizeof(text) - 1));
}

static void test_a_string_and_an_identifier_may_share_a_name(void) {
    add_rule("MD5", RULE_STRING, false);
    add_rule("MD5", RULE_FUNCTION, true);
    seal();
    TEST_ASSERT_NOT_NULL(find_string("md5"));
    TEST_ASSERT_NOT_NULL(find_callee("MD5"));
}

static void test_finds_calls_in_any_order(void) {
    add_call("Z_call", 1, CALL_NO_ARGUMENT);
    add_call("A_call", CALL_NO_ARGUMENT, 2);
    seal();
    TEST_ASSERT_EQUAL_INT(1, find_call("Z_call")->key_bits_argument);
    TEST_ASSERT_EQUAL_INT(2, find_call("A_call")->algorithm_argument);
    TEST_ASSERT_NULL(find_call("A_cal"));
    TEST_ASSERT_NULL(find_call("printf"));
}

static void test_seal_reports_duplicate_identifiers(void) {
    add_rule("RSA_new", RULE_FUNCTION, false);
    add_rule("DSA_new", RULE_FUNCTION, false);
    add_rule("RSA_new", RULE_CONSTANT, false);
    assert_seal_finds_duplicate("RSA_new");
}

static void test_seal_reports_duplicate_strings_ignoring_case(void) {
    add_rule("RSA", RULE_STRING, false);
    add_rule("rsa", RULE_STRING, false);
    const char *duplicate = NULL;
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_RULES, rule_set_seal(set, &duplicate));
    TEST_ASSERT_NOT_NULL(duplicate);
}

static void test_config_tokens_ignore_case_and_stay_in_their_family(void) {
    add_rule("ssh-rsa", RULE_CONFIG, false);
    add_rule("ECDHE", RULE_CONFIG, false);
    seal();
    TEST_ASSERT_NOT_NULL(find_config_token("SSH-RSA"));
    TEST_ASSERT_NOT_NULL(find_config_token("ecdhe"));
    TEST_ASSERT_NULL(find_config_token("ssh-rs"));
    TEST_ASSERT_NULL(find_string("ssh-rsa"));
    TEST_ASSERT_NULL(find_callee("ECDHE"));
    TEST_ASSERT_NULL(rule_set_find_key_type(set, "ECDHE"));
}

static void test_key_types_ignore_case_and_stay_in_their_family(void) {
    add_rule("rsaEncryption", RULE_KEY, false);
    seal();
    TEST_ASSERT_NOT_NULL(rule_set_find_key_type(set, "RSAENCRYPTION"));
    TEST_ASSERT_NULL(rule_set_find_key_type(set, "rsa"));
    TEST_ASSERT_NULL(find_config_token("rsaEncryption"));
    TEST_ASSERT_NULL(find_mention("rsaEncryption"));
}

static void test_every_family_may_share_one_name(void) {
    add_rule("RSA", RULE_FUNCTION, false);
    add_rule("RSA", RULE_STRING, false);
    add_rule("RSA", RULE_CONFIG, false);
    add_rule("RSA", RULE_KEY, false);
    seal();
    TEST_ASSERT_NOT_NULL(find_callee("RSA"));
    TEST_ASSERT_NOT_NULL(find_string("RSA"));
    TEST_ASSERT_NOT_NULL(find_config_token("RSA"));
    TEST_ASSERT_NOT_NULL(rule_set_find_key_type(set, "RSA"));
}

static void test_seal_reports_duplicate_config_tokens_ignoring_case(void) {
    add_rule("ssh-rsa", RULE_CONFIG, false);
    add_rule("SSH-RSA", RULE_CONFIG, false);
    const char *duplicate = NULL;
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_RULES, rule_set_seal(set, &duplicate));
    TEST_ASSERT_NOT_NULL(duplicate);
}

static void test_seal_reports_duplicate_key_types(void) {
    add_rule("ED25519", RULE_KEY, false);
    add_rule("ED25519", RULE_KEY, false);
    assert_seal_finds_duplicate("ED25519");
}

static void test_seal_reports_duplicate_calls(void) {
    add_call("EVP_RSA_gen", 0, CALL_NO_ARGUMENT);
    add_call("EVP_RSA_gen", 1, CALL_NO_ARGUMENT);
    assert_seal_finds_duplicate("EVP_RSA_gen");
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_destroy_accepts_null);
    RUN_TEST(test_an_empty_set_finds_nothing);
    RUN_TEST(test_copies_every_string);
    RUN_TEST(test_algorithm_keeps_its_address_as_others_are_added);
    RUN_TEST(test_refuses_more_algorithms_than_the_limit);
    RUN_TEST(test_refuses_a_duplicate_algorithm);
    RUN_TEST(test_unknown_algorithm_is_not_found);
    RUN_TEST(test_finds_rules_added_in_any_order);
    RUN_TEST(test_a_prefix_or_longer_name_is_not_found);
    RUN_TEST(test_names_need_not_be_terminated);
    RUN_TEST(test_call_only_rules_match_callees_but_not_mentions);
    RUN_TEST(test_strings_ignore_case);
    RUN_TEST(test_strings_match_whole_text_only);
    RUN_TEST(test_strings_stay_apart_from_identifiers);
    RUN_TEST(test_a_nul_in_a_string_never_reads_past_the_pattern);
    RUN_TEST(test_a_nul_in_a_name_never_reads_past_the_pattern);
    RUN_TEST(test_a_string_and_an_identifier_may_share_a_name);
    RUN_TEST(test_finds_calls_in_any_order);
    RUN_TEST(test_seal_reports_duplicate_identifiers);
    RUN_TEST(test_seal_reports_duplicate_strings_ignoring_case);
    RUN_TEST(test_config_tokens_ignore_case_and_stay_in_their_family);
    RUN_TEST(test_key_types_ignore_case_and_stay_in_their_family);
    RUN_TEST(test_every_family_may_share_one_name);
    RUN_TEST(test_seal_reports_duplicate_config_tokens_ignoring_case);
    RUN_TEST(test_seal_reports_duplicate_key_types);
    RUN_TEST(test_seal_reports_duplicate_calls);
    return UNITY_END();
}
