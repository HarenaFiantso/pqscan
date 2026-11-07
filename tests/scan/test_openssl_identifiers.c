/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/risk/risk.h"
#include "pqscan/scan/openssl_identifiers.h"
#include "unity.h"

#include <stddef.h>
#include <string.h>

void setUp(void) {}

void tearDown(void) {}

static const crypto_identifier *find_text(const char *text) {
    return openssl_identifier_find(text, strlen(text));
}

static void test_table_is_sorted_without_duplicates(void) {
    size_t count = 0;
    const crypto_identifier *table = openssl_identifier_table(&count);
    TEST_ASSERT_GREATER_THAN_size_t(0, count);
    for (size_t i = 1; i < count; i++) {
        TEST_ASSERT_LESS_THAN_INT_MESSAGE(0, strcmp(table[i - 1].name, table[i].name),
                                          table[i].name);
    }
}

static void test_every_entry_can_be_found(void) {
    size_t count = 0;
    const crypto_identifier *table = openssl_identifier_table(&count);
    for (size_t i = 0; i < count; i++) {
        TEST_ASSERT_EQUAL_PTR_MESSAGE(&table[i], find_text(table[i].name), table[i].name);
    }
}

static void test_finds_algorithm_and_risk(void) {
    const crypto_identifier *entry = find_text("RSA_generate_key_ex");
    TEST_ASSERT_NOT_NULL(entry);
    TEST_ASSERT_EQUAL_STRING("RSA", entry->algorithm);
    TEST_ASSERT_EQUAL_INT(RISK_QUANTUM_VULNERABLE, entry->risk);
}

static void test_weak_and_review_levels_are_used(void) {
    TEST_ASSERT_EQUAL_INT(RISK_CLASSICALLY_WEAK, find_text("EVP_md5")->risk);
    TEST_ASSERT_EQUAL_INT(RISK_REVIEW, find_text("EVP_aes_128_gcm")->risk);
}

static void test_a_prefix_of_an_entry_is_not_found(void) {
    TEST_ASSERT_NULL(find_text("RSA"));
    TEST_ASSERT_NULL(find_text("RSA_generate_key_"));
}

static void test_an_entry_with_a_suffix_is_not_found(void) {
    TEST_ASSERT_NULL(find_text("RSA_newer"));
}

static void test_name_need_not_be_terminated(void) {
    const char *text = "RSA_new(rsa)";
    TEST_ASSERT_NOT_NULL(openssl_identifier_find(text, strlen("RSA_new")));
}

static void test_unknown_and_empty_names_are_not_found(void) {
    TEST_ASSERT_NULL(find_text("printf"));
    TEST_ASSERT_NULL(find_text(""));
}

static const call_signature *find_call(const char *text) {
    return openssl_call_find(text, strlen(text));
}

static const crypto_identifier *find_algorithm(const char *text) {
    return openssl_algorithm_name_find(text, strlen(text));
}

static void test_call_table_is_sorted_without_duplicates(void) {
    size_t count = 0;
    const call_signature *table = openssl_call_table(&count);
    TEST_ASSERT_GREATER_THAN_size_t(0, count);
    for (size_t i = 1; i < count; i++) {
        TEST_ASSERT_LESS_THAN_INT_MESSAGE(0, strcmp(table[i - 1].name, table[i].name),
                                          table[i].name);
    }
}

static void test_every_call_can_be_found(void) {
    size_t count = 0;
    const call_signature *table = openssl_call_table(&count);
    for (size_t i = 0; i < count; i++) {
        TEST_ASSERT_EQUAL_PTR_MESSAGE(&table[i], find_call(table[i].name), table[i].name);
    }
}

static void test_call_reads_the_right_arguments(void) {
    const call_signature *keygen = find_call("EVP_PKEY_Q_keygen");
    TEST_ASSERT_NOT_NULL(keygen);
    TEST_ASSERT_EQUAL_INT(3, keygen->key_bits_argument);
    TEST_ASSERT_EQUAL_INT(2, keygen->algorithm_argument);
    TEST_ASSERT_EQUAL_INT(CALL_NO_ARGUMENT, find_call("EVP_MD_fetch")->key_bits_argument);
}

static void test_unknown_call_is_not_found(void) {
    TEST_ASSERT_NULL(find_call("printf"));
    TEST_ASSERT_NULL(find_call("EVP_MD_fetc"));
}

static void test_algorithm_names_ignore_case(void) {
    TEST_ASSERT_EQUAL_STRING("SHA-1", find_algorithm("sha1")->algorithm);
    TEST_ASSERT_EQUAL_STRING("SHA-1", find_algorithm("SHA-1")->algorithm);
    TEST_ASSERT_EQUAL_STRING("EdDSA", find_algorithm("ed25519")->algorithm);
    TEST_ASSERT_EQUAL_INT(RISK_REVIEW, find_algorithm("aes-128-gcm")->risk);
}

static void test_algorithm_names_match_whole_strings(void) {
    TEST_ASSERT_NULL(find_algorithm("RS"));
    TEST_ASSERT_NULL(find_algorithm("RSAX"));
    TEST_ASSERT_NULL(find_algorithm(""));
    TEST_ASSERT_NULL(find_algorithm("SHA2-256"));
    TEST_ASSERT_NOT_NULL(openssl_algorithm_name_find("RSA, not terminated", strlen("RSA")));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_table_is_sorted_without_duplicates);
    RUN_TEST(test_every_entry_can_be_found);
    RUN_TEST(test_finds_algorithm_and_risk);
    RUN_TEST(test_weak_and_review_levels_are_used);
    RUN_TEST(test_a_prefix_of_an_entry_is_not_found);
    RUN_TEST(test_an_entry_with_a_suffix_is_not_found);
    RUN_TEST(test_name_need_not_be_terminated);
    RUN_TEST(test_unknown_and_empty_names_are_not_found);
    RUN_TEST(test_call_table_is_sorted_without_duplicates);
    RUN_TEST(test_every_call_can_be_found);
    RUN_TEST(test_call_reads_the_right_arguments);
    RUN_TEST(test_unknown_call_is_not_found);
    RUN_TEST(test_algorithm_names_ignore_case);
    RUN_TEST(test_algorithm_names_match_whole_strings);
    return UNITY_END();
}
