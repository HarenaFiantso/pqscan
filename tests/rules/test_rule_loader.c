/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/primitive.h"
#include "pqscan/core/status.h"
#include "pqscan/risk/risk.h"
#include "pqscan/rules/rule_loader.h"
#include "pqscan/rules/rule_set.h"
#include "unity.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

enum {
    DOCUMENT_SIZE = 1024,
    DEEP_NESTING = 4096,
    NAME_LIMIT = 128,
    TOO_MANY_ALGORITHMS = RULE_SET_MAX_ALGORITHMS + 1,
    ALGORITHM_ENTRY_SIZE = 48,
    DOCUMENT_FRAME_SIZE = 64,
};

static const char TRAILER[] = "garbage";

static const char VALID[] =
    "{\n"
    "  \"schema_version\": 1,\n"
    "  \"algorithms\": [\n"
    "    {\"name\": \"RSA\", \"risk\": \"QUANTUM_VULNERABLE\", \"weak_below_bits\": 2048},\n"
    "    {\"name\": \"MD5\", \"risk\": \"CLASSICALLY_WEAK\"}\n"
    "  ],\n"
    "  \"rules\": [\n"
    "    {\"pattern\": \"RSA_sign\", \"kind\": \"function\", \"algorithm\": \"RSA\",\n"
    "     \"primitive\": \"signature\"},\n"
    "    {\"pattern\": \"EVP_PKEY_RSA\", \"kind\": \"constant\", \"algorithm\": \"RSA\",\n"
    "     \"primitive\": \"unspecified\"},\n"
    "    {\"pattern\": \"MD5\", \"kind\": \"function\", \"algorithm\": \"MD5\",\n"
    "     \"primitive\": \"hash\", \"call_only\": true},\n"
    "    {\"pattern\": \"md5\", \"kind\": \"string\", \"algorithm\": \"MD5\",\n"
    "     \"primitive\": \"hash\"}\n"
    "  ],\n"
    "  \"calls\": [\n"
    "    {\"name\": \"RSA_generate_key_ex\", \"key_bits_argument\": 1},\n"
    "    {\"name\": \"EVP_MD_fetch\", \"algorithm_argument\": 1}\n"
    "  ]\n"
    "}\n";

static rule_set *rules;
static rule_error error;

void setUp(void) { rules = NULL; }

void tearDown(void) { rule_set_destroy(rules); }

static pqscan_status load_bytes(const char *text, size_t len) {
    const rule_source source = {text, len};
    return rule_set_load(&source, &rules, &error);
}

static pqscan_status load_text(const char *text) { return load_bytes(text, strlen(text)); }

/* Puts the three section bodies in an otherwise valid document. */
static void load_sections(const char *algorithms, const char *entries, const char *calls) {
    char document[DOCUMENT_SIZE];
    const int written =
        snprintf(document, sizeof(document),
                 "{\"schema_version\":1,\"algorithms\":[%s],\"rules\":[%s],\"calls\":[%s]}",
                 algorithms, entries, calls);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(document));
    (void)load_text(document);
}

static void assert_refused(const char *expected_message) {
    TEST_ASSERT_NULL_MESSAGE(rules, "the document should have been refused");
    TEST_ASSERT_EQUAL_STRING(expected_message, error.message);
}

static void assert_text_refused(const char *text, const char *expected_message) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_RULES, load_text(text));
    assert_refused(expected_message);
}

static const char ONE_ALGORITHM[] = "{\"name\":\"RSA\",\"risk\":\"OK\"}";

static void assert_algorithm_refused(const char *entry, const char *expected_message) {
    load_sections(entry, "", "");
    assert_refused(expected_message);
}

static void assert_rule_refused(const char *entry, const char *expected_message) {
    load_sections(ONE_ALGORITHM, entry, "");
    assert_refused(expected_message);
}

static void assert_call_refused(const char *entry, const char *expected_message) {
    load_sections("", "", entry);
    assert_refused(expected_message);
}

static const crypto_rule *find_mention(const char *name) {
    return rule_set_find_mention(rules, name, strlen(name));
}

static const call_signature *find_call(const char *name) {
    return rule_set_find_call(rules, name, strlen(name));
}

static void test_loads_a_valid_document(void) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, load_text(VALID));
    TEST_ASSERT_EQUAL_STRING("", error.message);

    const algorithm_policy *rsa = rule_set_find_algorithm(rules, "RSA");
    TEST_ASSERT_NOT_NULL(rsa);
    TEST_ASSERT_EQUAL_INT(RISK_QUANTUM_VULNERABLE, rsa->risk);
    TEST_ASSERT_EQUAL_UINT(2048, rsa->weak_below_bits);
    TEST_ASSERT_EQUAL_UINT(0, rule_set_find_algorithm(rules, "MD5")->weak_below_bits);
}

static void test_loads_every_rule_field(void) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, load_text(VALID));

    const crypto_rule *sign = find_mention("RSA_sign");
    TEST_ASSERT_NOT_NULL(sign);
    TEST_ASSERT_EQUAL_INT(RULE_FUNCTION, sign->kind);
    TEST_ASSERT_EQUAL_INT(PRIMITIVE_SIGNATURE, sign->primitive);
    TEST_ASSERT_EQUAL_STRING("RSA", sign->algorithm->name);
    TEST_ASSERT_FALSE(sign->call_only);

    const crypto_rule *constant = find_mention("EVP_PKEY_RSA");
    TEST_ASSERT_EQUAL_INT(RULE_CONSTANT, constant->kind);
    TEST_ASSERT_EQUAL_INT(PRIMITIVE_UNSPECIFIED, constant->primitive);

    TEST_ASSERT_NULL(find_mention("MD5"));
    TEST_ASSERT_TRUE(rule_set_find_callee(rules, "MD5", strlen("MD5"))->call_only);
    TEST_ASSERT_NOT_NULL(rule_set_find_string(rules, "MD5", strlen("MD5")));
}

static void test_loads_calls_and_fills_in_absent_arguments(void) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, load_text(VALID));
    const call_signature *keygen = find_call("RSA_generate_key_ex");
    TEST_ASSERT_EQUAL_INT(1, keygen->key_bits_argument);
    TEST_ASSERT_EQUAL_INT(CALL_NO_ARGUMENT, keygen->algorithm_argument);
    const call_signature *fetch = find_call("EVP_MD_fetch");
    TEST_ASSERT_EQUAL_INT(CALL_NO_ARGUMENT, fetch->key_bits_argument);
    TEST_ASSERT_EQUAL_INT(1, fetch->algorithm_argument);
}

static void test_accepts_empty_sections(void) {
    load_sections("", "", "");
    TEST_ASSERT_NOT_NULL(rules);
}

static void test_sections_may_come_in_any_order(void) {
    TEST_ASSERT_EQUAL_INT(
        PQSCAN_OK,
        load_text("{\"calls\":[],\"rules\":[{\"pattern\":\"a\",\"kind\":\"macro\","
                  "\"algorithm\":\"X\",\"primitive\":\"hash\"}],"
                  "\"algorithms\":[{\"name\":\"X\",\"risk\":\"OK\"}],\"schema_version\":1}"));
    TEST_ASSERT_EQUAL_INT(RULE_MACRO, rule_set_find_mention(rules, "a", 1)->kind);
}

static void test_text_need_not_be_terminated(void) {
    char padded[sizeof(VALID) + 1];
    memcpy(padded, VALID, sizeof(VALID) - 1);
    padded[sizeof(VALID) - 1] = '}';
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, load_bytes(padded, sizeof(VALID) - 1));
}

static void test_refuses_text_that_is_not_json(void) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_RULES, load_bytes("", 0));
    assert_refused("line 1: invalid JSON");
    assert_text_refused("not json", "line 1: invalid JSON");
    assert_text_refused("{\n\n  oops\n}", "line 3: invalid JSON");
}

static void test_refuses_bytes_after_the_document(void) {
    char document[sizeof(VALID) + sizeof(TRAILER)];
    (void)snprintf(document, sizeof(document), "%s%s", VALID, TRAILER);
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_RULES, load_text(document));
    assert_refused("line 22: invalid JSON");
}

static void test_refuses_a_nul_after_the_document(void) {
    char document[sizeof(VALID) + 1];
    memcpy(document, VALID, sizeof(VALID));
    document[sizeof(VALID)] = 'x';
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_RULES, load_bytes(document, sizeof(document)));
    TEST_ASSERT_NULL(rules);
}

static void test_survives_every_truncation(void) {
    for (size_t len = 0; len < sizeof(VALID) - 2; len++) {
        TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_RULES, load_bytes(VALID, len));
        TEST_ASSERT_NULL(rules);
    }
}

static void test_survives_deep_nesting(void) {
    static char document[DEEP_NESTING];
    memset(document, '[', sizeof(document));
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_RULES, load_bytes(document, sizeof(document)));
    TEST_ASSERT_NULL(rules);
}

static void test_refuses_a_document_of_the_wrong_shape(void) {
    assert_text_refused("[]", "document: expected an object");
    assert_text_refused("1", "document: expected an object");
    assert_text_refused("{\"schema_version\":1,\"algorithms\":[],\"rules\":[]}",
                        "calls: expected an array");
    assert_text_refused("{\"schema_version\":1,\"algorithms\":{},\"rules\":[],\"calls\":[]}",
                        "algorithms: expected an array");
    assert_text_refused("{\"schema_version\":1,\"algorithms\":[1],\"rules\":[],\"calls\":[]}",
                        "algorithms[0].entry: expected an object");
}

static void test_refuses_unknown_or_repeated_fields(void) {
    assert_text_refused("{\"schema_version\":1,\"extra\":[]}", "extra: unknown field");
    assert_text_refused("{\"schema_version\":1,\"schema_version\":1}",
                        "schema_version: repeated field");
    assert_algorithm_refused("{\"name\":\"a\",\"risk\":\"OK\",\"size\":1}",
                             "algorithms[0].size: unknown field");
    assert_rule_refused("{\"pattern\":\"a\",\"pattern\":\"b\"}",
                        "rules[0].pattern: repeated field");
    assert_call_refused("{\"name\":\"a\",\"bits\":1}", "calls[0].bits: unknown field");
}

static void test_refuses_a_missing_or_unknown_schema_version(void) {
    assert_text_refused("{}", "schema_version: missing");
    assert_text_refused("{\"schema_version\":2}", "schema_version: expected an integer in range");
    assert_text_refused("{\"schema_version\":\"1\"}",
                        "schema_version: expected an integer in range");
}

static void test_refuses_bad_names(void) {
    assert_algorithm_refused("{\"risk\":\"OK\"}", "algorithms[0].name: expected a string");
    assert_algorithm_refused("{\"name\":1,\"risk\":\"OK\"}",
                             "algorithms[0].name: expected a string");
    assert_algorithm_refused("{\"name\":\"\",\"risk\":\"OK\"}",
                             "algorithms[0].name: expected 1 to 128 printable ASCII characters");
    assert_algorithm_refused("{\"name\":\"a\\u001bb\",\"risk\":\"OK\"}",
                             "algorithms[0].name: expected 1 to 128 printable ASCII characters");
    assert_algorithm_refused("{\"name\":\"\\u00e9\",\"risk\":\"OK\"}",
                             "algorithms[0].name: expected 1 to 128 printable ASCII characters");
}

static void test_refuses_a_name_over_the_limit(void) {
    char entry[DOCUMENT_SIZE];
    char name[NAME_LIMIT + 2];
    memset(name, 'a', sizeof(name) - 1);
    name[sizeof(name) - 1] = '\0';
    (void)snprintf(entry, sizeof(entry), "{\"name\":\"%s\",\"risk\":\"OK\"}", name);
    assert_algorithm_refused(entry,
                             "algorithms[0].name: expected 1 to 128 printable ASCII characters");

    name[sizeof(name) - 2] = '\0';
    (void)snprintf(entry, sizeof(entry), "{\"name\":\"%s\",\"risk\":\"OK\"}", name);
    load_sections(entry, "", "");
    TEST_ASSERT_NOT_NULL(rules);
}

static void test_refuses_bad_algorithms(void) {
    assert_algorithm_refused("{\"name\":\"a\",\"risk\":\"BAD\"}",
                             "algorithms[0].risk: unknown risk level");
    assert_algorithm_refused("{\"name\":\"a\",\"risk\":\"ok\"}",
                             "algorithms[0].risk: unknown risk level");
    assert_algorithm_refused("{\"name\":\"a\",\"risk\":\"OK\"},{\"name\":\"a\",\"risk\":\"OK\"}",
                             "algorithms[1].name: repeated, or too many algorithms");
}

static void test_refuses_bad_key_sizes(void) {
    const char *const values[] = {
        "0", "-1", "2048.5", "\"2048\"", "true", "null", "1e308", "1e999", "2147483648", "1048577",
    };
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
        char entry[DOCUMENT_SIZE];
        (void)snprintf(entry, sizeof(entry),
                       "{\"name\":\"a\",\"risk\":\"OK\",\"weak_below_bits\":%s}", values[i]);
        load_sections(entry, "", "");
        TEST_ASSERT_NULL_MESSAGE(rules, values[i]);
        TEST_ASSERT_EQUAL_STRING("algorithms[0].weak_below_bits: expected an integer in range",
                                 error.message);
    }
}

static void test_refuses_too_many_algorithms(void) {
    static char entries[TOO_MANY_ALGORITHMS * ALGORITHM_ENTRY_SIZE];
    size_t used = 0;
    for (int i = 0; i < TOO_MANY_ALGORITHMS; i++) {
        used += (size_t)snprintf(entries + used, sizeof(entries) - used,
                                 "%s{\"name\":\"a%d\",\"risk\":\"OK\"}", (i == 0) ? "" : ",", i);
    }
    static char document[sizeof(entries) + DOCUMENT_FRAME_SIZE];
    (void)snprintf(document, sizeof(document),
                   "{\"schema_version\":1,\"algorithms\":[%s],\"rules\":[],\"calls\":[]}", entries);
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_RULES, load_text(document));
    assert_refused("algorithms[256].name: repeated, or too many algorithms");
}

static void test_refuses_bad_rules(void) {
    assert_rule_refused("{\"kind\":\"function\"}", "rules[0].pattern: expected a string");
    assert_rule_refused("{\"pattern\":\"a\",\"kind\":\"class\"}", "rules[0].kind: unknown kind");
    assert_rule_refused("{\"pattern\":\"a\",\"kind\":\"macro\",\"algorithm\":\"NOPE\"}",
                        "rules[0].algorithm: not declared in algorithms");
    assert_rule_refused("{\"pattern\":\"a\",\"kind\":\"macro\",\"algorithm\":\"RSA\"}",
                        "rules[0].primitive: expected a string");
    assert_rule_refused(
        "{\"pattern\":\"a\",\"kind\":\"macro\",\"algorithm\":\"RSA\",\"primitive\":\"mac\"}",
        "rules[0].primitive: unknown primitive");
}

static void test_refuses_bad_call_only(void) {
    assert_rule_refused("{\"pattern\":\"a\",\"kind\":\"function\",\"algorithm\":\"RSA\","
                        "\"primitive\":\"hash\",\"call_only\":1}",
                        "rules[0].call_only: expected true or false");
    assert_rule_refused("{\"pattern\":\"a\",\"kind\":\"string\",\"algorithm\":\"RSA\","
                        "\"primitive\":\"hash\",\"call_only\":true}",
                        "rules[0].call_only: only a function can be called");
}

static void test_refuses_bad_calls(void) {
    assert_call_refused("{\"key_bits_argument\":1}", "calls[0].name: expected a string");
    assert_call_refused("{\"name\":\"a\"}",
                        "calls[0].name: a call needs at least one argument to read");
    assert_call_refused("{\"name\":\"a\",\"key_bits_argument\":-1}",
                        "calls[0].key_bits_argument: expected an integer in range");
    assert_call_refused("{\"name\":\"a\",\"algorithm_argument\":256}",
                        "calls[0].algorithm_argument: expected an integer in range");
}

static void test_reports_the_index_of_the_entry_at_fault(void) {
    load_sections("", "", "{\"name\":\"a\",\"key_bits_argument\":0},{\"name\":\"b\"}");
    assert_refused("calls[1].name: a call needs at least one argument to read");
}

static void test_refuses_duplicates_found_by_the_seal(void) {
    const char rule[] =
        "{\"pattern\":\"a\",\"kind\":\"macro\",\"algorithm\":\"RSA\",\"primitive\":\"hash\"}";
    char entries[DOCUMENT_SIZE];
    (void)snprintf(entries, sizeof(entries), "%s,%s", rule, rule);
    assert_rule_refused(entries, "repeated name: a");
    assert_call_refused("{\"name\":\"c\",\"key_bits_argument\":1},"
                        "{\"name\":\"c\",\"key_bits_argument\":2}",
                        "repeated name: c");
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_loads_a_valid_document);
    RUN_TEST(test_loads_every_rule_field);
    RUN_TEST(test_loads_calls_and_fills_in_absent_arguments);
    RUN_TEST(test_accepts_empty_sections);
    RUN_TEST(test_sections_may_come_in_any_order);
    RUN_TEST(test_text_need_not_be_terminated);
    RUN_TEST(test_refuses_text_that_is_not_json);
    RUN_TEST(test_refuses_bytes_after_the_document);
    RUN_TEST(test_refuses_a_nul_after_the_document);
    RUN_TEST(test_survives_every_truncation);
    RUN_TEST(test_survives_deep_nesting);
    RUN_TEST(test_refuses_a_document_of_the_wrong_shape);
    RUN_TEST(test_refuses_unknown_or_repeated_fields);
    RUN_TEST(test_refuses_a_missing_or_unknown_schema_version);
    RUN_TEST(test_refuses_bad_names);
    RUN_TEST(test_refuses_a_name_over_the_limit);
    RUN_TEST(test_refuses_bad_algorithms);
    RUN_TEST(test_refuses_bad_key_sizes);
    RUN_TEST(test_refuses_too_many_algorithms);
    RUN_TEST(test_refuses_bad_rules);
    RUN_TEST(test_refuses_bad_call_only);
    RUN_TEST(test_refuses_bad_calls);
    RUN_TEST(test_reports_the_index_of_the_entry_at_fault);
    RUN_TEST(test_refuses_duplicates_found_by_the_seal);
    return UNITY_END();
}
