/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/baseline/baseline.h"
#include "pqscan/core/finding.h"
#include "pqscan/core/json_fields.h"
#include "pqscan/core/key_size.h"
#include "pqscan/core/primitive.h"
#include "pqscan/core/status.h"
#include "pqscan/core/utc_time.h"
#include "pqscan/risk/priority.h"
#include "pqscan/risk/risk.h"
#include "unity.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

enum { DOCUMENT_SIZE = 4096, BITS = 2048, OTHER_BITS = 4096, LINE = 3, OTHER_LINE = 90 };

static const key_size NO_SIZE = {KEY_SIZE_NOT_APPLICABLE, 0};
static const key_size UNRESOLVED = {KEY_SIZE_UNKNOWN, 0};
static const key_size KNOWN = {KEY_SIZE_KNOWN, BITS};

/* Accepts two RSA key generations in a.c, an MD5 in b.c and an unresolved RSA in c.c. */
static const char VALID[] =
    "{\n"
    "  \"schema_version\": 1,\n"
    "  \"findings\": [\n"
    "    {\"path\": \"src/a.c\", \"algorithm\": \"RSA\", \"symbol\": \"RSA_generate_key_ex\",\n"
    "     \"primitive\": \"unspecified\", \"key_size\": 2048, \"count\": 2},\n"
    "    {\"path\": \"b.c\", \"algorithm\": \"MD5\", \"symbol\": \"MD5\", \"primitive\": "
    "\"hash\",\n"
    "     \"key_size\": null, \"count\": 1},\n"
    "    {\"path\": \"./c.c\", \"algorithm\": \"RSA\", \"symbol\": \"RSA_generate_key_ex\",\n"
    "     \"primitive\": \"unspecified\", \"key_size\": \"unknown\"}\n"
    "  ]\n"
    "}\n";

static baseline *loaded;
static finding_list *findings;
static json_error error;

void setUp(void) {
    loaded = NULL;
    findings = finding_list_create();
    TEST_ASSERT_NOT_NULL(findings);
}

void tearDown(void) {
    finding_list_destroy(findings);
    baseline_destroy(loaded);
}

static pqscan_status load_text(const char *text) {
    const baseline_source source = {text, strlen(text)};
    return baseline_load(&source, &loaded, &error);
}

static void load_valid(void) {
    TEST_ASSERT_EQUAL_INT_MESSAGE(PQSCAN_OK, load_text(VALID), error.message);
}

typedef struct sample {
    const char *path;
    size_t line;
    const char *algorithm;
    const char *symbol;
    crypto_primitive primitive;
    key_size size;
} sample;

static void add(const sample *item) {
    const finding found = {
        item->path,      item->line,   item->algorithm, RISK_QUANTUM_VULNERABLE, item->size,
        item->primitive, item->symbol, utc_time_none(), priority_none(),
    };
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, finding_list_add(findings, &found));
}

static void add_rsa(const char *path, size_t line, key_size size) {
    const sample item = {path, line, "RSA", "RSA_generate_key_ex", PRIMITIVE_UNSPECIFIED, size};
    add(&item);
}

static void add_md5(const char *path, size_t line) {
    const sample item = {path, line, "MD5", "MD5", PRIMITIVE_HASH, NO_SIZE};
    add(&item);
}

static void assert_left(size_t index, const char *path, size_t line) {
    const finding *item = finding_list_get(findings, index);
    TEST_ASSERT_NOT_NULL(item);
    TEST_ASSERT_EQUAL_STRING(path, item->path);
    TEST_ASSERT_EQUAL_size_t(line, item->line);
}

static void test_accepted_findings_are_removed_whatever_their_line(void) {
    load_valid();
    add_rsa("src/a.c", OTHER_LINE, KNOWN);
    add_md5("b.c", LINE);
    add_rsa("c.c", LINE, UNRESOLVED);
    TEST_ASSERT_EQUAL_size_t(3, baseline_remove_accepted(loaded, findings));
    TEST_ASSERT_EQUAL_size_t(0, finding_list_count(findings));
    TEST_ASSERT_EQUAL_size_t(1, baseline_unused(loaded));
}

static void test_a_count_accepts_that_many_and_the_last_ones_are_new(void) {
    load_valid();
    add_rsa("src/a.c", 1, KNOWN);
    add_rsa("src/a.c", 2, KNOWN);
    add_rsa("src/a.c", LINE, KNOWN);
    TEST_ASSERT_EQUAL_size_t(2, baseline_remove_accepted(loaded, findings));
    TEST_ASSERT_EQUAL_size_t(1, finding_list_count(findings));
    assert_left(0, "src/a.c", LINE);
}

static void test_the_occurrences_are_used_up_across_calls(void) {
    load_valid();
    add_md5("b.c", 1);
    TEST_ASSERT_EQUAL_size_t(1, baseline_remove_accepted(loaded, findings));
    add_md5("b.c", 2);
    TEST_ASSERT_EQUAL_size_t(0, baseline_remove_accepted(loaded, findings));
    assert_left(0, "b.c", 2);
}

static void test_a_leading_current_directory_does_not_matter(void) {
    load_valid();
    add_rsa("./src/a.c", 1, KNOWN);
    add_rsa(".//c.c", 1, UNRESOLVED);
    TEST_ASSERT_EQUAL_size_t(2, baseline_remove_accepted(loaded, findings));
}

static void test_every_part_of_the_identity_counts(void) {
    load_valid();
    add_rsa("src/b.c", 1, KNOWN);
    add_rsa("src/a.c", 2, (key_size){KEY_SIZE_KNOWN, OTHER_BITS});
    add_rsa("src/a.c", LINE, UNRESOLVED);
    const sample other_symbol = {"src/a.c", 4, "RSA", "RSA_new", PRIMITIVE_UNSPECIFIED, KNOWN};
    add(&other_symbol);
    const sample other_algorithm = {"b.c", 5, "SHA-1", "MD5", PRIMITIVE_HASH, NO_SIZE};
    add(&other_algorithm);
    const sample other_primitive = {"b.c", 6, "MD5", "MD5", PRIMITIVE_SIGNATURE, NO_SIZE};
    add(&other_primitive);
    TEST_ASSERT_EQUAL_size_t(0, baseline_remove_accepted(loaded, findings));
    TEST_ASSERT_EQUAL_size_t(6, finding_list_count(findings));
    TEST_ASSERT_EQUAL_size_t(4, baseline_unused(loaded));
}

static void test_repeated_entries_add_up(void) {
    TEST_ASSERT_EQUAL_INT(
        PQSCAN_OK,
        load_text(
            "{\"schema_version\":1,\"findings\":["
            "{\"path\":\"b.c\",\"algorithm\":\"MD5\",\"symbol\":\"MD5\",\"primitive\":\"hash\","
            "\"key_size\":null},"
            "{\"path\":\"b.c\",\"algorithm\":\"MD5\",\"symbol\":\"MD5\",\"primitive\":\"hash\","
            "\"key_size\":null,\"count\":2}]}"));
    for (size_t line = 1; line <= 4; line++) {
        add_md5("b.c", line);
    }
    TEST_ASSERT_EQUAL_size_t(3, baseline_remove_accepted(loaded, findings));
    assert_left(0, "b.c", 4);
}

static void test_a_path_is_matched_in_its_safe_form(void) {
    TEST_ASSERT_EQUAL_INT(
        PQSCAN_OK,
        load_text("{\"schema_version\":1,\"findings\":["
                  "{\"path\":\"a\\\\x0ab\\\\\\\\.c\",\"algorithm\":\"MD5\",\"symbol\":\"MD5\","
                  "\"primitive\":\"hash\",\"key_size\":null}]}"));
    add_md5("a\\x0ab.c", 1);
    add_md5("a\nb\\.c", 2);
    TEST_ASSERT_EQUAL_size_t(1, baseline_remove_accepted(loaded, findings));
    assert_left(0, "a\\x0ab.c", 1);
}

static void test_an_empty_baseline_accepts_nothing(void) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, load_text("{\"schema_version\":1,\"findings\":[]}"));
    add_md5("b.c", 1);
    TEST_ASSERT_EQUAL_size_t(0, baseline_remove_accepted(loaded, findings));
    TEST_ASSERT_EQUAL_size_t(0, baseline_unused(loaded));
}

static void assert_refused(const char *text, const char *expected_message) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_BASELINE, load_text(text));
    TEST_ASSERT_NULL_MESSAGE(loaded, "the document should have been refused");
    TEST_ASSERT_EQUAL_STRING(expected_message, error.message);
}

/* Puts one entry in an otherwise valid document. */
static void assert_entry_refused(const char *entry, const char *expected_message) {
    char document[DOCUMENT_SIZE];
    const int written =
        snprintf(document, sizeof(document), "{\"schema_version\":1,\"findings\":[%s]}", entry);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(document));
    assert_refused(document, expected_message);
}

#define ENTRY_START                                                                                \
    "{\"path\":\"b.c\",\"algorithm\":\"MD5\",\"symbol\":\"MD5\",\"primitive\":\"hash\""

static void test_a_document_must_be_a_versioned_object(void) {
    assert_refused("[", "line 1: invalid JSON");
    assert_refused("[]", "document: expected an object");
    assert_refused("{\"findings\":[]}", "schema_version: missing");
    assert_refused("{\"schema_version\":2,\"findings\":[]}",
                   "schema_version: expected an integer in range");
    assert_refused("{\"schema_version\":1}", "findings: expected an array");
    assert_refused("{\"schema_version\":1,\"findings\":{}}", "findings: expected an array");
    assert_refused("{\"schema_version\":1,\"findings\":[],\"tool\":{}}", "tool: unknown field");
}

static void test_an_entry_must_name_what_it_accepts(void) {
    assert_entry_refused("1", "findings[0].entry: expected an object");
    assert_entry_refused("{\"algorithm\":\"MD5\"}",
                         "findings[0].path: expected a non-empty string");
    assert_entry_refused("{\"path\":\"\"}", "findings[0].path: expected a non-empty string");
    assert_entry_refused("{\"path\":\"b.c\",\"algorithm\":1}",
                         "findings[0].algorithm: expected a non-empty string");
    assert_entry_refused("{\"path\":\"b.c\",\"algorithm\":\"MD5\"}",
                         "findings[0].symbol: expected a non-empty string");
    assert_entry_refused(ENTRY_START ",\"key_size\":null,\"line\":3}",
                         "findings[0].line: unknown field");
    assert_entry_refused(ENTRY_START ",\"key_size\":null,\"path\":\"c.c\"}",
                         "findings[0].path: repeated field");
}

static void test_an_entry_must_have_a_known_primitive(void) {
    assert_entry_refused("{\"path\":\"b.c\",\"algorithm\":\"MD5\",\"symbol\":\"MD5\","
                         "\"primitive\":\"Hash\",\"key_size\":null}",
                         "findings[0].primitive: unknown primitive");
}

static void test_a_key_size_is_bits_unknown_or_null(void) {
    const char *const bad_sizes[] = {
        "",
        ",\"key_size\":-1",
        ",\"key_size\":2048.5",
        ",\"key_size\":4294967296",
        ",\"key_size\":\"2048\"",
        ",\"key_size\":\"Unknown\"",
        ",\"key_size\":true",
    };
    for (size_t i = 0; i < sizeof(bad_sizes) / sizeof(bad_sizes[0]); i++) {
        char entry[DOCUMENT_SIZE];
        (void)snprintf(entry, sizeof(entry), "%s%s}", ENTRY_START, bad_sizes[i]);
        assert_entry_refused(
            entry, "findings[0].key_size: expected a number of bits, \"unknown\" or null");
    }
}

static void test_the_largest_key_size_is_read(void) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, load_text("{\"schema_version\":1,\"findings\":[" ENTRY_START
                                               ",\"key_size\":4294967295}]}"));
}

static void test_a_count_is_a_positive_integer(void) {
    assert_entry_refused(ENTRY_START ",\"key_size\":null,\"count\":0}",
                         "findings[0].count: expected an integer in range");
    assert_entry_refused(ENTRY_START ",\"key_size\":null,\"count\":1.5}",
                         "findings[0].count: expected an integer in range");
    assert_entry_refused(ENTRY_START ",\"key_size\":null,\"count\":\"2\"}",
                         "findings[0].count: expected an integer in range");
}

static void test_the_failing_entry_is_named(void) {
    assert_refused("{\"schema_version\":1,\"findings\":[" ENTRY_START
                   ",\"key_size\":null}," ENTRY_START ",\"key_size\":null,\"count\":-2}]}",
                   "findings[1].count: expected an integer in range");
}

static void test_destroy_accepts_null(void) { baseline_destroy(NULL); }

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_accepted_findings_are_removed_whatever_their_line);
    RUN_TEST(test_a_count_accepts_that_many_and_the_last_ones_are_new);
    RUN_TEST(test_the_occurrences_are_used_up_across_calls);
    RUN_TEST(test_a_leading_current_directory_does_not_matter);
    RUN_TEST(test_every_part_of_the_identity_counts);
    RUN_TEST(test_repeated_entries_add_up);
    RUN_TEST(test_a_path_is_matched_in_its_safe_form);
    RUN_TEST(test_an_empty_baseline_accepts_nothing);
    RUN_TEST(test_a_document_must_be_a_versioned_object);
    RUN_TEST(test_an_entry_must_name_what_it_accepts);
    RUN_TEST(test_an_entry_must_have_a_known_primitive);
    RUN_TEST(test_a_key_size_is_bits_unknown_or_null);
    RUN_TEST(test_the_largest_key_size_is_read);
    RUN_TEST(test_a_count_is_a_positive_integer);
    RUN_TEST(test_the_failing_entry_is_named);
    RUN_TEST(test_destroy_accepts_null);
    return UNITY_END();
}
