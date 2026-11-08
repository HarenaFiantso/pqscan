/* SPDX-License-Identifier: Apache-2.0 */
#include "elf_builder.h"
#include "pqscan/core/finding.h"
#include "pqscan/core/key_size.h"
#include "pqscan/core/primitive.h"
#include "pqscan/core/status.h"
#include "pqscan/risk/risk.h"
#include "pqscan/rules/default_rules.h"
#include "pqscan/rules/rule_loader.h"
#include "pqscan/rules/rule_set.h"
#include "pqscan/scan/elf_scanner.h"
#include "pqscan/scan/file_reader.h"
#include "pqscan/scan/scanner.h"
#include "scan_support.h"
#include "temp_tree.h"
#include "unity.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum { PATH_SIZE = 512, DESCRIPTION_SIZE = 512, PAST_ANY_TABLE = 4000, CLIENT_FINDING_COUNT = 5 };

/* In the order client.c first refers to them. */
static const char CLIENT_FINDINGS[] = "0:DH 0:RSA 0:SHA-1 0:MD5 0:RSA-unknown";

static const test_symbol IMPORTS[] = {
    {"RSA_new", TEST_STT_FUNC, false},
    {"EVP_sha1", TEST_STT_FUNC, false},
    {"printf", TEST_STT_FUNC, false},
};
static const test_symbol OBJECT_SYMBOLS[] = {
    {"RSA_new", TEST_STT_NOTYPE, false},
    {"MD5", TEST_STT_NOTYPE, true},
    {"EVP_md5", TEST_STT_OBJECT, true},
    {"DSA_sign", TEST_STT_GNU_IFUNC, true},
};
static const test_symbols IMPORT_LIST = {IMPORTS, sizeof(IMPORTS) / sizeof(IMPORTS[0])};
static const test_symbols OBJECT_LIST = {
    OBJECT_SYMBOLS,
    sizeof(OBJECT_SYMBOLS) / sizeof(OBJECT_SYMBOLS[0]),
};

static finding_list *findings;
static rule_set *rules;
static built_elf elf;

void setUp(void) {
    findings = finding_list_create();
    TEST_ASSERT_NOT_NULL(findings);
    rule_error error;
    const rule_source source = default_rules_source();
    TEST_ASSERT_EQUAL_INT_MESSAGE(PQSCAN_OK, rule_set_load(&source, &rules, &error), error.message);
}

void tearDown(void) {
    finding_list_destroy(findings);
    rule_set_destroy(rules);
}

static pqscan_status scan_contents(const file_contents *file) {
    const scan_input input = {"binary", file, rules};
    return elf_scanner.scan(&input, findings);
}

static pqscan_status scan_fixture(const char *name) {
    char path[PATH_SIZE];
    const int written = snprintf(path, sizeof(path), "%s/%s", PQSCAN_ELF_FIXTURES, name);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(path));
    file_contents *file = NULL;
    TEST_ASSERT_EQUAL_INT_MESSAGE(PQSCAN_OK, file_contents_read(path, &file), path);
    const pqscan_status status = scan_contents(file);
    file_contents_destroy(file);
    return status;
}

static pqscan_status scan_built(void) {
    const file_contents file = {(char *)elf.bytes, elf.len};
    return scan_contents(&file);
}

static void build_both(void) {
    const elf_spec spec = {false, OBJECT_LIST, IMPORT_LIST};
    elf_build(&spec, &elf);
}

static void assert_findings(const char *expected) {
    char actual[DESCRIPTION_SIZE];
    describe_findings(findings, actual, sizeof(actual));
    TEST_ASSERT_EQUAL_STRING(expected, actual);
}

static const finding *nth(size_t index) {
    const finding *item = finding_list_get(findings, index);
    TEST_ASSERT_NOT_NULL(item);
    return item;
}

static void test_accepts_elf_files_whatever_their_name(void) {
    temp_tree *tree = temp_tree_create();
    TEST_ASSERT_TRUE(elf_scanner.accepts(temp_tree_add_file(tree, "server", "\177ELF\002")));
    TEST_ASSERT_FALSE(elf_scanner.accepts(temp_tree_add_file(tree, "lib.so", "text")));
    TEST_ASSERT_FALSE(elf_scanner.accepts(temp_tree_add_file(tree, "main.c", "int x;")));
    temp_tree_destroy(tree);
}

static void test_reports_what_an_object_file_calls_and_defines(void) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, scan_fixture("bin/client.o"));
    assert_findings(CLIENT_FINDINGS);
}

static void test_reads_a_big_endian_object_file(void) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, scan_fixture("bin/client-aarch64be"));
    assert_findings(CLIENT_FINDINGS);
}

static void test_a_finding_names_the_symbol_and_what_the_rule_says(void) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, scan_fixture("bin/client.o"));
    const finding *dh = nth(0);
    TEST_ASSERT_EQUAL_STRING("binary", dh->path);
    TEST_ASSERT_EQUAL_size_t(0, dh->line);
    TEST_ASSERT_EQUAL_STRING("DH_generate_key", dh->symbol);
    TEST_ASSERT_EQUAL_INT(PRIMITIVE_KEY_EXCHANGE, dh->primitive);
    TEST_ASSERT_EQUAL_INT(RISK_QUANTUM_VULNERABLE, dh->risk);
    TEST_ASSERT_EQUAL_INT(KEY_SIZE_NOT_APPLICABLE, dh->size.kind);
    TEST_ASSERT_FALSE(dh->expires.known);
    TEST_ASSERT_EQUAL_INT(RISK_CLASSICALLY_WEAK, nth(3)->risk);
}

static void test_the_key_size_of_a_call_is_unknown_in_a_binary(void) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, scan_fixture("bin/client.o"));
    const finding *keygen = nth(4);
    TEST_ASSERT_EQUAL_STRING("RSA_generate_key_ex", keygen->symbol);
    TEST_ASSERT_EQUAL_INT(KEY_SIZE_UNKNOWN, keygen->size.kind);
}

static void test_counts_functions_and_imports_but_not_data_or_labels(void) {
    build_both();
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, scan_built());
    assert_findings("0:RSA 0:SHA-1 0:DSA");
    TEST_ASSERT_EQUAL_STRING("DSA_sign", nth(2)->symbol);
}

static void test_each_file_has_its_own_findings(void) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, scan_fixture("bin/client.o"));
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, scan_fixture("bin/client.o"));
    TEST_ASSERT_EQUAL_size_t(2 * CLIENT_FINDING_COUNT, finding_list_count(findings));
}

static void test_a_damaged_table_keeps_the_findings_of_the_other(void) {
    build_both();
    const size_t header = built_elf_section(&elf, elf.static_table);
    const elf_field offset = {header + TEST_SH_OFFSET, TEST_XWORD};
    built_elf_put(&elf, offset, PAST_ANY_TABLE);
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_ELF_MALFORMED, scan_built());
    assert_findings("0:RSA 0:SHA-1");
}

static void test_a_32_bit_file_is_not_analyzed(void) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_ELF_UNSUPPORTED, scan_fixture("broken/client-i386.o"));
    TEST_ASSERT_EQUAL_size_t(0, finding_list_count(findings));
}

static void test_a_truncated_file_is_malformed(void) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_ELF_MALFORMED, scan_fixture("broken/truncated.o"));
    TEST_ASSERT_EQUAL_size_t(0, finding_list_count(findings));
}

static void test_a_file_without_symbols_is_not_analyzed(void) {
    const elf_spec spec = {false, {NULL, 0}, {NULL, 0}};
    elf_build(&spec, &elf);
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_ELF_NO_SYMBOLS, scan_built());
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_accepts_elf_files_whatever_their_name);
    RUN_TEST(test_reports_what_an_object_file_calls_and_defines);
    RUN_TEST(test_reads_a_big_endian_object_file);
    RUN_TEST(test_a_finding_names_the_symbol_and_what_the_rule_says);
    RUN_TEST(test_the_key_size_of_a_call_is_unknown_in_a_binary);
    RUN_TEST(test_counts_functions_and_imports_but_not_data_or_labels);
    RUN_TEST(test_each_file_has_its_own_findings);
    RUN_TEST(test_a_damaged_table_keeps_the_findings_of_the_other);
    RUN_TEST(test_a_32_bit_file_is_not_analyzed);
    RUN_TEST(test_a_truncated_file_is_malformed);
    RUN_TEST(test_a_file_without_symbols_is_not_analyzed);
    return UNITY_END();
}
