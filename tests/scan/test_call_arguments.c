/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/key_size.h"
#include "pqscan/core/status.h"
#include "pqscan/flow/constant_flow.h"
#include "pqscan/flow/flow_source.h"
#include "pqscan/scan/call_arguments.h"
#include "pqscan/scan/file_reader.h"
#include "pqscan/scan/syntax_parser.h"
#include "pqscan/walk/file_type.h"
#include "unity.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <tree_sitter/api.h>

enum { SOURCE_SIZE = 256, BUDGET_SECONDS = 60, KEY_BITS = 2048, OCTAL_BITS = 01000 };

static syntax_parser *parser;
static constant_flow *flow;
static TSTree *tree;
static file_contents file;
static char source[SOURCE_SIZE];

void setUp(void) {
    parser = NULL;
    flow = NULL;
    tree = NULL;
}

static void release_parser(void) {
    constant_flow_destroy(flow);
    flow = NULL;
    ts_tree_delete(tree);
    tree = NULL;
    syntax_parser_destroy(parser);
    parser = NULL;
}

void tearDown(void) { release_parser(); }

/* Parses f(<arguments>) inside a function and returns the call. */
static TSNode parse_call(source_language language, const char *arguments) {
    const int written = snprintf(source, sizeof(source), "void g(void) { f(%s); }\n", arguments);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(source));
    file.data = source;
    file.len = (size_t)written;
    const syntax_source input = {language, &file, BUDGET_SECONDS};
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, syntax_parser_create(&input, &parser));
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, syntax_parser_parse_file(parser, &tree));
    const flow_source flow_input = {&file, parser, language};
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, constant_flow_create(&flow_input, &flow));
    const TSNode function = ts_node_named_child(ts_tree_root_node(tree), 0);
    const TSNode statement = ts_node_named_child(syntax_node_field(function, "body"), 0);
    const TSNode call = ts_node_named_child(statement, 0);
    TEST_ASSERT_TRUE(syntax_node_is(call, "call_expression"));
    return call;
}

static key_size key_size_of(source_language language, const char *arguments, uint32_t index) {
    const call_argument argument = {parse_call(language, arguments), index};
    return call_key_size(&argument, flow);
}

static void assert_known_bits(unsigned expected, const char *arguments) {
    const key_size size = key_size_of(SOURCE_LANGUAGE_CPP, arguments, 1);
    TEST_ASSERT_EQUAL_INT_MESSAGE(KEY_SIZE_KNOWN, size.kind, arguments);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(expected, size.bits, arguments);
    release_parser();
}

static void assert_kind(key_size_kind expected, const char *arguments) {
    const key_size size = key_size_of(SOURCE_LANGUAGE_C, arguments, 1);
    TEST_ASSERT_EQUAL_INT_MESSAGE(expected, size.kind, arguments);
    release_parser();
}

static void test_reads_integer_literals(void) {
    assert_known_bits(KEY_BITS, "r, 2048");
    assert_known_bits(KEY_BITS, "r, 0x800");
    assert_known_bits(OCTAL_BITS, "r, 01000");
    assert_known_bits(KEY_BITS, "r, 2048U");
    assert_known_bits(KEY_BITS, "r, 2048ul");
    assert_known_bits(KEY_BITS, "r, 2'048");
}

static void test_looks_through_casts_and_parentheses(void) {
    assert_known_bits(KEY_BITS, "r, (int)2048");
    assert_known_bits(KEY_BITS, "r, ((2048))");
    assert_known_bits(KEY_BITS, "r, (unsigned)(2048u)");
}

static void test_skips_comments_between_arguments(void) {
    assert_known_bits(KEY_BITS, "/* bits next */ r, /* here */ 2048 /* done */");
    assert_known_bits(KEY_BITS, "r, ( /* odd */ 2048)");
}

static void test_computes_simple_expressions(void) {
    assert_known_bits(KEY_BITS, "r, 1 << 11");
    assert_known_bits(KEY_BITS, "r, 1024 * 2");
}

static void test_anything_it_cannot_prove_is_unknown(void) {
    assert_kind(KEY_SIZE_UNKNOWN, "r, bits");
    assert_kind(KEY_SIZE_UNKNOWN, "r, -2048");
    assert_kind(KEY_SIZE_UNKNOWN, "r, get_bits()");
}

static void test_malformed_numbers_are_unknown(void) {
    assert_kind(KEY_SIZE_UNKNOWN, "r, 2048.0");
    assert_kind(KEY_SIZE_UNKNOWN, "r, 1e3");
    assert_kind(KEY_SIZE_UNKNOWN, "r, 99999999999999999999999999");
    assert_kind(KEY_SIZE_UNKNOWN, "r, 0xFFFFFFFFFFFFFFFFFFFF");
    assert_kind(KEY_SIZE_UNKNOWN, "r, 1000000000000000000000000000000000000000000000000");
}

static void test_values_above_unsigned_are_unknown(void) {
    assert_kind(KEY_SIZE_UNKNOWN, "r, 4294967296");
}

static void test_missing_or_string_argument_has_no_key_size(void) {
    assert_kind(KEY_SIZE_NOT_APPLICABLE, "r");
    assert_kind(KEY_SIZE_NOT_APPLICABLE, "");
    assert_kind(KEY_SIZE_NOT_APPLICABLE, "r, \"P-256\"");
}

static bool read_string(TSNode call, uint32_t index, string_argument *out) {
    const call_argument argument = {call, index};
    return call_string_argument(&argument, flow, out);
}

static void test_finds_string_arguments(void) {
    const TSNode call = parse_call(SOURCE_LANGUAGE_C, "NULL, \"RSA\", NULL");
    string_argument found;
    TEST_ASSERT_TRUE(read_string(call, 1, &found));
    TEST_ASSERT_EQUAL_size_t(strlen("RSA"), found.text.len);
    TEST_ASSERT_EQUAL_MEMORY("RSA", found.text.data, found.text.len);
}

static void test_refuses_other_string_shapes(void) {
    const TSNode call = parse_call(SOURCE_LANGUAGE_C, "\"\", \"R\\x53\", \"R\" \"SA\", name");
    string_argument found;
    TEST_ASSERT_FALSE(read_string(call, 0, &found));
    TEST_ASSERT_FALSE(read_string(call, 1, &found));
    TEST_ASSERT_FALSE(read_string(call, 2, &found));
    TEST_ASSERT_FALSE(read_string(call, 3, &found));
    TEST_ASSERT_FALSE(read_string(call, 4, &found));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_reads_integer_literals);
    RUN_TEST(test_looks_through_casts_and_parentheses);
    RUN_TEST(test_skips_comments_between_arguments);
    RUN_TEST(test_computes_simple_expressions);
    RUN_TEST(test_anything_it_cannot_prove_is_unknown);
    RUN_TEST(test_malformed_numbers_are_unknown);
    RUN_TEST(test_values_above_unsigned_are_unknown);
    RUN_TEST(test_missing_or_string_argument_has_no_key_size);
    RUN_TEST(test_finds_string_arguments);
    RUN_TEST(test_refuses_other_string_shapes);
    return UNITY_END();
}
