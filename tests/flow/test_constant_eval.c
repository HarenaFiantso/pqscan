/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/flow/constant_eval.h"
#include "pqscan/flow/constant_table.h"
#include "pqscan/scan/syntax_parser.h"
#include "pqscan/walk/file_type.h"
#include "scan_support.h"
#include "unity.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <tree_sitter/api.h>

enum {
    SOURCE_SIZE = 256,
    BOUND_VALUE = 7,
    LATE_VALUE = 9,
    DOUBLED_VALUE = BOUND_VALUE * 2,
    SMALL_KEY = 1024,
    KEY_BITS = 2048,
    KEY_BITS_PLUS_ONE = 2049,
    MEDIUM_KEY = 3072,
    LARGE_KEY = 4096,
};

static char text[SOURCE_SIZE];
static parsed_source source;
static constant_table *bindings;
static constant_table *mutations;

void setUp(void) {
    bindings = constant_table_create();
    mutations = constant_table_create();
    TEST_ASSERT_NOT_NULL(bindings);
    TEST_ASSERT_NOT_NULL(mutations);
}

void tearDown(void) {
    constant_table_destroy(mutations);
    constant_table_destroy(bindings);
}

/* Evaluates the expression in int x = <expression>; */
static constant_value eval(const char *expression) {
    const int written = snprintf(text, sizeof(text), "int x = %s;\n", expression);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(text));
    parsed_source_init(&source, text, SOURCE_LANGUAGE_C);
    const TSNode declarator = find_node_of_type(parsed_source_root(&source), "init_declarator");
    const eval_env env = {&source.flow, bindings, mutations, false};
    const constant_value value = constant_eval(&env, syntax_node_field(declarator, "value"));
    parsed_source_release(&source);
    return value;
}

static void bind_value(const char *name, uint64_t integer) {
    constant_binding binding;
    memset(&binding, 0, sizeof(binding));
    binding.name = text_from(name);
    binding.value.kind = CONSTANT_INTEGER;
    binding.value.integer = integer;
    constant_table_bind(bindings, &binding);
}

static void assert_integer(uint64_t expected, const char *expression) {
    const constant_value value = eval(expression);
    TEST_ASSERT_EQUAL_INT_MESSAGE(CONSTANT_INTEGER, value.kind, expression);
    TEST_ASSERT_EQUAL_UINT64_MESSAGE(expected, value.integer, expression);
}

static void assert_unknown(const char *expression) {
    TEST_ASSERT_EQUAL_INT_MESSAGE(CONSTANT_UNKNOWN, eval(expression).kind, expression);
}

static void test_reads_integer_literals(void) {
    assert_integer(KEY_BITS, "2048");
    assert_integer(KEY_BITS, "0x800");
    assert_integer(KEY_BITS, "2048UL");
    assert_integer(UINT64_MAX, "0xFFFFFFFFFFFFFFFF");
}

static void test_reads_plain_strings(void) {
    const constant_value value = eval("\"RSA\"");
    TEST_ASSERT_EQUAL_INT(CONSTANT_STRING, value.kind);
    TEST_ASSERT_EQUAL_MEMORY("RSA", value.text.data, value.text.len);
}

static void test_refuses_strings_it_cannot_read(void) {
    assert_unknown("\"\"");
    assert_unknown("\"R\\x53\"");
    assert_unknown("\"R\" \"SA\"");
}

static void test_computes_the_four_operators(void) {
    assert_integer(MEDIUM_KEY, "2048 + 1024");
    assert_integer(SMALL_KEY, "2048 - 1024");
    assert_integer(LARGE_KEY, "2048 * 2");
    assert_integer(KEY_BITS, "1 << 11");
}

static void test_respects_precedence_and_parentheses(void) {
    assert_integer(KEY_BITS_PLUS_ONE, "1 + 2 * 1024");
    assert_integer(LARGE_KEY, "(1 + 1) * 2048");
    assert_integer(KEY_BITS, "(size_t)(1024 * 2)");
}

static void test_refuses_other_operators(void) {
    assert_unknown("4096 / 2");
    assert_unknown("4096 % 7");
    assert_unknown("4096 >> 1");
    assert_unknown("4096 | 1");
    assert_unknown("-2048");
    assert_unknown("-1");
    assert_unknown("+1");
    assert_unknown("~0");
    assert_unknown("x ? 1 : 2");
    assert_unknown("sizeof(int)");
    assert_unknown("get_bits()");
}

static void test_refuses_every_overflow(void) {
    assert_unknown("18446744073709551615 + 1");
    assert_unknown("1024 - 2048");
    assert_unknown("4294967296 * 4294967296");
    assert_unknown("1 << 64");
    assert_unknown("1 << 1000");
    assert_unknown("2 << 63");
}

static void test_an_operator_with_an_unknown_side_is_unknown(void) {
    assert_unknown("x + 1");
    assert_unknown("1 + x");
    assert_unknown("\"a\" + 1");
}

static void test_reads_bound_names(void) {
    bind_value("n", BOUND_VALUE);
    assert_integer(BOUND_VALUE, "n");
    assert_integer(DOUBLED_VALUE, "n * 2");
    assert_unknown("m");
}

static void test_a_mutation_stops_trust_from_its_position(void) {
    bind_value("n", BOUND_VALUE);
    constant_binding mutation;
    memset(&mutation, 0, sizeof(mutation));
    mutation.name = text_from("n");
    mutation.position = 0;
    constant_table_bind(mutations, &mutation);
    assert_unknown("n");
}

static void test_a_later_mutation_does_not_matter_yet(void) {
    bind_value("n", BOUND_VALUE);
    constant_binding mutation;
    memset(&mutation, 0, sizeof(mutation));
    mutation.name = text_from("n");
    mutation.position = SOURCE_SIZE;
    constant_table_bind(mutations, &mutation);
    assert_integer(BOUND_VALUE, "n");
}

static void test_a_full_table_makes_every_name_unknown(void) {
    bind_value("n", BOUND_VALUE);
    for (int i = 0; i <= CONSTANT_TABLE_MAX_BINDINGS; i++) {
        bind_value("filler", LATE_VALUE);
    }
    assert_unknown("n");
    assert_integer(KEY_BITS, "2048");
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_reads_integer_literals);
    RUN_TEST(test_reads_plain_strings);
    RUN_TEST(test_refuses_strings_it_cannot_read);
    RUN_TEST(test_computes_the_four_operators);
    RUN_TEST(test_respects_precedence_and_parentheses);
    RUN_TEST(test_refuses_other_operators);
    RUN_TEST(test_refuses_every_overflow);
    RUN_TEST(test_an_operator_with_an_unknown_side_is_unknown);
    RUN_TEST(test_reads_bound_names);
    RUN_TEST(test_a_mutation_stops_trust_from_its_position);
    RUN_TEST(test_a_later_mutation_does_not_matter_yet);
    RUN_TEST(test_a_full_table_makes_every_name_unknown);
    return UNITY_END();
}
