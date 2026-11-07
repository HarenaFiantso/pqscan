/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/status.h"
#include "pqscan/flow/constant_table.h"
#include "pqscan/flow/function_mutations.h"
#include "pqscan/walk/file_type.h"
#include "scan_support.h"
#include "unity.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <tree_sitter/api.h>

enum { SOURCE_SIZE = 512 };

static char text[SOURCE_SIZE];
static parsed_source source;
static constant_table *table;

void setUp(void) {
    table = constant_table_create();
    TEST_ASSERT_NOT_NULL(table);
}

void tearDown(void) {
    constant_table_destroy(table);
    parsed_source_release(&source);
}

static void collect(const char *code, source_language language) {
    const int written = snprintf(text, sizeof(text), "%s", code);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(text));
    parsed_source_init(&source, text, language);
    const TSNode function = find_node_of_type(parsed_source_root(&source), "function_definition");
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, function_mutations_collect(&source.flow, function, table));
}

static void collect_c(const char *code) { collect(code, SOURCE_LANGUAGE_C); }

static uint32_t offset_of(const char *needle) {
    const char *found = strstr(text, needle);
    TEST_ASSERT_NOT_NULL_MESSAGE(found, needle);
    return (uint32_t)(found - text);
}

static void assert_position(const char *name, uint32_t expected) {
    const constant_binding *binding = constant_table_find(table, text_from(name));
    TEST_ASSERT_NOT_NULL_MESSAGE(binding, name);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(expected, binding->position, name);
}

static void assert_untouched(const char *name) {
    TEST_ASSERT_NULL_MESSAGE(constant_table_find(table, text_from(name)), name);
}

static void test_a_straight_line_write_stays_trusted(void) {
    collect_c("void f(void) { int a = 1; a = 2; }\n");
    assert_position("a", UINT32_MAX);
}

static void test_a_declaration_alone_is_no_mutation(void) {
    collect_c("void f(void) { int a = 1; g(a); }\n");
    assert_untouched("a");
}

static void test_a_write_in_a_branch_counts_from_there(void) {
    collect_c("void f(int x) { int a = 1; if (x) a = 2; }\n");
    assert_position("a", offset_of("a = 2"));
}

static void test_every_kind_of_branch_counts(void) {
    collect_c("void f(int x) {\n"
              "  switch (x) { case 1: a = 1; }\n"
              "  x ? (b = 1) : 0;\n"
              "  x && (c = 1);\n"
              "  x || (d = 1);\n"
              "#ifdef Y\n  e = 1;\n#endif\n"
              "}\n");
    assert_position("a", offset_of("a = 1"));
    assert_position("b", offset_of("b = 1"));
    assert_position("c", offset_of("c = 1"));
    assert_position("d", offset_of("d = 1"));
    assert_position("e", offset_of("e = 1"));
}

static void test_a_write_in_a_try_counts_from_there(void) {
    collect("void f() { try { a = 1; } catch (...) {} }\n", SOURCE_LANGUAGE_CPP);
    assert_position("a", offset_of("a = 1"));
}

static void test_a_write_in_a_loop_counts_from_the_loop(void) {
    collect_c("void f(int x) { while (x) { g(a); a = 2; } }\n");
    assert_position("a", offset_of("while"));
}

static void test_every_kind_of_loop_counts(void) {
    collect_c("void f(void) {\n"
              "  for (;;) { a = 1; }\n"
              "  do { b = 1; } while (0);\n"
              "}\n");
    assert_position("a", offset_of("for"));
    assert_position("b", offset_of("do"));
}

static void test_a_nested_loop_counts_from_the_outermost(void) {
    collect_c("void f(void) { for (;;) { while (x) { a = 1; } } }\n");
    assert_position("a", offset_of("for"));
}

static void test_the_end_of_a_loop_ends_its_effect(void) {
    collect_c("void f(void) { for (;;) { } a = 1; }\n");
    assert_position("a", UINT32_MAX);
}

static void test_compound_writes_and_updates_always_count(void) {
    collect_c("void f(void) { a += 1; b *= 2; c++; --d; }\n");
    assert_position("a", offset_of("a +="));
    assert_position("b", offset_of("b *="));
    assert_position("c", offset_of("c++"));
    assert_position("d", offset_of("--d"));
}

static void test_taking_an_address_counts_but_a_dereference_does_not(void) {
    collect_c("void f(void) { g(&a); h(*b); }\n");
    assert_position("a", offset_of("&a"));
    assert_untouched("b");
}

static void test_a_field_or_an_element_is_not_a_variable(void) {
    collect_c("void f(void) { s.a = 1; t->b = 2; c[0] = 3; (*d) = 4; }\n");
    assert_untouched("a");
    assert_untouched("b");
    assert_untouched("c");
    assert_untouched("d");
}

static void test_the_earliest_position_wins(void) {
    collect_c("void f(int x) { if (x) a = 1; a += 2; }\n");
    assert_position("a", offset_of("a = 1"));
}

static void test_a_label_makes_every_write_count_from_the_start(void) {
    collect_c("void f(void) { a = 1; b += 1; retry: if (c) goto retry; }\n");
    assert_position("a", offset_of("void"));
    assert_position("b", offset_of("void"));
}

static void test_a_label_leaves_variables_that_are_never_written(void) {
    collect_c("void f(void) { int a = 1; out: g(a); }\n");
    assert_untouched("a");
}

static void test_declarations_in_preprocessor_branches_count(void) {
    collect_c("void f(void) {\n#ifdef X\n  int a = 1;\n#else\n  int b = 2;\n#endif\n}\n");
    assert_position("a", offset_of("a = 1"));
    assert_position("b", offset_of("b = 2"));
}

static void test_declarations_in_plain_branches_do_not_count(void) {
    collect_c("void f(int x) { if (x) { int a = 1; } }\n");
    assert_untouched("a");
}

static void test_a_cpp_reference_counts_for_what_it_aliases(void) {
    collect("void f() { int a = 1; int &r = a; }\n", SOURCE_LANGUAGE_CPP);
    assert_position("a", offset_of("&r"));
}

static void test_a_cpp_call_may_change_its_arguments_after_it_returns(void) {
    collect("void f() { g(a, 1); }\n", SOURCE_LANGUAGE_CPP);
    assert_position("a", offset_of("; }"));
}

static void test_a_c_call_changes_nothing(void) {
    collect_c("void f(void) { g(a, 1); }\n");
    assert_untouched("a");
}

static void test_a_cpp_stream_read_counts(void) {
    collect("void f() { cin >> a; }\n", SOURCE_LANGUAGE_CPP);
    assert_position("a", offset_of("; }"));
}

static void test_a_shift_in_c_is_no_stream_read(void) {
    collect_c("void f(void) { int b = c >> a; }\n");
    assert_untouched("a");
}

static void test_a_write_in_a_lambda_counts_from_the_lambda(void) {
    collect("void f() { auto l = [&]() { a = 1; }; }\n", SOURCE_LANGUAGE_CPP);
    assert_position("a", offset_of("[&]"));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_a_straight_line_write_stays_trusted);
    RUN_TEST(test_a_declaration_alone_is_no_mutation);
    RUN_TEST(test_a_write_in_a_branch_counts_from_there);
    RUN_TEST(test_every_kind_of_branch_counts);
    RUN_TEST(test_a_write_in_a_try_counts_from_there);
    RUN_TEST(test_a_write_in_a_loop_counts_from_the_loop);
    RUN_TEST(test_every_kind_of_loop_counts);
    RUN_TEST(test_a_nested_loop_counts_from_the_outermost);
    RUN_TEST(test_the_end_of_a_loop_ends_its_effect);
    RUN_TEST(test_compound_writes_and_updates_always_count);
    RUN_TEST(test_taking_an_address_counts_but_a_dereference_does_not);
    RUN_TEST(test_a_field_or_an_element_is_not_a_variable);
    RUN_TEST(test_the_earliest_position_wins);
    RUN_TEST(test_a_label_makes_every_write_count_from_the_start);
    RUN_TEST(test_a_label_leaves_variables_that_are_never_written);
    RUN_TEST(test_declarations_in_preprocessor_branches_count);
    RUN_TEST(test_declarations_in_plain_branches_do_not_count);
    RUN_TEST(test_a_cpp_reference_counts_for_what_it_aliases);
    RUN_TEST(test_a_cpp_call_may_change_its_arguments_after_it_returns);
    RUN_TEST(test_a_c_call_changes_nothing);
    RUN_TEST(test_a_cpp_stream_read_counts);
    RUN_TEST(test_a_shift_in_c_is_no_stream_read);
    RUN_TEST(test_a_write_in_a_lambda_counts_from_the_lambda);
    return UNITY_END();
}
