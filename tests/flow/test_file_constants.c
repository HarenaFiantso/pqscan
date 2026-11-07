/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/status.h"
#include "pqscan/flow/constant_table.h"
#include "pqscan/flow/file_constants.h"
#include "pqscan/walk/file_type.h"
#include "scan_support.h"
#include "unity.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

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
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK,
                          file_constants_collect(&source.flow, parsed_source_root(&source), table));
}

static const constant_binding *find(const char *name) {
    return constant_table_find(table, text_from(name));
}

static void assert_kind(binding_kind expected, const char *name) {
    const constant_binding *binding = find(name);
    TEST_ASSERT_NOT_NULL_MESSAGE(binding, name);
    TEST_ASSERT_EQUAL_INT_MESSAGE(expected, binding->kind, name);
}

static void test_records_macros_and_constants(void) {
    collect("#define BITS 2048\nconst int SIZE = 1024;\nstatic const long MORE = 1;\n",
            SOURCE_LANGUAGE_C);
    assert_kind(BINDING_MACRO, "BITS");
    assert_kind(BINDING_GLOBAL, "SIZE");
    assert_kind(BINDING_GLOBAL, "MORE");
}

static void test_records_each_constant_of_a_declaration(void) {
    collect("const int A = 1, B = 2;\n", SOURCE_LANGUAGE_C);
    assert_kind(BINDING_GLOBAL, "A");
    assert_kind(BINDING_GLOBAL, "B");
}

static void test_records_constexpr_and_namespaces_in_cpp(void) {
    collect("constexpr int A = 1;\nnamespace n { const int B = 2; }\n"
            "extern \"C\" { const int C = 3; }\n",
            SOURCE_LANGUAGE_CPP);
    assert_kind(BINDING_GLOBAL, "A");
    assert_kind(BINDING_GLOBAL, "B");
    assert_kind(BINDING_GLOBAL, "C");
}

static void test_skips_globals_that_can_change(void) {
    collect("int A = 1;\nconst char *B = \"x\";\nconst volatile int C = 1;\nextern const int D;\n",
            SOURCE_LANGUAGE_C);
    TEST_ASSERT_NULL(find("A"));
    TEST_ASSERT_NULL(find("B"));
    TEST_ASSERT_NULL(find("C"));
    TEST_ASSERT_NULL(find("D"));
}

static void test_records_strings_that_cannot_change(void) {
    collect("const char *const A = \"x\";\nconst char B[] = \"y\";\nchar *const C = \"z\";\n",
            SOURCE_LANGUAGE_C);
    assert_kind(BINDING_GLOBAL, "A");
    assert_kind(BINDING_GLOBAL, "B");
    assert_kind(BINDING_GLOBAL, "C");
}

static void test_ignores_locals(void) {
    collect("void f(void) { const int A = 1; }\n", SOURCE_LANGUAGE_C);
    TEST_ASSERT_NULL(find("A"));
}

static void test_a_macro_defined_in_a_function_still_counts(void) {
    collect("void f(void) {\n#define A 1\n}\n", SOURCE_LANGUAGE_C);
    assert_kind(BINDING_MACRO, "A");
}

static void test_two_definitions_with_one_body_stay_known(void) {
    collect("#define A 1024\n#define A 1024\n", SOURCE_LANGUAGE_C);
    assert_kind(BINDING_MACRO, "A");
}

static void test_two_different_definitions_are_unknown(void) {
    collect("#define A 1024\n#define A 2048\nconst int B = 1;\nconst int B = 2;\n",
            SOURCE_LANGUAGE_C);
    assert_kind(BINDING_VALUE, "A");
    assert_kind(BINDING_VALUE, "B");
}

static void test_a_macro_and_a_constant_of_one_name_are_unknown(void) {
    collect("#define A 1\nconst int A = 1;\n", SOURCE_LANGUAGE_C);
    assert_kind(BINDING_VALUE, "A");
}

static void test_a_macro_with_parameters_is_unknown(void) {
    collect("#define A(x) (x)\n", SOURCE_LANGUAGE_C);
    assert_kind(BINDING_VALUE, "A");
}

static void test_a_macro_without_a_body_is_unknown(void) {
    collect("#define A\n", SOURCE_LANGUAGE_C);
    assert_kind(BINDING_VALUE, "A");
}

static void test_undef_makes_a_name_unknown_wherever_it_stands(void) {
    collect("#undef B\n#define A 1\n#undef A /* done */\n#define B 2\n", SOURCE_LANGUAGE_C);
    assert_kind(BINDING_VALUE, "A");
    assert_kind(BINDING_VALUE, "B");
}

static void test_other_directives_change_nothing(void) {
    collect("#define A 1\n#pragma A\n#error A\n", SOURCE_LANGUAGE_C);
    assert_kind(BINDING_MACRO, "A");
}

static void test_definitions_in_conditionals_are_unknown(void) {
    collect("#ifdef X\n#define A 1\nconst int B = 1;\n#else\n#define C 2\n#endif\n"
            "#if Y\n#define D 3\n#elif Z\n#define E 4\n#endif\n"
            "#ifndef F\n#define F 5\n#endif\n#define G 6\n",
            SOURCE_LANGUAGE_C);
    assert_kind(BINDING_VALUE, "A");
    assert_kind(BINDING_VALUE, "B");
    assert_kind(BINDING_VALUE, "C");
    assert_kind(BINDING_VALUE, "D");
    assert_kind(BINDING_VALUE, "E");
    assert_kind(BINDING_MACRO, "G");
}

static void test_an_include_guard_is_not_a_conditional(void) {
    collect("/* header */\n#ifndef A_H\n#define A_H\n#define BITS 2048\nconst int N = 1;\n"
            "#ifdef X\n#define C 1\n#endif\n#endif\n",
            SOURCE_LANGUAGE_C);
    assert_kind(BINDING_MACRO, "BITS");
    assert_kind(BINDING_GLOBAL, "N");
    assert_kind(BINDING_VALUE, "C");
}

static void test_a_lookalike_of_an_include_guard_is_a_conditional(void) {
    collect("#ifndef OTHER\n#define A 1\n#define B 2\n#endif\n", SOURCE_LANGUAGE_C);
    assert_kind(BINDING_VALUE, "A");
    assert_kind(BINDING_VALUE, "B");
}

static void test_a_default_value_is_no_include_guard(void) {
    collect("#ifndef A\n#define A 2048\n#endif\nint x;\n", SOURCE_LANGUAGE_C);
    assert_kind(BINDING_VALUE, "A");
}

static void test_code_after_an_include_guard_makes_it_a_conditional(void) {
    collect("#ifndef A_H\n#define A_H\n#define B 1\n#endif\n#define C 2\n", SOURCE_LANGUAGE_C);
    assert_kind(BINDING_VALUE, "B");
    assert_kind(BINDING_MACRO, "C");
}

static void test_a_comment_after_an_include_guard_changes_nothing(void) {
    collect("#ifndef A_H\n#define A_H\n#define B 1\n#endif\n/* A_H */\n", SOURCE_LANGUAGE_C);
    assert_kind(BINDING_MACRO, "B");
}

static void test_a_guard_with_an_else_is_a_conditional(void) {
    collect("#ifndef A\n#define A\n#define B 1\n#else\n#define C 2\n#endif\n", SOURCE_LANGUAGE_C);
    assert_kind(BINDING_VALUE, "B");
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_records_macros_and_constants);
    RUN_TEST(test_records_each_constant_of_a_declaration);
    RUN_TEST(test_records_constexpr_and_namespaces_in_cpp);
    RUN_TEST(test_skips_globals_that_can_change);
    RUN_TEST(test_records_strings_that_cannot_change);
    RUN_TEST(test_ignores_locals);
    RUN_TEST(test_a_macro_defined_in_a_function_still_counts);
    RUN_TEST(test_two_definitions_with_one_body_stay_known);
    RUN_TEST(test_two_different_definitions_are_unknown);
    RUN_TEST(test_a_macro_and_a_constant_of_one_name_are_unknown);
    RUN_TEST(test_a_macro_with_parameters_is_unknown);
    RUN_TEST(test_a_macro_without_a_body_is_unknown);
    RUN_TEST(test_undef_makes_a_name_unknown_wherever_it_stands);
    RUN_TEST(test_other_directives_change_nothing);
    RUN_TEST(test_definitions_in_conditionals_are_unknown);
    RUN_TEST(test_an_include_guard_is_not_a_conditional);
    RUN_TEST(test_a_lookalike_of_an_include_guard_is_a_conditional);
    RUN_TEST(test_a_default_value_is_no_include_guard);
    RUN_TEST(test_code_after_an_include_guard_makes_it_a_conditional);
    RUN_TEST(test_a_comment_after_an_include_guard_changes_nothing);
    RUN_TEST(test_a_guard_with_an_else_is_a_conditional);
    return UNITY_END();
}
