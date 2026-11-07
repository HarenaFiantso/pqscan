/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/finding.h"
#include "pqscan/core/key_size.h"
#include "pqscan/core/status.h"
#include "pqscan/risk/risk.h"
#include "pqscan/rules/default_rules.h"
#include "pqscan/rules/rule_loader.h"
#include "pqscan/rules/rule_set.h"
#include "pqscan/scan/file_reader.h"
#include "pqscan/scan/scanner.h"
#include "pqscan/scan/source_scanner.h"
#include "scan_support.h"
#include "unity.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    DESCRIPTION_SIZE = 256,
    SOURCE_SIZE = 1024,
    MACRO_LEVELS = 40,
    DEEP_CHAIN = 100,
    DEEP_NESTING = 20000,
    LINE_SIZE = 64,
    DOUBLING_TEXT_SIZE = (MACRO_LEVELS + 1) * LINE_SIZE,
    CHAIN_TEXT_SIZE = (DEEP_CHAIN + 1) * LINE_SIZE,
};

/* KEY(n) in the snippets below stands for this call. */
#define KEY(n) "RSA_generate_key_ex(r, " n ", 0, 0);"

static finding_list *findings;
static rule_set *rules;

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

static pqscan_status scan_in(const char *path, char *text) {
    const file_contents file = {text, strlen(text)};
    const scan_input input = {path, &file, rules};
    return source_scanner.scan(&input, findings);
}

static void assert_scan(const char *path, const char *code, const char *expected) {
    char text[SOURCE_SIZE];
    const int written = snprintf(text, sizeof(text), "%s", code);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(text));
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, scan_in(path, text));
    char actual[DESCRIPTION_SIZE];
    describe_findings(findings, actual, sizeof(actual));
    TEST_ASSERT_EQUAL_STRING_MESSAGE(expected, actual, code);
    finding_list_destroy(findings);
    findings = finding_list_create();
    TEST_ASSERT_NOT_NULL(findings);
}

static void assert_c(const char *code, const char *expected) { assert_scan("a.c", code, expected); }

static void assert_cpp(const char *code, const char *expected) {
    assert_scan("a.cpp", code, expected);
}

static void test_a_local_carries_its_value(void) {
    assert_c("void f(void) { int bits = 2048; " KEY("bits") " }", "1:RSA-2048");
    assert_c("void f(void) { const int bits = 1024; " KEY("bits") " }", "1:RSA-1024");
    assert_c("void f(void) { int a = 2048, b = a; " KEY("b") " }", "1:RSA-2048");
}

static void test_a_local_set_after_its_declaration_carries_its_value(void) {
    assert_c("void f(void) { int bits; bits = 2048; " KEY("bits") " }", "1:RSA-2048");
}

static void test_straight_line_writes_are_followed(void) {
    assert_c("void f(void) { int b = 1024; " KEY("b") " b = 2048; " KEY("b") " }",
             "1:RSA-1024 1:RSA-2048");
    assert_c("void f(void) { int b = 1024; b = b * 2; " KEY("b") " }", "1:RSA-2048");
}

static void test_a_macro_flows_through_a_local(void) {
    assert_c("#define KEY_BITS 4096\nvoid f(void) { int bits = KEY_BITS; " KEY("bits") " }",
             "2:RSA-4096");
}

static void test_expressions_mix_names_and_literals(void) {
    assert_c("#define BASE 1024\nvoid f(void) { int n = 2; " KEY("BASE * n") " }", "2:RSA-2048");
    assert_c("const int SHIFT = 11;\nvoid f(void) { " KEY("1 << SHIFT") " }", "2:RSA-2048");
}

static void test_a_parameter_is_unknown(void) {
    assert_c("void f(int bits) { " KEY("bits") " }", "1:RSA-unknown");
}

static void test_a_declaration_without_a_value_is_unknown(void) {
    assert_c("void f(void) { int bits; " KEY("bits") " }", "1:RSA-unknown");
}

static void test_a_value_from_a_call_is_unknown(void) {
    assert_c("void f(void) { int bits = get(); " KEY("bits") " }", "1:RSA-unknown");
}

static void test_a_write_in_a_branch_loses_the_value_from_there(void) {
    assert_c("void f(int x) { int b = 2048; " KEY("b") " if (x) b = 1024; " KEY("b") " }",
             "1:RSA-2048 1:RSA-unknown");
    assert_c("void f(int x) { int b = 2048; if (x) { b = 1024; } else { b = 4096; } " KEY("b") " }",
             "1:RSA-unknown");
}

static void test_a_write_in_a_loop_loses_the_value_before_it_too(void) {
    assert_c("void f(int x) { int b = 2048; while (x) { " KEY("b") " b = 1024; } }",
             "1:RSA-unknown");
    assert_c("void f(int x) { int b = 2048; " KEY("b") " while (x) { b = 1024; } }", "1:RSA-2048");
}

static void test_a_loop_that_writes_nothing_keeps_the_value(void) {
    assert_c("void f(int x) { int b = 2048; while (x) { " KEY("b") " } }", "1:RSA-2048");
    assert_c("void f(int x) { while (x) { int b = 2048; " KEY("b") " } }", "1:RSA-2048");
}

static void test_changes_other_than_writes_lose_the_value(void) {
    assert_c("void f(void) { int b = 2048; b += 8; " KEY("b") " }", "1:RSA-unknown");
    assert_c("void f(void) { int b = 2048; b++; " KEY("b") " }", "1:RSA-unknown");
    assert_c("void f(void) { int b = 2048; g(&b); " KEY("b") " }", "1:RSA-unknown");
    assert_c("void f(void) { int b = 2048; int *p = &b; *p = 1; " KEY("b") " }", "1:RSA-unknown");
}

static void test_use_before_the_address_is_taken_stays_known(void) {
    assert_c("void f(void) { int b = 2048; " KEY("b") " g(&b); }", "1:RSA-2048");
}

static void test_a_label_loses_every_written_variable(void) {
    assert_c("void f(int x) { int b = 2048; b = 1024; again: " KEY("b") " if (x) goto again; }",
             "1:RSA-unknown");
    assert_c("void f(int x) { int b = 2048; again: " KEY("b") " if (x) goto again; }",
             "1:RSA-2048");
}

static void test_static_volatile_and_extern_locals_are_unknown(void) {
    assert_c("void f(void) { static int b = 2048; " KEY("b") " b = 1; }", "1:RSA-unknown");
    assert_c("void f(void) { volatile int b = 2048; " KEY("b") " }", "1:RSA-unknown");
    assert_c("void f(void) { extern int b; " KEY("b") " }", "1:RSA-unknown");
    assert_c("void f(void) { static const int b = 2048; " KEY("b") " }", "1:RSA-2048");
}

static void test_locals_hide_constants(void) {
    assert_c("const int N = 2048;\nvoid f(int N) { " KEY("N") " }", "2:RSA-unknown");
    assert_c("const int N = 2048;\nvoid f(void) { int N = 1024; " KEY("N") " }", "2:RSA-1024");
    assert_c("const int N = 2048;\nvoid f(void) { int N = g(); " KEY("N") " }", "2:RSA-unknown");
}

static void test_a_block_hides_a_local_only_until_it_ends(void) {
    assert_c("void f(void) { int b = 1024; { int b = 2048; " KEY("b") " } " KEY("b") " }",
             "1:RSA-2048 1:RSA-1024");
}

static void test_a_loop_variable_ends_with_its_loop(void) {
    assert_c("const int i = 2048;\nvoid f(void) { for (int i = 1; i; ) {} " KEY("i") " }",
             "2:RSA-2048");
}

static void test_a_local_does_not_outlive_its_function(void) {
    assert_c("void f(void) { int b = 2048; }\nvoid g(void) { " KEY("b") " }", "2:RSA-unknown");
    assert_c("void f(int x) { if (x) a = 1; }\nvoid g(void) { int a = 2048; " KEY("a") " }",
             "2:RSA-2048");
}

static void test_a_global_that_is_not_constant_is_unknown(void) {
    assert_c("int bits = 2048;\nvoid f(void) { " KEY("bits") " }", "2:RSA-unknown");
}

static void test_constants_build_on_each_other(void) {
    assert_c("#define A 1024\nconst int B = A * 2;\nconst int C = B + B;\n"
             "void f(void) { " KEY("C") " }",
             "4:RSA-4096");
}

static void test_the_initializer_of_a_constant_sees_no_locals(void) {
    assert_c("const int A = 1024;\nconst int B = A * 2;\nvoid f(void) { int A = 1; " KEY("B") " }",
             "3:RSA-2048");
}

static void test_macros_expand_in_the_scope_of_their_use(void) {
    assert_c("#define B (n * 2)\nvoid f(void) { int n = 1024; " KEY("B") " }", "2:RSA-2048");
    assert_c("#define B (A * 2)\n#define A 1024\nvoid f(void) { " KEY("B") " }", "3:RSA-2048");
}

static void test_a_name_means_nothing_before_its_definition(void) {
    assert_c("void f(void) { " KEY("N") " }\n#define N 2048\n", "1:RSA-unknown");
    assert_c("void f(void) { " KEY("N") " }\nconst int N = 2048;\n", "1:RSA-unknown");
}

static void test_macros_that_cannot_be_trusted_are_unknown(void) {
    assert_c("#define N(x) 2048\nvoid f(void) { " KEY("N") " }", "2:RSA-unknown");
    assert_c("#define N 2048\n#undef N\nvoid f(void) { " KEY("N") " }", "3:RSA-unknown");
    assert_c("#ifdef X\n#define N 1024\n#else\n#define N 4096\n#endif\n"
             "void f(void) { " KEY("N") " }",
             "6:RSA-unknown");
    assert_c("#ifndef N\n#define N 2048\n#endif\nvoid f(void) { " KEY("N") " }", "4:RSA-unknown");
}

static void test_macro_bodies_must_be_one_whole_expression(void) {
    assert_c("#define N 1024 +\nvoid f(void) { " KEY("N") " }", "2:RSA-unknown");
    assert_c("#define N 1024 2048\nvoid f(void) { " KEY("N") " }", "2:RSA-unknown");
    assert_c("#define N 2048;\nvoid f(void) { " KEY("N") " }", "2:RSA-unknown");
    assert_c("#define N\nvoid f(void) { " KEY("N") " }", "2:RSA-unknown");
}

static void test_macro_bodies_may_end_in_a_comment(void) {
    assert_c("#define N 2048 /* bits */\nvoid f(void) { " KEY("N") " }", "2:RSA-2048");
    assert_c("#define N 2048 // bits\nvoid f(void) { " KEY("N") " }", "2:RSA-2048");
    assert_c("#define N (2048)   \nvoid f(void) { " KEY("N") " }", "2:RSA-2048");
}

static void test_macros_that_refer_to_themselves_are_unknown(void) {
    assert_c("#define N N\nvoid f(void) { " KEY("N") " }", "2:RSA-unknown");
    assert_c("#define A B\n#define B A\nvoid f(void) { " KEY("A") " }", "3:RSA-unknown");
    assert_c("#define N (N + 1)\nvoid f(void) { " KEY("N") " }", "2:RSA-unknown");
}

static void test_code_in_a_macro_body_sees_earlier_macros(void) {
    assert_c("#define BITS 2048\n#define GEN(r) " KEY("BITS"), "2:RSA-2048");
}

static void test_macro_parameters_hide_macros(void) {
    assert_c("#define BITS 2048\n#define GEN(r, BITS) " KEY("BITS"), "2:RSA-unknown");
}

static void test_code_in_a_macro_body_trusts_nothing_a_local_could_hide(void) {
    assert_c("const int N = 2048;\n#define GEN(r) " KEY("N"), "2:RSA-unknown");
    assert_c("void f(void) { int n = 2048;\n#define GEN(r) " KEY("n") "\n}", "2:RSA-unknown");
}

static void test_a_macro_parameter_ends_with_its_macro(void) {
    assert_c("#define BITS 2048\n#define GEN(BITS) (BITS)\nvoid f(void) { " KEY("BITS") " }",
             "3:RSA-2048");
}

static void test_strings_flow_like_integers(void) {
    assert_c("void f(void) { const char *a = \"RSA\"; EVP_PKEY_CTX_new_from_name(0, a, 0); }",
             "1:RSA");
    assert_c("#define ALG \"RSA\"\nvoid f(void) { EVP_PKEY_CTX_new_from_name(0, ALG, 0); }",
             "2:RSA");
    assert_c("const char *const A = \"md5\";\nvoid f(void) { EVP_MD_fetch(0, A, 0); }", "2:MD5");
    assert_c("const char A[] = \"md5\";\nvoid f(void) { EVP_MD_fetch(0, A, 0); }", "2:MD5");
    assert_c("void f(void) { const char a[] = \"md5\"; EVP_MD_fetch(0, a, 0); }", "1:MD5");
}

static void test_a_resolved_string_reports_the_line_of_the_argument(void) {
    assert_c("void f(void) {\n  const char *a = \"RSA\";\n"
             "  EVP_PKEY_CTX_new_from_name(0,\n    a, 0);\n}",
             "4:RSA");
}

static void test_a_string_and_a_size_can_both_resolve(void) {
    assert_c("void f(void) { const char *a = \"RSA\"; int n = 1024;\n"
             "  EVP_PKEY_Q_keygen(0, 0, a, (size_t)n); }",
             "2:RSA-1024");
}

static void test_strings_that_can_change_are_not_trusted(void) {
    assert_c("void f(int x) { const char *a = \"RSA\"; if (x) a = \"EC\";"
             " EVP_PKEY_CTX_new_from_name(0, a, 0); }",
             "");
    assert_c("const char *A = \"RSA\";\nvoid f(void) { EVP_PKEY_CTX_new_from_name(0, A, 0); }", "");
    assert_c("void f(void) { char a[] = \"md5\"; g(a); EVP_MD_fetch(0, a, 0); }", "");
}

static void test_a_reassigned_string_follows_the_last_write(void) {
    assert_c("void f(void) { const char *a = \"RSA\"; a = \"md5\"; EVP_MD_fetch(0, a, 0); }",
             "1:MD5");
}

static void test_a_string_is_no_key_size_and_a_size_is_no_string(void) {
    assert_c("void f(void) { const char *c = \"P-256\"; EVP_PKEY_Q_keygen(0, 0, \"EC\", c); }",
             "1:EC");
    assert_c("void f(void) { int n = 2048; EVP_PKEY_CTX_new_from_name(0, n, 0); }", "");
}

static void test_a_cpp_reference_loses_what_it_aliases(void) {
    assert_cpp("void f() { int b = 2048; int &r = b; r = 1024; " KEY("b") " }", "1:RSA-unknown");
}

static void test_a_reference_itself_is_unknown(void) {
    assert_cpp("void f(int a) { int &r = a; " KEY("r") " }", "1:RSA-unknown");
    assert_cpp("void f(int &n) { " KEY("n") " }", "1:RSA-unknown");
}

static void test_a_cpp_call_loses_its_arguments_afterwards(void) {
    assert_cpp("void f() { int b = 2048; g(b); " KEY("b") " }", "1:RSA-unknown");
    assert_c("void f(void) { int b = 2048; g(b); " KEY("b") " }", "1:RSA-2048");
}

static void test_a_cpp_call_still_reads_the_value_it_is_given(void) {
    assert_cpp("void f() { int b = 2048; " KEY("b") " " KEY("b") " }", "1:RSA-2048 1:RSA-unknown");
}

static void test_a_cpp_stream_read_loses_the_value(void) {
    assert_cpp("void f() { int b = 2048; std::cin >> b; " KEY("b") " }", "1:RSA-unknown");
}

static void test_a_lambda_that_writes_loses_the_value(void) {
    assert_cpp("void f() { int b = 2048; auto l = [&]() { b = 1; }; l(); " KEY("b") " }",
               "1:RSA-unknown");
}

static void test_a_lambda_at_file_scope_is_analyzed_too(void) {
    assert_cpp("auto l = []() { int b = 2048; while (x) { " KEY("b") " b = 1; } };",
               "1:RSA-unknown");
}

static void test_a_condition_declaration_ends_with_its_statement(void) {
    assert_cpp("void f(int b) { if (int b = 2048) { } " KEY("b") " }", "1:RSA-unknown");
}

static void test_a_range_loop_variable_hides_a_constant(void) {
    assert_cpp("const int b = 2048;\nvoid f() { for (int b : xs) { " KEY("b") " } }",
               "2:RSA-unknown");
}

static void test_constexpr_counts_as_a_constant(void) {
    assert_cpp("constexpr int N = 2048;\nvoid f() { " KEY("N") " }", "2:RSA-2048");
    assert_cpp("void f() { constexpr int n = 2048; " KEY("n") " }", "1:RSA-2048");
}

static void test_declarations_in_preprocessor_branches_are_unknown(void) {
    assert_c("void f(void) {\n#ifdef X\n  int b = 1024;\n#else\n  int b = 2048;\n#endif\n"
             "  " KEY("b") "\n}",
             "7:RSA-unknown");
}

static void test_short_keys_found_through_names_are_classically_weak(void) {
    char text[] = "#define KEY_BITS 1024\nvoid f(void) { " KEY("KEY_BITS") " }";
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, scan_in("a.c", text));
    TEST_ASSERT_EQUAL_INT(RISK_CLASSICALLY_WEAK, finding_list_get(findings, 0)->risk);
}

static char *allocate_text(size_t size) {
    char *text = malloc(size);
    TEST_ASSERT_NOT_NULL(text);
    return text;
}

static void assert_call_at_end_is_unknown(char *text) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, scan_in("a.c", text));
    TEST_ASSERT_EQUAL_size_t(1, finding_list_count(findings));
    TEST_ASSERT_EQUAL_INT(KEY_SIZE_UNKNOWN, finding_list_get(findings, 0)->size.kind);
    free(text);
}

/* Each macro uses the previous one twice, which naive expansion pays for 2^40 times. */
static void test_macros_that_double_stay_fast(void) {
    const size_t size = DOUBLING_TEXT_SIZE;
    char *text = allocate_text(size);
    size_t used = (size_t)snprintf(text, size, "#define M0 1\n");
    for (int i = 1; i < MACRO_LEVELS; i++) {
        used += (size_t)snprintf(text + used, size - used, "#define M%d (M%d + M%d)\n", i, i - 1,
                                 i - 1);
    }
    (void)snprintf(text + used, size - used, "void f(void) { " KEY("M%d") " }\n", MACRO_LEVELS - 1);
    assert_call_at_end_is_unknown(text);
}

static void test_a_long_macro_chain_stops_at_the_limit(void) {
    const size_t size = CHAIN_TEXT_SIZE;
    char *text = allocate_text(size);
    size_t used = (size_t)snprintf(text, size, "#define M0 2048\n");
    for (int i = 1; i < DEEP_CHAIN; i++) {
        used += (size_t)snprintf(text + used, size - used, "#define M%d M%d\n", i, i - 1);
    }
    (void)snprintf(text + used, size - used, "void f(void) { " KEY("M%d") " }\n", DEEP_CHAIN - 1);
    assert_call_at_end_is_unknown(text);
}

static void test_survives_deep_block_nesting(void) {
    const size_t depth = DEEP_NESTING;
    const size_t size = (depth * 2) + LINE_SIZE;
    char *text = allocate_text(size);
    size_t used = (size_t)snprintf(text, size, "void f(void) ");
    memset(text + used, '{', depth);
    used += depth;
    memset(text + used, '}', depth);
    text[used + depth] = '\0';
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, scan_in("a.c", text));
    free(text);
}

static void test_survives_every_truncation(void) {
    static char code[] = "#define A 1024\nconst int B = A * 2;\n"
                         "void f(int x) { int b = B; if (x) { b = 1; } " KEY("b") " }\n";
    const size_t len = strlen(code);
    for (size_t cut = 0; cut < len; cut++) {
        const char saved = code[cut];
        code[cut] = '\0';
        TEST_ASSERT_EQUAL_INT(PQSCAN_OK, scan_in("a.cpp", code));
        code[cut] = saved;
    }
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_a_local_carries_its_value);
    RUN_TEST(test_a_local_set_after_its_declaration_carries_its_value);
    RUN_TEST(test_straight_line_writes_are_followed);
    RUN_TEST(test_a_macro_flows_through_a_local);
    RUN_TEST(test_expressions_mix_names_and_literals);
    RUN_TEST(test_a_parameter_is_unknown);
    RUN_TEST(test_a_declaration_without_a_value_is_unknown);
    RUN_TEST(test_a_value_from_a_call_is_unknown);
    RUN_TEST(test_a_write_in_a_branch_loses_the_value_from_there);
    RUN_TEST(test_a_write_in_a_loop_loses_the_value_before_it_too);
    RUN_TEST(test_a_loop_that_writes_nothing_keeps_the_value);
    RUN_TEST(test_changes_other_than_writes_lose_the_value);
    RUN_TEST(test_use_before_the_address_is_taken_stays_known);
    RUN_TEST(test_a_label_loses_every_written_variable);
    RUN_TEST(test_static_volatile_and_extern_locals_are_unknown);
    RUN_TEST(test_locals_hide_constants);
    RUN_TEST(test_a_block_hides_a_local_only_until_it_ends);
    RUN_TEST(test_a_loop_variable_ends_with_its_loop);
    RUN_TEST(test_a_local_does_not_outlive_its_function);
    RUN_TEST(test_a_global_that_is_not_constant_is_unknown);
    RUN_TEST(test_constants_build_on_each_other);
    RUN_TEST(test_the_initializer_of_a_constant_sees_no_locals);
    RUN_TEST(test_macros_expand_in_the_scope_of_their_use);
    RUN_TEST(test_a_name_means_nothing_before_its_definition);
    RUN_TEST(test_macros_that_cannot_be_trusted_are_unknown);
    RUN_TEST(test_macro_bodies_must_be_one_whole_expression);
    RUN_TEST(test_macro_bodies_may_end_in_a_comment);
    RUN_TEST(test_macros_that_refer_to_themselves_are_unknown);
    RUN_TEST(test_code_in_a_macro_body_sees_earlier_macros);
    RUN_TEST(test_macro_parameters_hide_macros);
    RUN_TEST(test_code_in_a_macro_body_trusts_nothing_a_local_could_hide);
    RUN_TEST(test_a_macro_parameter_ends_with_its_macro);
    RUN_TEST(test_strings_flow_like_integers);
    RUN_TEST(test_a_resolved_string_reports_the_line_of_the_argument);
    RUN_TEST(test_a_string_and_a_size_can_both_resolve);
    RUN_TEST(test_strings_that_can_change_are_not_trusted);
    RUN_TEST(test_a_reassigned_string_follows_the_last_write);
    RUN_TEST(test_a_string_is_no_key_size_and_a_size_is_no_string);
    RUN_TEST(test_a_cpp_reference_loses_what_it_aliases);
    RUN_TEST(test_a_reference_itself_is_unknown);
    RUN_TEST(test_a_cpp_call_loses_its_arguments_afterwards);
    RUN_TEST(test_a_cpp_call_still_reads_the_value_it_is_given);
    RUN_TEST(test_a_cpp_stream_read_loses_the_value);
    RUN_TEST(test_a_lambda_that_writes_loses_the_value);
    RUN_TEST(test_a_lambda_at_file_scope_is_analyzed_too);
    RUN_TEST(test_a_condition_declaration_ends_with_its_statement);
    RUN_TEST(test_a_range_loop_variable_hides_a_constant);
    RUN_TEST(test_constexpr_counts_as_a_constant);
    RUN_TEST(test_declarations_in_preprocessor_branches_are_unknown);
    RUN_TEST(test_short_keys_found_through_names_are_classically_weak);
    RUN_TEST(test_macros_that_double_stay_fast);
    RUN_TEST(test_a_long_macro_chain_stops_at_the_limit);
    RUN_TEST(test_survives_deep_block_nesting);
    RUN_TEST(test_survives_every_truncation);
    return UNITY_END();
}
