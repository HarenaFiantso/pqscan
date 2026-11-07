/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/finding.h"
#include "pqscan/core/primitive.h"
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

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    HUGE_LINE_SIZE = 1024 * 1024,
    EXPECTED_LINE = 4,
    DESCRIPTION_SIZE = 256,
    DEEP_NESTING = 20000,
    RANDOM_INPUT_SIZE = 4096,
    RANDOM_ROUNDS = 50,
};

/* A linear congruential generator, so that every run tests the same bytes. */
static const uint32_t RANDOM_SEED = 2048;
static const uint32_t RANDOM_MULTIPLIER = 1664525;
static const uint32_t RANDOM_INCREMENT = 1013904223;
static const uint32_t RANDOM_SHIFT = 24;

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

static pqscan_status scan_bytes(char *data, size_t len) {
    const file_contents file = {data, len};
    const scan_input input = {"a.c", &file, rules};
    return source_scanner.scan(&input, findings);
}

static void scan_text(char *text) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, scan_bytes(text, strlen(text)));
}

static void assert_finding_count(size_t expected) {
    TEST_ASSERT_EQUAL_size_t(expected, finding_list_count(findings));
}

static void test_records_what_matched(void) {
    char text[] = "void f(void) {\n"
                  "    RSA_new();\n"
                  "    EVP_PKEY_CTX_new_from_name(0, \"rsa\", 0);\n"
                  "}\n";
    scan_text(text);
    TEST_ASSERT_EQUAL_size_t(2, finding_list_count(findings));
    TEST_ASSERT_EQUAL_STRING("RSA_new", finding_list_get(findings, 0)->symbol);
    TEST_ASSERT_EQUAL_STRING("RSA", finding_list_get(findings, 1)->symbol);
}

static void assert_findings(const char *expected) {
    char actual[DESCRIPTION_SIZE];
    describe_findings(findings, actual, sizeof(actual));
    TEST_ASSERT_EQUAL_STRING(expected, actual);
}

static void test_accepts_only_source_files(void) {
    TEST_ASSERT_TRUE(source_scanner.accepts("a.c"));
    TEST_ASSERT_FALSE(source_scanner.accepts("a.txt"));
}

static void test_empty_file_has_no_findings(void) {
    scan_text("");
    assert_finding_count(0);
}

static void test_reports_path_line_algorithm_and_risk(void) {
    scan_text("\n\n\nRSA *r = RSA_new();\n");
    assert_finding_count(1);
    const finding *item = finding_list_get(findings, 0);
    TEST_ASSERT_EQUAL_STRING("a.c", item->path);
    TEST_ASSERT_EQUAL_size_t(EXPECTED_LINE, item->line);
    TEST_ASSERT_EQUAL_STRING("RSA", item->algorithm);
    TEST_ASSERT_EQUAL_INT(RISK_QUANTUM_VULNERABLE, item->risk);
}

static void test_counts_lines_with_crlf_endings(void) {
    scan_text("\r\n\r\n\r\nDH_new();\r\n");
    TEST_ASSERT_EQUAL_size_t(EXPECTED_LINE, finding_list_get(findings, 0)->line);
}

static void test_reports_each_match_on_a_line(void) {
    scan_text("EVP_md5(); EVP_sha1();\n");
    assert_finding_count(2);
    TEST_ASSERT_EQUAL_STRING("MD5", finding_list_get(findings, 0)->algorithm);
    TEST_ASSERT_EQUAL_STRING("SHA-1", finding_list_get(findings, 1)->algorithm);
}

static void test_matches_at_the_edges_of_the_file(void) {
    scan_text("RSA_new");
    assert_finding_count(1);
}

static void test_skips_longer_identifiers(void) {
    scan_text("MY_RSA_new RSA_new_x xRSA_new _RSA_new RSA_new1\n");
    assert_finding_count(0);
}

static void test_non_utf8_bytes_separate_identifiers(void) {
    scan_text("\xE9RSA_new\xFF\n");
    assert_finding_count(1);
}

static void scan_cpp_text(const char *text) {
    const file_contents file = {(char *)text, strlen(text)};
    const scan_input input = {"a.cpp", &file, rules};
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, source_scanner.scan(&input, findings));
}

static void test_ignores_comments(void) {
    scan_text("/* RSA_new */\n// DSA_new()\nint a; /* DH_new */\n");
    assert_finding_count(0);
}

static void test_ignores_strings_outside_known_calls(void) {
    scan_text("const char *s = \"DSA_new\";\n"
              "void f(void) { puts(\"RSA_new\"); other(NULL, \"RSA\", NULL); }\n");
    assert_finding_count(0);
}

static void test_ignores_declarations_of_a_name(void) {
    scan_text("RSA *RSA_new(void);\n"
              "RSA *RSA_new(void) { return 0; }\n"
              "int (DSA_new)(void);\n"
              "void f(int RSA_sign, int DSA_sign[4]);\n"
              "int RSA_verify = 1;\n"
              "enum { EVP_PKEY_RSA = 6 };\n"
              "#define DH_new other\n"
              "#define WRAP(EVP_md5) 1\n"
              "#ifdef EVP_PKEY_DSA\n#endif\n"
              "#ifndef EVP_PKEY_DH\n#endif\n"
              "#if defined(EVP_sha1)\n#endif\n");
    assert_finding_count(0);
}

static void test_ignores_fields_and_methods(void) {
    scan_cpp_text("struct s { int EVP_PKEY_RSA; RSA *(*RSA_new)(void); };\n"
                  "void f(s *p, s v) { p->EVP_PKEY_RSA = 1; p->RSA_new(); v.RSA_new(); }\n");
    assert_finding_count(0);
}

static void test_ignores_directives_that_are_not_code(void) {
    scan_text("#error RSA_new is gone\n#pragma RSA_new\n#include \"RSA_new\"\n");
    assert_finding_count(0);
}

static void test_reports_references_that_are_not_calls(void) {
    scan_text("void f(void) {\n  RSA *(*make)(void) = RSA_new;\n  use(EVP_sha1);\n}\n");
    assert_findings("2:RSA 3:SHA-1");
}

static void test_reports_one_shot_hash_calls(void) {
    scan_text("void f(void) {\n  MD5(d, n, out);\n  SHA1(d, n, out);\n}\n");
    assert_findings("2:MD5 3:SHA-1");
}

static void test_reports_one_shot_hash_calls_in_macros_and_namespaces(void) {
    scan_cpp_text("#define HASH(d, n, o) MD5(d, n, o)\n"
                  "void f(void) { ::SHA1(d, n, out); }\n");
    assert_findings("1:MD5 2:SHA-1");
}

static void test_ignores_one_shot_hash_names_outside_calls(void) {
    scan_text("enum kind { MD5, SHA1 };\n"
              "int MD5(int n);\n"
              "int h = MD5;\n"
              "void f(void) { use(SHA1); }\n");
    assert_finding_count(0);
}

static void test_ignores_one_shot_hash_methods(void) {
    scan_cpp_text("void f(s *p, s v) { p->MD5(d); v.SHA1(d); }\n");
    assert_finding_count(0);
}

static void assert_risk_at(size_t index, risk_level expected) {
    TEST_ASSERT_EQUAL_INT(expected, finding_list_get(findings, index)->risk);
}

static void test_a_short_literal_key_is_classically_weak(void) {
    scan_text("void f(void) {\n"
              "  RSA_generate_key_ex(r, 1024, 0, 0);\n"
              "  RSA_generate_key_ex(r, 2047, 0, 0);\n"
              "  RSA_generate_key_ex(r, 2048, 0, 0);\n"
              "  DSA_generate_parameters_ex(d, 1024, 0, 0, 0, 0, 0);\n"
              "  DH_generate_parameters_ex(h, 1024, 2, 0);\n"
              "}\n");
    assert_findings("2:RSA-1024 3:RSA-2047 4:RSA-2048 5:DSA-1024 6:DH-1024");
    assert_risk_at(0, RISK_CLASSICALLY_WEAK);
    assert_risk_at(1, RISK_CLASSICALLY_WEAK);
    assert_risk_at(2, RISK_QUANTUM_VULNERABLE);
    assert_risk_at(3, RISK_CLASSICALLY_WEAK);
    assert_risk_at(4, RISK_CLASSICALLY_WEAK);
}

static void test_an_unresolved_key_size_keeps_the_base_risk(void) {
    scan_text("void f(int bits) { RSA_generate_key_ex(r, bits, 0, 0); }\n");
    assert_findings("1:RSA-unknown");
    assert_risk_at(0, RISK_QUANTUM_VULNERABLE);
}

static void test_a_size_next_to_an_algorithm_name_sets_the_risk(void) {
    scan_text("void f(void) {\n"
              "  EVP_PKEY_Q_keygen(0, 0, \"RSA\", (size_t)1024);\n"
              "  EVP_PKEY_Q_keygen(0, 0, \"RSA\", (size_t)3072);\n"
              "}\n");
    assert_findings("2:RSA-1024 3:RSA-3072");
    assert_risk_at(0, RISK_CLASSICALLY_WEAK);
    assert_risk_at(1, RISK_QUANTUM_VULNERABLE);
}

static void test_findings_carry_the_primitive_of_their_rule(void) {
    scan_text("void f(void) {\n"
              "  RSA_sign(0, 0, 0, 0, 0, 0);\n"
              "  RSA_new();\n"
              "  use(EVP_md5);\n"
              "  EVP_PKEY_CTX_new_from_name(0, \"X25519\", 0);\n"
              "}\n");
    assert_finding_count(4);
    TEST_ASSERT_EQUAL_INT(PRIMITIVE_SIGNATURE, finding_list_get(findings, 0)->primitive);
    TEST_ASSERT_EQUAL_INT(PRIMITIVE_UNSPECIFIED, finding_list_get(findings, 1)->primitive);
    TEST_ASSERT_EQUAL_INT(PRIMITIVE_HASH, finding_list_get(findings, 2)->primitive);
    TEST_ASSERT_EQUAL_INT(PRIMITIVE_KEY_EXCHANGE, finding_list_get(findings, 3)->primitive);
}

static void use_rules(const char *json) {
    rule_set_destroy(rules);
    rules = NULL;
    rule_error error;
    const rule_source source = {json, strlen(json)};
    TEST_ASSERT_EQUAL_INT_MESSAGE(PQSCAN_OK, rule_set_load(&source, &rules, &error), error.message);
}

static void test_an_empty_rule_set_reports_nothing(void) {
    use_rules("{\"schema_version\":1,\"algorithms\":[],\"rules\":[],\"calls\":[]}");
    scan_text("void f(void) { RSA_new(); MD5(d, 1, o); use(EVP_sha1); }\n");
    assert_finding_count(0);
}

static void test_the_rules_alone_decide_what_is_reported(void) {
    use_rules("{\"schema_version\":1,"
              "\"algorithms\":[{\"name\":\"HOME-GROWN\",\"risk\":\"REVIEW\","
              "\"weak_below_bits\":512}],"
              "\"rules\":[{\"pattern\":\"my_keygen\",\"kind\":\"function\","
              "\"algorithm\":\"HOME-GROWN\",\"primitive\":\"signature\"}],"
              "\"calls\":[{\"name\":\"my_keygen\",\"key_bits_argument\":0}]}");
    scan_text("void f(void) {\n  RSA_new();\n  my_keygen(256);\n  my_keygen(1024);\n}\n");
    assert_findings("3:HOME-GROWN-256 4:HOME-GROWN-1024");
    assert_risk_at(0, RISK_CLASSICALLY_WEAK);
    assert_risk_at(1, RISK_REVIEW);
}

static void test_reports_constants_as_arguments(void) {
    scan_text("void f(void) { EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); }\n");
    assert_findings("1:RSA");
}

static void test_reports_nested_calls_in_order(void) {
    scan_text("void f(void) { RSA_set0(RSA_new(), DSA_new()); }\n");
    assert_findings("1:RSA 1:DSA");
}

static void test_reads_key_sizes(void) {
    scan_text("void f(int bits) {\n"
              "  RSA_generate_key_ex(r, 2048, NULL, NULL);\n"
              "  RSA_generate_key_ex(r, bits, NULL, NULL);\n"
              "  EVP_RSA_gen((unsigned)0xC00);\n"
              "  RSA_new();\n"
              "}\n");
    assert_findings("2:RSA-2048 3:RSA-unknown 4:RSA-3072 5:RSA");
}

static void test_reference_without_a_call_has_no_key_size(void) {
    scan_text("void *p = RSA_generate_key_ex;\n");
    assert_findings("1:RSA");
}

static void test_reads_algorithm_names_from_known_calls(void) {
    scan_text("void f(void) {\n"
              "  EVP_PKEY_CTX_new_from_name(NULL, \"RSA\", NULL);\n"
              "  EVP_MD_fetch(NULL,\n"
              "               \"md5\", NULL);\n"
              "  EVP_get_digestbyname(\"sha1\");\n"
              "}\n");
    assert_findings("2:RSA 4:MD5 5:SHA-1");
}

static void test_reads_algorithm_and_size_from_the_same_call(void) {
    scan_text("void f(void) {\n"
              "  EVP_PKEY_Q_keygen(NULL, NULL, \"RSA\", (size_t)3072);\n"
              "  EVP_PKEY_Q_keygen(NULL, NULL, \"EC\", \"P-256\");\n"
              "  EVP_PKEY_Q_keygen(NULL, NULL, \"ED25519\");\n"
              "  EVP_PKEY_Q_keygen(NULL, NULL, \"RSA\", bits);\n"
              "}\n");
    assert_findings("2:RSA-3072 3:EC 4:EdDSA 5:RSA-unknown");
}

static void test_ignores_safe_or_non_literal_algorithm_names(void) {
    scan_text("void f(const char *name) {\n"
              "  EVP_MD_fetch(NULL, \"SHA2-256\", NULL);\n"
              "  EVP_MD_fetch(NULL, name, NULL);\n"
              "}\n");
    assert_finding_count(0);
}

static void test_scans_macro_bodies_at_their_real_line(void) {
    scan_text("\n#define NEW_KEY RSA_new()\n"
              "#define GENERATE(r) \\\n"
              "    RSA_generate_key_ex(r, 2048, \\\n"
              "                        NULL, NULL)\n"
              "#define ALGORITHM EVP_PKEY_DSA\n");
    assert_findings("2:RSA 4:RSA-2048 6:DSA");
}

static void test_ignores_comments_and_strings_in_macro_bodies(void) {
    scan_text("#define A 1 /* RSA_new */\n#define B \"DSA_new\"\n#define C(x) #x\n");
    assert_finding_count(0);
}

static void test_a_define_inside_a_macro_body_is_not_followed(void) {
    scan_text("#define A #define B RSA_new\n");
    assert_finding_count(0);
}

static void test_skips_literal_if_zero_but_not_its_else(void) {
    scan_text("#if 0\nvoid a(void) { RSA_new(); }\n#else\nvoid b(void) { DSA_new(); }\n#endif\n"
              "void c(void) {\n#if 0\n  DH_new();\n#endif\n}\n");
    assert_findings("4:DSA");
}

static void test_skips_prose_under_if_zero(void) {
    scan_text(
        "#if 0\nThis isn't C: RSA_new stays disabled.\n#endif\nvoid f(void) { DSA_new(); }\n");
    assert_findings("4:DSA");
}

static void test_scans_every_other_conditional_branch(void) {
    scan_text("#ifdef X\nvoid a(void) { RSA_new(); }\n#else\nvoid a(void) { DSA_new(); }\n#endif\n"
              "#if 1\nvoid b(void) { DH_new(); }\n#endif\n"
              "#if FEATURE\n#elif 0\nvoid c(void) { EVP_md5(); }\n#else\n"
              "void c(void) { EVP_sha1(); }\n#endif\n");
    assert_findings("2:RSA 4:DSA 7:DH 13:SHA-1");
}

static void test_scans_broken_syntax(void) {
    scan_text("void f(void {\n  RSA_new(;\n}\nint g(void) { return DSA_new();\n");
    assert_findings("2:RSA 4:DSA");
}

static void test_reads_qualified_names_in_cpp(void) {
    scan_cpp_text("void f() {\n"
                  "  ::RSA_new();\n"
                  "  ossl::v3::RSA_generate_key_ex(r, 2048, 0, 0);\n"
                  "  auto id = ::EVP_PKEY_DSA;\n"
                  "}\n"
                  "RSA *ns::RSA_new() { return 0; }\n");
    assert_findings("2:RSA 3:RSA-2048 4:DSA");
}

static void test_scans_lambdas_and_templates_in_cpp(void) {
    scan_cpp_text("template <class T> T make() { return DH_new(); }\n"
                  "auto f = [] { return EVP_md5(); };\n");
    assert_findings("1:DH 2:MD5");
}

static void test_headers_accept_c_code_using_cpp_keywords(void) {
    const char *text = "int class = 1;\nvoid f(void) { int new = 0; RSA_new(); }\n";
    const file_contents file = {(char *)text, strlen(text)};
    const scan_input input = {"a.h", &file, rules};
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, source_scanner.scan(&input, findings));
    assert_findings("2:RSA");
}

static void test_skips_files_containing_nul_bytes(void) {
    char data[] = {'R', 'S', 'A', '_', 'n', 'e', 'w', '\0', ' '};
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_BINARY, scan_bytes(data, sizeof(data)));
    assert_finding_count(0);
}

static void test_survives_deep_nesting(void) {
    static char text[((size_t)DEEP_NESTING * 2) + 1];
    memset(text, '(', DEEP_NESTING);
    text[DEEP_NESTING] = '1';
    memset(text + DEEP_NESTING + 1, ')', DEEP_NESTING);
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, scan_bytes(text, sizeof(text)));
}

static void test_survives_many_nested_conditionals(void) {
    static const char level[] = "#if 0\n#else\n";
    static char text[(size_t)DEEP_NESTING * (sizeof(level) - 1)];
    for (size_t i = 0; i < sizeof(text); i++) {
        text[i] = level[i % (sizeof(level) - 1)];
    }
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, scan_bytes(text, sizeof(text)));
}

static void test_survives_every_truncation_of_a_source(void) {
    static const char source[] =
        "#define K(x) \\\n  RSA_generate_key_ex(x, (int)2048, NULL, NULL)\n#if 0\n/* c */\n#else\n"
        "void f(void) { EVP_MD_fetch(NULL, \"md5\", NULL); ::a::b(\"\\x41\"); }\n#endif\n";
    char copy[sizeof(source)];
    for (size_t len = 0; len < sizeof(source); len++) {
        memcpy(copy, source, len);
        TEST_ASSERT_EQUAL_INT(PQSCAN_OK, scan_bytes(copy, len));
    }
}

static void test_survives_arbitrary_bytes(void) {
    static unsigned char data[RANDOM_INPUT_SIZE];
    uint32_t state = RANDOM_SEED;
    for (size_t round = 0; round < RANDOM_ROUNDS; round++) {
        for (size_t i = 0; i < sizeof(data); i++) {
            state = (state * RANDOM_MULTIPLIER) + RANDOM_INCREMENT;
            data[i] = (unsigned char)((state >> RANDOM_SHIFT) | 1U);
        }
        TEST_ASSERT_EQUAL_INT(PQSCAN_OK, scan_bytes((char *)data, sizeof(data)));
    }
}

static void test_finds_a_match_after_a_huge_line(void) {
    static const char suffix[] = ";\nRSA_new();";
    const size_t len = HUGE_LINE_SIZE + strlen(suffix);
    char *data = malloc(len + 1);
    TEST_ASSERT_NOT_NULL(data);
    memset(data, 'x', HUGE_LINE_SIZE);
    memcpy(data + HUGE_LINE_SIZE, suffix, sizeof(suffix));

    const pqscan_status status = scan_bytes(data, len);
    free(data);
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, status);
    assert_finding_count(1);
    TEST_ASSERT_EQUAL_size_t(2, finding_list_get(findings, 0)->line);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_accepts_only_source_files);
    RUN_TEST(test_empty_file_has_no_findings);
    RUN_TEST(test_reports_path_line_algorithm_and_risk);
    RUN_TEST(test_counts_lines_with_crlf_endings);
    RUN_TEST(test_reports_each_match_on_a_line);
    RUN_TEST(test_matches_at_the_edges_of_the_file);
    RUN_TEST(test_skips_longer_identifiers);
    RUN_TEST(test_non_utf8_bytes_separate_identifiers);
    RUN_TEST(test_ignores_comments);
    RUN_TEST(test_ignores_strings_outside_known_calls);
    RUN_TEST(test_ignores_declarations_of_a_name);
    RUN_TEST(test_ignores_fields_and_methods);
    RUN_TEST(test_ignores_directives_that_are_not_code);
    RUN_TEST(test_reports_references_that_are_not_calls);
    RUN_TEST(test_reports_one_shot_hash_calls);
    RUN_TEST(test_reports_one_shot_hash_calls_in_macros_and_namespaces);
    RUN_TEST(test_ignores_one_shot_hash_names_outside_calls);
    RUN_TEST(test_ignores_one_shot_hash_methods);
    RUN_TEST(test_a_short_literal_key_is_classically_weak);
    RUN_TEST(test_an_unresolved_key_size_keeps_the_base_risk);
    RUN_TEST(test_a_size_next_to_an_algorithm_name_sets_the_risk);
    RUN_TEST(test_findings_carry_the_primitive_of_their_rule);
    RUN_TEST(test_an_empty_rule_set_reports_nothing);
    RUN_TEST(test_the_rules_alone_decide_what_is_reported);
    RUN_TEST(test_reports_constants_as_arguments);
    RUN_TEST(test_reports_nested_calls_in_order);
    RUN_TEST(test_reads_key_sizes);
    RUN_TEST(test_reference_without_a_call_has_no_key_size);
    RUN_TEST(test_reads_algorithm_names_from_known_calls);
    RUN_TEST(test_reads_algorithm_and_size_from_the_same_call);
    RUN_TEST(test_ignores_safe_or_non_literal_algorithm_names);
    RUN_TEST(test_scans_macro_bodies_at_their_real_line);
    RUN_TEST(test_ignores_comments_and_strings_in_macro_bodies);
    RUN_TEST(test_a_define_inside_a_macro_body_is_not_followed);
    RUN_TEST(test_skips_literal_if_zero_but_not_its_else);
    RUN_TEST(test_skips_prose_under_if_zero);
    RUN_TEST(test_scans_every_other_conditional_branch);
    RUN_TEST(test_scans_broken_syntax);
    RUN_TEST(test_reads_qualified_names_in_cpp);
    RUN_TEST(test_scans_lambdas_and_templates_in_cpp);
    RUN_TEST(test_headers_accept_c_code_using_cpp_keywords);
    RUN_TEST(test_skips_files_containing_nul_bytes);
    RUN_TEST(test_finds_a_match_after_a_huge_line);
    RUN_TEST(test_survives_deep_nesting);
    RUN_TEST(test_records_what_matched);
    RUN_TEST(test_survives_many_nested_conditionals);
    RUN_TEST(test_survives_every_truncation_of_a_source);
    RUN_TEST(test_survives_arbitrary_bytes);
    return UNITY_END();
}
