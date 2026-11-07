/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/status.h"
#include "pqscan/scan/file_reader.h"
#include "pqscan/scan/syntax_parser.h"
#include "pqscan/walk/file_type.h"
#include "unity.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <tree_sitter/api.h>

/* Well past Tree-sitter's progress check, which only runs every hundred steps or so. */
enum { LARGE_SOURCE_SIZE = 256 * 1024, BUDGET_SECONDS = 60 };

static syntax_parser *parser;
static TSTree *tree;
static file_contents file;

void setUp(void) {
    parser = NULL;
    tree = NULL;
}

static void release_parser(void) {
    ts_tree_delete(tree);
    tree = NULL;
    syntax_parser_destroy(parser);
    parser = NULL;
}

void tearDown(void) { release_parser(); }

static void create_parser(source_language language, const char *text, unsigned budget) {
    file.data = (char *)text;
    file.len = strlen(text);
    const syntax_source source = {language, &file, budget};
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, syntax_parser_create(&source, &parser));
}

static TSNode parse_root(source_language language, const char *text) {
    create_parser(language, text, BUDGET_SECONDS);
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, syntax_parser_parse_file(parser, &tree));
    return ts_tree_root_node(tree);
}

static void test_empty_file_gives_an_empty_tree(void) {
    const TSNode root = parse_root(SOURCE_LANGUAGE_C, "");
    TEST_ASSERT_TRUE(syntax_node_is(root, "translation_unit"));
    TEST_ASSERT_EQUAL_UINT32(0, ts_node_named_child_count(root));
}

static void test_each_language_uses_its_own_grammar(void) {
    static const char source[] = "template <class T> T g();\n";
    TEST_ASSERT_FALSE(ts_node_has_error(parse_root(SOURCE_LANGUAGE_CPP, source)));
    release_parser();
    TEST_ASSERT_TRUE(ts_node_has_error(parse_root(SOURCE_LANGUAGE_C, source)));
}

static void test_syntax_errors_still_give_a_tree(void) {
    TEST_ASSERT_TRUE(ts_node_has_error(parse_root(SOURCE_LANGUAGE_C, "void f(void { (; }\n")));
}

static void test_rejects_files_above_the_size_limit(void) {
    const file_contents huge = {"", (size_t)PQSCAN_MAX_FILE_SIZE + 1};
    const syntax_source source = {SOURCE_LANGUAGE_C, &huge, BUDGET_SECONDS};
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_TOO_LARGE, syntax_parser_create(&source, &parser));
    TEST_ASSERT_NULL(parser);
}

static void test_expired_budget_stops_the_parse(void) {
    char *text = malloc(LARGE_SOURCE_SIZE + 1);
    TEST_ASSERT_NOT_NULL(text);
    memset(text, ';', LARGE_SOURCE_SIZE);
    text[LARGE_SOURCE_SIZE] = '\0';
    create_parser(SOURCE_LANGUAGE_C, text, 0);

    TEST_ASSERT_TRUE(syntax_parser_expired(parser));
    const pqscan_status status = syntax_parser_parse_file(parser, &tree);
    free(text);
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_PARSE, status);
    TEST_ASSERT_NULL(tree);
}

static void test_budget_not_expired_right_after_creation(void) {
    create_parser(SOURCE_LANGUAGE_C, "", BUDGET_SECONDS);
    TEST_ASSERT_FALSE(syntax_parser_expired(parser));
}

static void test_node_text_and_fields(void) {
    const TSNode root = parse_root(SOURCE_LANGUAGE_C, "int total;\n");
    const TSNode declaration = ts_node_named_child(root, 0);
    const TSNode name = syntax_node_field(declaration, "declarator");
    const syntax_text text = syntax_node_text(name, &file);
    TEST_ASSERT_TRUE(syntax_node_is(name, "identifier"));
    TEST_ASSERT_EQUAL_size_t(strlen("total"), text.len);
    TEST_ASSERT_EQUAL_MEMORY("total", text.data, text.len);
    TEST_ASSERT_TRUE(ts_node_is_null(syntax_node_field(declaration, "no_such_field")));
    TEST_ASSERT_FALSE(
        syntax_node_is(syntax_node_field(declaration, "no_such_field"), "identifier"));
}

static void test_node_outside_the_file_has_empty_text(void) {
    const TSNode root = parse_root(SOURCE_LANGUAGE_C, "int total;\n");
    const file_contents shorter = {file.data, 1};
    TEST_ASSERT_EQUAL_size_t(0, syntax_node_text(root, &shorter).len);
}

static void test_parsing_a_node_keeps_file_positions(void) {
    static const char source[] = "\n#define KEY \\\n    RSA_new()\n";
    const TSNode definition = ts_node_named_child(parse_root(SOURCE_LANGUAGE_C, source), 0);
    const TSNode body = syntax_node_field(definition, "value");
    TSTree *body_tree = NULL;
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, syntax_parser_parse_node(parser, body, &body_tree));

    const uint32_t offset = (uint32_t)(strstr(source, "RSA_new") - source);
    const TSNode name = ts_node_descendant_for_byte_range(ts_tree_root_node(body_tree), offset,
                                                          offset + (uint32_t)strlen("RSA_new"));
    const uint32_t row = ts_node_start_point(name).row;
    const bool is_identifier = syntax_node_is(name, "identifier");
    ts_tree_delete(body_tree);
    TEST_ASSERT_TRUE(is_identifier);
    TEST_ASSERT_EQUAL_UINT32(2, row);
}

static void test_destroy_accepts_null(void) { syntax_parser_destroy(NULL); }

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_empty_file_gives_an_empty_tree);
    RUN_TEST(test_each_language_uses_its_own_grammar);
    RUN_TEST(test_syntax_errors_still_give_a_tree);
    RUN_TEST(test_rejects_files_above_the_size_limit);
    RUN_TEST(test_expired_budget_stops_the_parse);
    RUN_TEST(test_budget_not_expired_right_after_creation);
    RUN_TEST(test_node_text_and_fields);
    RUN_TEST(test_node_outside_the_file_has_empty_text);
    RUN_TEST(test_parsing_a_node_keeps_file_positions);
    RUN_TEST(test_destroy_accepts_null);
    return UNITY_END();
}
