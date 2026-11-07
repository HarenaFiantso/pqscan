/* SPDX-License-Identifier: Apache-2.0 */
#include "scan_support.h"

#include "pqscan/core/finding.h"
#include "pqscan/core/key_size.h"
#include "pqscan/core/status.h"
#include "pqscan/flow/flow_source.h"
#include "pqscan/scan/syntax_parser.h"
#include "pqscan/walk/file_type.h"
#include "unity.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <tree_sitter/api.h>

enum { BUDGET_SECONDS = 60 };

void parsed_source_init(parsed_source *source, char *text, source_language language) {
    source->file.data = text;
    source->file.len = strlen(text);
    source->parser = NULL;
    source->tree = NULL;
    const syntax_source input = {language, &source->file, BUDGET_SECONDS};
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, syntax_parser_create(&input, &source->parser));
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, syntax_parser_parse_file(source->parser, &source->tree));
    const flow_source flow = {&source->file, source->parser, language};
    source->flow = flow;
}

void parsed_source_release(parsed_source *source) {
    ts_tree_delete(source->tree);
    syntax_parser_destroy(source->parser);
}

TSNode parsed_source_root(const parsed_source *source) { return ts_tree_root_node(source->tree); }

TSNode find_node_of_type(TSNode root, const char *type) {
    TSTreeCursor cursor = ts_tree_cursor_new(root);
    TSNode found = ts_tree_cursor_current_node(&cursor);
    bool more = true;
    while (more && !syntax_node_is(found, type)) {
        more = syntax_cursor_advance(&cursor, false);
        found = ts_tree_cursor_current_node(&cursor);
    }
    ts_tree_cursor_delete(&cursor);
    TEST_ASSERT_TRUE_MESSAGE(more, type);
    return found;
}

syntax_text text_from(const char *text) {
    const syntax_text slice = {text, strlen(text)};
    return slice;
}

static int describe_finding(const finding *item, char *out, size_t left) {
    if (item->size.kind == KEY_SIZE_KNOWN) {
        return snprintf(out, left, "%zu:%s-%u", item->line, item->algorithm, item->size.bits);
    }
    if (item->size.kind == KEY_SIZE_UNKNOWN) {
        return snprintf(out, left, "%zu:%s-unknown", item->line, item->algorithm);
    }
    return snprintf(out, left, "%zu:%s", item->line, item->algorithm);
}

void describe_findings(const finding_list *findings, char *description, size_t size) {
    size_t used = 0;
    description[0] = '\0';
    for (size_t i = 0; i < finding_list_count(findings); i++) {
        if (i > 0) {
            TEST_ASSERT_TRUE(used + 1 < size);
            description[used++] = ' ';
        }
        const int written =
            describe_finding(finding_list_get(findings, i), description + used, size - used);
        TEST_ASSERT_TRUE(written > 0 && (size_t)written < size - used);
        used += (size_t)written;
    }
}
