/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/scan/syntax_parser.h"

#include "pqscan/core/status.h"
#include "pqscan/scan/file_reader.h"
#include "pqscan/walk/file_type.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <tree_sitter/api.h>

/* Grammars generate these entry points but ship no header at a stable path. */
const TSLanguage *tree_sitter_c(void);
const TSLanguage *tree_sitter_cpp(void);

struct syntax_parser {
    TSParser *parser;
    const file_contents *file;
    time_t deadline;
};

static time_t monotonic_seconds(void) {
    struct timespec now;
    return (clock_gettime(CLOCK_MONOTONIC, &now) == 0) ? now.tv_sec : 0;
}

static const TSLanguage *language_for(source_language language) {
    return (language == SOURCE_LANGUAGE_C) ? tree_sitter_c() : tree_sitter_cpp();
}

pqscan_status syntax_parser_create(const syntax_source *source, syntax_parser **out) {
    if (source->file->len > (size_t)PQSCAN_MAX_FILE_SIZE) {
        return PQSCAN_ERR_TOO_LARGE;
    }
    syntax_parser *parser = calloc(1, sizeof(*parser));
    if (parser == NULL) {
        return PQSCAN_ERR_NOMEM;
    }
    parser->parser = ts_parser_new();
    parser->file = source->file;
    parser->deadline = monotonic_seconds() + (time_t)source->budget_seconds;
    if (!ts_parser_set_language(parser->parser, language_for(source->language))) {
        syntax_parser_destroy(parser);
        return PQSCAN_ERR_PARSE;
    }
    *out = parser;
    return PQSCAN_OK;
}

void syntax_parser_destroy(syntax_parser *parser) {
    if (parser == NULL) {
        return;
    }
    ts_parser_delete(parser->parser);
    free(parser);
}

bool syntax_parser_expired(const syntax_parser *parser) {
    return monotonic_seconds() >= parser->deadline;
}

/* Tree-sitter dictates the signatures of this callback and the next one. */
// cppcheck-suppress constParameterCallback
// NOLINTNEXTLINE(readability-function-size)
static const char *read_from_file(void *payload, uint32_t byte_index, TSPoint position,
                                  uint32_t *bytes_read) {
    (void)position;
    const file_contents *file = payload;
    if (byte_index >= file->len) {
        *bytes_read = 0;
        return "";
    }
    *bytes_read = (uint32_t)(file->len - byte_index);
    return file->data + byte_index;
}

// cppcheck-suppress constParameterCallback
static bool cancel_when_expired(TSParseState *state) {
    return syntax_parser_expired(state->payload);
}

static pqscan_status parse_included_ranges(syntax_parser *parser, TSTree **out) {
    const TSInput input = {(void *)parser->file, read_from_file, TSInputEncodingUTF8, NULL};
    const TSParseOptions options = {parser, cancel_when_expired};
    TSTree *tree = ts_parser_parse_with_options(parser->parser, NULL, input, options);
    if (tree == NULL) {
        /* A cancelled parser keeps its state to resume, which the next parse must not see. */
        ts_parser_reset(parser->parser);
        return PQSCAN_ERR_PARSE;
    }
    *out = tree;
    return PQSCAN_OK;
}

pqscan_status syntax_parser_parse_file(syntax_parser *parser, TSTree **out) {
    if (!ts_parser_set_included_ranges(parser->parser, NULL, 0)) {
        return PQSCAN_ERR_PARSE;
    }
    return parse_included_ranges(parser, out);
}

pqscan_status syntax_parser_parse_node(syntax_parser *parser, TSNode node, TSTree **out) {
    const TSRange range = {
        ts_node_start_point(node),
        ts_node_end_point(node),
        ts_node_start_byte(node),
        ts_node_end_byte(node),
    };
    if (!ts_parser_set_included_ranges(parser->parser, &range, 1)) {
        return PQSCAN_ERR_PARSE;
    }
    return parse_included_ranges(parser, out);
}

syntax_text syntax_node_text(TSNode node, const file_contents *file) {
    const size_t start = ts_node_start_byte(node);
    const size_t end = ts_node_end_byte(node);
    if (start > end || end > file->len) {
        const syntax_text empty = {"", 0};
        return empty;
    }
    const syntax_text text = {file->data + start, end - start};
    return text;
}

bool syntax_node_is(TSNode node, const char *type) {
    return !ts_node_is_null(node) && strcmp(ts_node_type(node), type) == 0;
}

TSNode syntax_node_field(TSNode node, const char *field) {
    return ts_node_child_by_field_name(node, field, (uint32_t)strlen(field));
}
