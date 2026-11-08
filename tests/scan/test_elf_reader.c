/* SPDX-License-Identifier: Apache-2.0 */
#include "elf_builder.h"
#include "pqscan/core/status.h"
#include "pqscan/scan/elf_reader.h"
#include "unity.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { DESCRIPTION_SIZE = 2048, NEVER = 0, OUT_OF_RANGE = 99, PAST_ANY_TABLE = 4000 };
enum { ELF32_CLASS = 1, NO_ENCODING = 0, UNKNOWN_ENCODING = 3, SMALLER_SECTION_HEADER = 40 };
enum { SMALLER_SYMBOL = 16, NAME_BLOCK = ELF_MAX_SYMBOL_NAME + 2 };

/* What a visit saw, as "name:type:defined" words. */
typedef struct recording {
    char text[DESCRIPTION_SIZE];
    size_t used;
    size_t visits;
    size_t stop_after; /* Stop the read on this visit, or NEVER. */
} recording;

static const test_symbol IMPORTS[] = {
    {"RSA_new", TEST_STT_FUNC, false},
    {"EVP_sha1", TEST_STT_FUNC, false},
};
static const test_symbol OBJECT_SYMBOLS[] = {
    {"MD5", TEST_STT_NOTYPE, false},
    {"make_key", TEST_STT_FUNC, true},
    {"key_table", TEST_STT_OBJECT, true},
    {"resolver", TEST_STT_GNU_IFUNC, true},
};
static const test_symbols IMPORT_LIST = {IMPORTS, sizeof(IMPORTS) / sizeof(IMPORTS[0])};
static const test_symbols OBJECT_LIST = {
    OBJECT_SYMBOLS,
    sizeof(OBJECT_SYMBOLS) / sizeof(OBJECT_SYMBOLS[0]),
};
static const test_symbols NO_TABLE = {NULL, 0};
static const test_symbols EMPTY_TABLE = {IMPORTS, 0};

static const char IMPORTS_SEEN[] = "RSA_new:func:undefined EVP_sha1:func:undefined";
static const char OBJECT_SYMBOLS_SEEN[] =
    "MD5:untyped:undefined make_key:func:defined key_table:other:defined resolver:func:defined";

static recording seen;
static built_elf elf;
static char expected_both[DESCRIPTION_SIZE];

void setUp(void) {
    memset(&seen, 0, sizeof(seen));
    const int written =
        snprintf(expected_both, sizeof(expected_both), "%s %s", IMPORTS_SEEN, OBJECT_SYMBOLS_SEEN);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(expected_both));
}

void tearDown(void) {}

static const char *type_label(elf_symbol_type type) {
    switch (type) {
    case ELF_SYMBOL_FUNCTION:
        return "func";
    case ELF_SYMBOL_UNTYPED:
        return "untyped";
    case ELF_SYMBOL_OTHER:
        return "other";
    }
    return "?";
}

static pqscan_status record_symbol(const elf_symbol *symbol, void *context) {
    recording *record = context;
    record->visits++;
    TEST_ASSERT_EQUAL_CHAR('\0', symbol->name[symbol->len]);
    TEST_ASSERT_TRUE(symbol->len <= ELF_MAX_SYMBOL_NAME);
    const size_t room = sizeof(record->text) - record->used;
    const int written =
        snprintf(record->text + record->used, room, "%s%s:%s:%s", (record->used > 0) ? " " : "",
                 symbol->name, type_label(symbol->type), symbol->defined ? "defined" : "undefined");
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < room);
    record->used += (size_t)written;
    return (record->visits == record->stop_after) ? PQSCAN_ERR_NOMEM : PQSCAN_OK;
}

/* A copy of exactly len bytes, so that the sanitizer catches any read past the end. */
static pqscan_status read_prefix(size_t len) {
    unsigned char *copy = malloc((len > 0) ? len : 1);
    TEST_ASSERT_NOT_NULL(copy);
    memcpy(copy, elf.bytes, len);
    const elf_symbol_sink sink = {record_symbol, &seen};
    const pqscan_status status = elf_read_symbols(copy, len, &sink);
    free(copy);
    return status;
}

static pqscan_status read_elf(void) { return read_prefix(elf.len); }

static void build(test_symbols statics, test_symbols dynamics, bool big_endian) {
    const elf_spec spec = {big_endian, statics, dynamics};
    elf_build(&spec, &elf);
}

static void build_both(void) { build(OBJECT_LIST, IMPORT_LIST, false); }

static void put(size_t offset, size_t width, uint64_t value) {
    const elf_field field = {offset, width};
    built_elf_put(&elf, field, value);
}

static uint64_t get(size_t offset, size_t width) {
    const elf_field field = {offset, width};
    return built_elf_get(&elf, field);
}

static size_t static_header(void) { return built_elf_section(&elf, elf.static_table); }

static size_t static_strings_header(void) {
    const uint64_t link = get(static_header() + TEST_SH_LINK, TEST_WORD);
    return built_elf_section(&elf, (size_t)link);
}

static void assert_read(pqscan_status expected_status, const char *expected_symbols) {
    TEST_ASSERT_EQUAL_INT(expected_status, read_elf());
    TEST_ASSERT_EQUAL_STRING(expected_symbols, seen.text);
}

static void test_reports_dynamic_symbols_then_static_ones(void) {
    build_both();
    assert_read(PQSCAN_OK, expected_both);
}

static void test_reads_big_endian_files(void) {
    build(OBJECT_LIST, IMPORT_LIST, true);
    assert_read(PQSCAN_OK, expected_both);
}

static void test_reads_a_file_with_one_table(void) {
    build(OBJECT_LIST, NO_TABLE, false);
    assert_read(PQSCAN_OK, OBJECT_SYMBOLS_SEEN);
}

static void test_an_empty_table_is_read_and_reports_nothing(void) {
    build(EMPTY_TABLE, NO_TABLE, false);
    assert_read(PQSCAN_OK, "");
}

static void test_a_file_without_symbol_tables_has_no_symbols(void) {
    build(NO_TABLE, NO_TABLE, false);
    assert_read(PQSCAN_ERR_ELF_NO_SYMBOLS, "");
}

static void test_a_file_without_section_headers_has_no_symbols(void) {
    build_both();
    put(TEST_E_SHOFF, TEST_XWORD, 0);
    put(TEST_E_SHNUM, TEST_HALF, 0);
    assert_read(PQSCAN_ERR_ELF_NO_SYMBOLS, "");
}

static void test_only_64_bit_files_are_supported(void) {
    build_both();
    elf.bytes[TEST_EI_CLASS] = ELF32_CLASS;
    assert_read(PQSCAN_ERR_ELF_UNSUPPORTED, "");
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_ELF_UNSUPPORTED, read_prefix(TEST_EI_CLASS + 1));
}

static void test_input_that_is_not_elf_is_malformed(void) {
    build_both();
    elf.bytes[0] = 'M';
    assert_read(PQSCAN_ERR_ELF_MALFORMED, "");
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_ELF_MALFORMED, read_prefix(0));
}

static void test_an_unknown_byte_order_is_malformed(void) {
    build_both();
    elf.bytes[TEST_EI_DATA] = NO_ENCODING;
    assert_read(PQSCAN_ERR_ELF_MALFORMED, "");
    elf.bytes[TEST_EI_DATA] = UNKNOWN_ENCODING;
    assert_read(PQSCAN_ERR_ELF_MALFORMED, "");
}

/* The section table comes last, so every truncation cuts it. */
static void test_every_truncation_is_malformed_and_reports_nothing(void) {
    build_both();
    for (size_t len = 0; len < elf.len; len++) {
        TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_ELF_MALFORMED, read_prefix(len));
        TEST_ASSERT_EQUAL_size_t(0, seen.visits);
    }
}

static void test_a_section_table_past_the_end_is_malformed(void) {
    build_both();
    put(TEST_E_SHOFF, TEST_XWORD, elf.len - 1);
    assert_read(PQSCAN_ERR_ELF_MALFORMED, "");
}

static void test_a_section_table_offset_that_would_wrap_is_malformed(void) {
    build_both();
    put(TEST_E_SHOFF, TEST_XWORD, UINT64_MAX - 1);
    assert_read(PQSCAN_ERR_ELF_MALFORMED, "");
}

static void test_more_sections_than_fit_is_malformed(void) {
    build_both();
    put(TEST_E_SHNUM, TEST_HALF, elf.section_count + 1);
    assert_read(PQSCAN_ERR_ELF_MALFORMED, "");
}

static void test_an_unexpected_section_header_size_is_malformed(void) {
    build_both();
    put(TEST_E_SHENTSIZE, TEST_HALF, SMALLER_SECTION_HEADER);
    assert_read(PQSCAN_ERR_ELF_MALFORMED, "");
}

static void test_reads_the_section_count_from_the_first_header_when_there_are_many(void) {
    build_both();
    put(TEST_E_SHNUM, TEST_HALF, 0);
    put(built_elf_section(&elf, 0) + TEST_SH_SIZE, TEST_XWORD, elf.section_count);
    assert_read(PQSCAN_OK, expected_both);
}

static void test_a_symbol_table_past_the_end_leaves_the_other_table(void) {
    build_both();
    put(static_header() + TEST_SH_OFFSET, TEST_XWORD, PAST_ANY_TABLE);
    assert_read(PQSCAN_ERR_ELF_MALFORMED, IMPORTS_SEEN);
}

static void test_a_symbol_table_size_that_would_wrap_is_malformed(void) {
    build_both();
    put(static_header() + TEST_SH_SIZE, TEST_XWORD, UINT64_MAX / TEST_SYM_SIZE * TEST_SYM_SIZE);
    assert_read(PQSCAN_ERR_ELF_MALFORMED, IMPORTS_SEEN);
}

static void test_a_symbol_table_with_a_partial_entry_is_malformed(void) {
    build_both();
    const size_t size = static_header() + TEST_SH_SIZE;
    put(size, TEST_XWORD, get(size, TEST_XWORD) - 1);
    assert_read(PQSCAN_ERR_ELF_MALFORMED, IMPORTS_SEEN);
}

static void test_an_unexpected_symbol_size_is_malformed(void) {
    build_both();
    put(static_header() + TEST_SH_ENTSIZE, TEST_XWORD, SMALLER_SYMBOL);
    assert_read(PQSCAN_ERR_ELF_MALFORMED, IMPORTS_SEEN);
}

static void test_a_string_table_link_out_of_range_is_malformed(void) {
    build_both();
    put(static_header() + TEST_SH_LINK, TEST_WORD, OUT_OF_RANGE);
    assert_read(PQSCAN_ERR_ELF_MALFORMED, IMPORTS_SEEN);
}

static void test_a_link_to_a_section_that_holds_no_strings_is_malformed(void) {
    build_both();
    put(static_header() + TEST_SH_LINK, TEST_WORD, elf.dynamic_table);
    assert_read(PQSCAN_ERR_ELF_MALFORMED, IMPORTS_SEEN);
}

static void test_a_string_table_past_the_end_is_malformed(void) {
    build_both();
    put(static_strings_header() + TEST_SH_OFFSET, TEST_XWORD, PAST_ANY_TABLE);
    assert_read(PQSCAN_ERR_ELF_MALFORMED, IMPORTS_SEEN);
}

static void test_a_name_past_its_string_table_is_malformed_but_the_rest_is_read(void) {
    build_both();
    put(built_elf_symbol(&elf, elf.static_table, 1) + TEST_ST_NAME, TEST_WORD, PAST_ANY_TABLE);
    assert_read(PQSCAN_ERR_ELF_MALFORMED,
                "RSA_new:func:undefined EVP_sha1:func:undefined make_key:func:defined "
                "key_table:other:defined resolver:func:defined");
}

static void test_a_name_that_runs_off_its_string_table_is_malformed(void) {
    build_both();
    const size_t strings = static_strings_header();
    const uint64_t end =
        get(strings + TEST_SH_OFFSET, TEST_XWORD) + get(strings + TEST_SH_SIZE, TEST_XWORD);
    elf.bytes[end - 1] = 'x';
    assert_read(PQSCAN_ERR_ELF_MALFORMED,
                "RSA_new:func:undefined EVP_sha1:func:undefined MD5:untyped:undefined "
                "make_key:func:defined key_table:other:defined");
}

static void test_names_longer_than_the_limit_are_skipped(void) {
    static char longest[NAME_BLOCK];
    static char too_long[NAME_BLOCK];
    memset(longest, 'a', ELF_MAX_SYMBOL_NAME);
    memset(too_long, 'b', ELF_MAX_SYMBOL_NAME + 1);
    const test_symbol symbols[] = {
        {too_long, TEST_STT_FUNC, false},
        {longest, TEST_STT_FUNC, false},
    };
    const test_symbols list = {symbols, sizeof(symbols) / sizeof(symbols[0])};
    build(list, NO_TABLE, false);
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, read_elf());
    TEST_ASSERT_EQUAL_size_t(1, seen.visits);
    TEST_ASSERT_EQUAL_CHAR('a', seen.text[0]);
}

static void test_a_second_table_of_one_kind_is_malformed_and_not_read(void) {
    build_both();
    put(built_elf_section(&elf, elf.dynamic_table) + TEST_SH_TYPE, TEST_WORD, TEST_SHT_SYMTAB);
    assert_read(PQSCAN_ERR_ELF_MALFORMED, IMPORTS_SEEN);
}

static void test_sections_of_other_types_are_ignored(void) {
    build_both();
    put(static_header() + TEST_SH_TYPE, TEST_WORD, TEST_SHT_PROGBITS);
    assert_read(PQSCAN_OK, IMPORTS_SEEN);
}

static void test_the_visitor_can_stop_the_read(void) {
    build_both();
    seen.stop_after = 1;
    assert_read(PQSCAN_ERR_NOMEM, "RSA_new:func:undefined");
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_reports_dynamic_symbols_then_static_ones);
    RUN_TEST(test_reads_big_endian_files);
    RUN_TEST(test_reads_a_file_with_one_table);
    RUN_TEST(test_an_empty_table_is_read_and_reports_nothing);
    RUN_TEST(test_a_file_without_symbol_tables_has_no_symbols);
    RUN_TEST(test_a_file_without_section_headers_has_no_symbols);
    RUN_TEST(test_only_64_bit_files_are_supported);
    RUN_TEST(test_input_that_is_not_elf_is_malformed);
    RUN_TEST(test_an_unknown_byte_order_is_malformed);
    RUN_TEST(test_every_truncation_is_malformed_and_reports_nothing);
    RUN_TEST(test_a_section_table_past_the_end_is_malformed);
    RUN_TEST(test_a_section_table_offset_that_would_wrap_is_malformed);
    RUN_TEST(test_more_sections_than_fit_is_malformed);
    RUN_TEST(test_an_unexpected_section_header_size_is_malformed);
    RUN_TEST(test_reads_the_section_count_from_the_first_header_when_there_are_many);
    RUN_TEST(test_a_symbol_table_past_the_end_leaves_the_other_table);
    RUN_TEST(test_a_symbol_table_size_that_would_wrap_is_malformed);
    RUN_TEST(test_a_symbol_table_with_a_partial_entry_is_malformed);
    RUN_TEST(test_an_unexpected_symbol_size_is_malformed);
    RUN_TEST(test_a_string_table_link_out_of_range_is_malformed);
    RUN_TEST(test_a_link_to_a_section_that_holds_no_strings_is_malformed);
    RUN_TEST(test_a_string_table_past_the_end_is_malformed);
    RUN_TEST(test_a_name_past_its_string_table_is_malformed_but_the_rest_is_read);
    RUN_TEST(test_a_name_that_runs_off_its_string_table_is_malformed);
    RUN_TEST(test_names_longer_than_the_limit_are_skipped);
    RUN_TEST(test_a_second_table_of_one_kind_is_malformed_and_not_read);
    RUN_TEST(test_sections_of_other_types_are_ignored);
    RUN_TEST(test_the_visitor_can_stop_the_read);
    return UNITY_END();
}
