/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/status.h"
#include "pqscan/flow/constant_table.h"
#include "pqscan/scan/syntax_parser.h"
#include "scan_support.h"
#include "unity.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum { NAME_SIZE = 16, SCOPE_END = 100, LATE = 200, BEFORE_END = 99, COLLIDING_NAMES = 10000 };

static constant_table *table;

void setUp(void) {
    table = constant_table_create();
    TEST_ASSERT_NOT_NULL(table);
}

void tearDown(void) { constant_table_destroy(table); }

static void bind_integer(const char *name, uint64_t integer) {
    constant_binding binding;
    memset(&binding, 0, sizeof(binding));
    binding.name = text_from(name);
    binding.value.kind = CONSTANT_INTEGER;
    binding.value.integer = integer;
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, constant_table_bind(table, &binding));
}

static void open_scope(uint32_t end) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, constant_table_open_scope(table, end));
}

static void assert_value(const char *name, uint64_t expected) {
    const constant_binding *found = constant_table_find(table, text_from(name));
    TEST_ASSERT_NOT_NULL_MESSAGE(found, name);
    TEST_ASSERT_EQUAL_UINT64(expected, found->value.integer);
}

static void test_destroy_accepts_null(void) { constant_table_destroy(NULL); }

static void test_an_empty_table_finds_nothing(void) {
    TEST_ASSERT_NULL(constant_table_find(table, text_from("a")));
}

static void test_finds_bound_names(void) {
    bind_integer("a", 1);
    bind_integer("bc", 2);
    assert_value("a", 1);
    assert_value("bc", 2);
    TEST_ASSERT_NULL(constant_table_find(table, text_from("b")));
    TEST_ASSERT_NULL(constant_table_find(table, text_from("abc")));
}

static void test_a_name_need_not_be_terminated(void) {
    bind_integer("key", 1);
    const syntax_text prefix = {"key_bits", strlen("key")};
    TEST_ASSERT_NOT_NULL(constant_table_find(table, prefix));
}

static void test_a_scope_hides_and_then_restores_a_name(void) {
    bind_integer("a", 1);
    open_scope(SCOPE_END);
    bind_integer("a", 2);
    assert_value("a", 2);
    constant_table_close_ended(table, SCOPE_END);
    assert_value("a", 1);
}

static void test_a_scope_stays_open_before_its_end(void) {
    open_scope(SCOPE_END);
    bind_integer("a", 1);
    constant_table_close_ended(table, BEFORE_END);
    assert_value("a", 1);
}

static void test_closing_drops_the_names_of_a_scope(void) {
    open_scope(SCOPE_END);
    bind_integer("a", 1);
    bind_integer("b", 2);
    constant_table_close_ended(table, SCOPE_END);
    TEST_ASSERT_NULL(constant_table_find(table, text_from("a")));
    TEST_ASSERT_NULL(constant_table_find(table, text_from("b")));
}

static void test_one_position_can_close_nested_scopes(void) {
    open_scope(LATE);
    open_scope(SCOPE_END);
    bind_integer("a", 1);
    constant_table_close_ended(table, LATE);
    TEST_ASSERT_NULL(constant_table_find(table, text_from("a")));
}

static void test_file_scope_lookup_ignores_locals(void) {
    bind_integer("a", 1);
    open_scope(SCOPE_END);
    bind_integer("a", 2);
    bind_integer("b", 3);
    const constant_binding *global = constant_table_find_file_scope(table, text_from("a"));
    TEST_ASSERT_NOT_NULL(global);
    TEST_ASSERT_EQUAL_UINT64(1, global->value.integer);
    TEST_ASSERT_NULL(constant_table_find_file_scope(table, text_from("b")));
}

static void test_setting_the_scope_position_leaves_outer_scopes_alone(void) {
    bind_integer("a", 1);
    open_scope(SCOPE_END);
    bind_integer("b", 2);
    constant_table_set_scope_position(table, SCOPE_END);
    TEST_ASSERT_EQUAL_UINT32(SCOPE_END, constant_table_find(table, text_from("b"))->position);
    TEST_ASSERT_EQUAL_UINT32(0, constant_table_find(table, text_from("a"))->position);
}

/* More names than buckets, so that each bucket must chain. */
static void test_keeps_many_names_apart(void) {
    static char names[COLLIDING_NAMES][NAME_SIZE];
    for (int i = 0; i < COLLIDING_NAMES; i++) {
        (void)snprintf(names[i], NAME_SIZE, "name_%d", i);
        bind_integer(names[i], (uint64_t)i);
    }
    for (int i = 0; i < COLLIDING_NAMES; i++) {
        assert_value(names[i], (uint64_t)i);
    }
}

static void test_a_full_table_says_so_for_good(void) {
    for (int i = 0; i < CONSTANT_TABLE_MAX_BINDINGS; i++) {
        bind_integer("a", 1);
    }
    TEST_ASSERT_FALSE(constant_table_is_saturated(table));
    bind_integer("b", 2);
    TEST_ASSERT_TRUE(constant_table_is_saturated(table));
    TEST_ASSERT_NULL(constant_table_find(table, text_from("b")));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_destroy_accepts_null);
    RUN_TEST(test_an_empty_table_finds_nothing);
    RUN_TEST(test_finds_bound_names);
    RUN_TEST(test_a_name_need_not_be_terminated);
    RUN_TEST(test_a_scope_hides_and_then_restores_a_name);
    RUN_TEST(test_a_scope_stays_open_before_its_end);
    RUN_TEST(test_closing_drops_the_names_of_a_scope);
    RUN_TEST(test_one_position_can_close_nested_scopes);
    RUN_TEST(test_file_scope_lookup_ignores_locals);
    RUN_TEST(test_setting_the_scope_position_leaves_outer_scopes_alone);
    RUN_TEST(test_keeps_many_names_apart);
    RUN_TEST(test_a_full_table_says_so_for_good);
    return UNITY_END();
}
