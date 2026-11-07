/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/status.h"
#include "pqscan/core/string_list.h"
#include "unity.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { MANY_STRINGS = 100, LABEL_SIZE = 16 };

static string_list *list;

void setUp(void) {
    list = string_list_create();
    TEST_ASSERT_NOT_NULL(list);
}

void tearDown(void) { string_list_destroy(list); }

static void test_new_list_is_empty(void) {
    TEST_ASSERT_EQUAL_size_t(0, string_list_count(list));
    TEST_ASSERT_NULL(string_list_get(list, 0));
    TEST_ASSERT_NULL(string_list_pop(list));
}

static void test_add_keeps_its_own_copy(void) {
    char *text = strdup("original");
    TEST_ASSERT_NOT_NULL(text);
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, string_list_add(list, text));
    free(text);
    TEST_ASSERT_EQUAL_STRING("original", string_list_get(list, 0));
}

static void test_add_owned_adopts_the_pointer(void) {
    char *text = strdup("adopted");
    TEST_ASSERT_NOT_NULL(text);
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, string_list_add_owned(list, text));
    TEST_ASSERT_EQUAL_PTR(text, string_list_get(list, 0));
}

static void test_pop_returns_last_and_transfers_ownership(void) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, string_list_add(list, "first"));
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, string_list_add(list, "second"));
    char *popped = string_list_pop(list);
    TEST_ASSERT_EQUAL_STRING("second", popped);
    TEST_ASSERT_EQUAL_size_t(1, string_list_count(list));
    free(popped);
}

static void test_grows_past_initial_capacity(void) {
    for (int i = 0; i < MANY_STRINGS; i++) {
        char label[LABEL_SIZE];
        TEST_ASSERT_GREATER_THAN_INT(0, snprintf(label, sizeof(label), "%d", i));
        TEST_ASSERT_EQUAL_INT(PQSCAN_OK, string_list_add(list, label));
    }
    TEST_ASSERT_EQUAL_size_t(MANY_STRINGS, string_list_count(list));
    TEST_ASSERT_EQUAL_STRING("0", string_list_get(list, 0));
    TEST_ASSERT_EQUAL_STRING("99", string_list_get(list, MANY_STRINGS - 1));
}

static void test_sort_orders_by_byte_value(void) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, string_list_add(list, "b"));
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, string_list_add(list, "a"));
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, string_list_add(list, "B"));
    string_list_sort(list);
    TEST_ASSERT_EQUAL_STRING("B", string_list_get(list, 0));
    TEST_ASSERT_EQUAL_STRING("a", string_list_get(list, 1));
    TEST_ASSERT_EQUAL_STRING("b", string_list_get(list, 2));
}

static void test_destroy_accepts_null(void) { string_list_destroy(NULL); }

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_new_list_is_empty);
    RUN_TEST(test_add_keeps_its_own_copy);
    RUN_TEST(test_add_owned_adopts_the_pointer);
    RUN_TEST(test_pop_returns_last_and_transfers_ownership);
    RUN_TEST(test_grows_past_initial_capacity);
    RUN_TEST(test_sort_orders_by_byte_value);
    RUN_TEST(test_destroy_accepts_null);
    return UNITY_END();
}
