/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/skip_list.h"
#include "pqscan/core/status.h"
#include "unity.h"

#include <stdlib.h>
#include <string.h>

enum { MANY_PATHS = 100 };

static skip_list *list;

void setUp(void) {
    list = skip_list_create();
    TEST_ASSERT_NOT_NULL(list);
}

void tearDown(void) { skip_list_destroy(list); }

static void test_new_list_is_empty(void) {
    TEST_ASSERT_EQUAL_size_t(0, skip_list_count(list));
    TEST_ASSERT_NULL(skip_list_get(list, 0));
}

static void test_add_copies_the_path(void) {
    char *path = strdup("a.c");
    TEST_ASSERT_NOT_NULL(path);
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, skip_list_add(list, path, PQSCAN_ERR_BINARY));
    free(path);

    const skipped_path *stored = skip_list_get(list, 0);
    TEST_ASSERT_NOT_NULL(stored);
    TEST_ASSERT_EQUAL_STRING("a.c", stored->path);
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_BINARY, stored->reason);
}

static void test_grows_and_keeps_order(void) {
    for (size_t i = 0; i < MANY_PATHS; i++) {
        const pqscan_status reason = (i == 0) ? PQSCAN_ERR_IO : PQSCAN_ERR_BUDGET;
        TEST_ASSERT_EQUAL_INT(PQSCAN_OK, skip_list_add(list, "a.c", reason));
    }
    TEST_ASSERT_EQUAL_size_t(MANY_PATHS, skip_list_count(list));
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_IO, skip_list_get(list, 0)->reason);
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_BUDGET, skip_list_get(list, MANY_PATHS - 1)->reason);
}

static void test_destroy_accepts_null(void) { skip_list_destroy(NULL); }

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_new_list_is_empty);
    RUN_TEST(test_add_copies_the_path);
    RUN_TEST(test_grows_and_keeps_order);
    RUN_TEST(test_destroy_accepts_null);
    return UNITY_END();
}
