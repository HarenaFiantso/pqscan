/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/memory.h"
#include "unity.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

void setUp(void) {}

void tearDown(void) {}

static void test_grow_allocates_then_doubles(void) {
    size_t capacity = 0;
    int *items = pqscan_array_grow(NULL, &capacity, sizeof(int));
    TEST_ASSERT_NOT_NULL(items);
    const size_t first_capacity = capacity;
    TEST_ASSERT_GREATER_THAN_size_t(0, first_capacity);

    int *grown = pqscan_array_grow(items, &capacity, sizeof(int));
    TEST_ASSERT_NOT_NULL(grown);
    TEST_ASSERT_EQUAL_size_t(first_capacity * 2, capacity);
    free(grown);
}

static void test_grow_rejects_capacity_overflow(void) {
    size_t capacity = (SIZE_MAX / 2) + 1;
    const size_t before = capacity;
    TEST_ASSERT_NULL(pqscan_array_grow(NULL, &capacity, 1));
    TEST_ASSERT_EQUAL_size_t(before, capacity);
}

static void test_grow_rejects_byte_size_overflow(void) {
    size_t capacity = SIZE_MAX / 2;
    TEST_ASSERT_NULL(pqscan_array_grow(NULL, &capacity, sizeof(int)));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_grow_allocates_then_doubles);
    RUN_TEST(test_grow_rejects_capacity_overflow);
    RUN_TEST(test_grow_rejects_byte_size_overflow);
    return UNITY_END();
}
