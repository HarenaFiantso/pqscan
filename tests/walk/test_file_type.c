/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/walk/file_type.h"
#include "unity.h"

void setUp(void) {}

void tearDown(void) {}

static void test_accepts_c_and_cpp_extensions(void) {
    TEST_ASSERT_TRUE(file_type_is_source("a.c"));
    TEST_ASSERT_TRUE(file_type_is_source("dir/a.h"));
    TEST_ASSERT_TRUE(file_type_is_source("a.cpp"));
    TEST_ASSERT_TRUE(file_type_is_source("a.hpp"));
    TEST_ASSERT_TRUE(file_type_is_source("a.tar.c"));
}

static void test_rejects_everything_else(void) {
    TEST_ASSERT_FALSE(file_type_is_source("a.txt"));
    TEST_ASSERT_FALSE(file_type_is_source("Makefile"));
    TEST_ASSERT_FALSE(file_type_is_source("a.C"));
    TEST_ASSERT_FALSE(file_type_is_source("a.c.orig"));
    TEST_ASSERT_FALSE(file_type_is_source("dir.c/README"));
    TEST_ASSERT_FALSE(file_type_is_source(""));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_accepts_c_and_cpp_extensions);
    RUN_TEST(test_rejects_everything_else);
    return UNITY_END();
}
