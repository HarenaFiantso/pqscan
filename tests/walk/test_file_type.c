/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/walk/file_type.h"
#include "unity.h"

#include <stddef.h>

void setUp(void) {}

void tearDown(void) {}

static void test_accepts_c_and_cpp_extensions(void) {
    TEST_ASSERT_TRUE(file_type_is_source("a.c"));
    TEST_ASSERT_TRUE(file_type_is_source("dir/a.h"));
    TEST_ASSERT_TRUE(file_type_is_source("a.cpp"));
    TEST_ASSERT_TRUE(file_type_is_source("a.hpp"));
    TEST_ASSERT_TRUE(file_type_is_source("a.tar.c"));
}

static void test_accepts_the_other_cpp_extensions(void) {
    static const char *const PATHS[] = {
        "a.cc", "a.cxx", "a.C", "a.hh", "a.hxx", "a.ipp", "a.inl", "a.tcc",
    };
    for (size_t i = 0; i < sizeof(PATHS) / sizeof(PATHS[0]); i++) {
        TEST_ASSERT_TRUE_MESSAGE(file_type_is_source(PATHS[i]), PATHS[i]);
        TEST_ASSERT_EQUAL_INT_MESSAGE(SOURCE_LANGUAGE_CPP, file_type_source_language(PATHS[i]),
                                      PATHS[i]);
    }
}

static void test_rejects_everything_else(void) {
    TEST_ASSERT_FALSE(file_type_is_source("a.txt"));
    TEST_ASSERT_FALSE(file_type_is_source("Makefile"));
    TEST_ASSERT_FALSE(file_type_is_source("a.H.txt"));
    TEST_ASSERT_FALSE(file_type_is_source("a.CC"));
    TEST_ASSERT_FALSE(file_type_is_source("a.c.orig"));
    TEST_ASSERT_FALSE(file_type_is_source("dir.c/README"));
    TEST_ASSERT_FALSE(file_type_is_source(""));
}

static void test_c_files_use_the_c_grammar(void) {
    TEST_ASSERT_EQUAL_INT(SOURCE_LANGUAGE_C, file_type_source_language("dir/a.c"));
    TEST_ASSERT_EQUAL_INT(SOURCE_LANGUAGE_C, file_type_source_language("a.tar.c"));
}

static void test_headers_and_cpp_files_use_the_cpp_grammar(void) {
    TEST_ASSERT_EQUAL_INT(SOURCE_LANGUAGE_CPP, file_type_source_language("a.h"));
    TEST_ASSERT_EQUAL_INT(SOURCE_LANGUAGE_CPP, file_type_source_language("a.cpp"));
    TEST_ASSERT_EQUAL_INT(SOURCE_LANGUAGE_CPP, file_type_source_language("a.hpp"));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_accepts_c_and_cpp_extensions);
    RUN_TEST(test_accepts_the_other_cpp_extensions);
    RUN_TEST(test_rejects_everything_else);
    RUN_TEST(test_c_files_use_the_c_grammar);
    RUN_TEST(test_headers_and_cpp_files_use_the_cpp_grammar);
    return UNITY_END();
}
