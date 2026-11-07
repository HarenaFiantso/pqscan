/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/key_size.h"
#include "unity.h"

#include <limits.h>
#include <stdio.h>

enum { SAMPLE_BITS = 2048 };

void setUp(void) {}

void tearDown(void) {}

static void assert_suffix(key_size size, const char *expected) {
    char suffix[KEY_SIZE_SUFFIX_SIZE];
    key_size_format_suffix(size, suffix, sizeof(suffix));
    TEST_ASSERT_EQUAL_STRING(expected, suffix);
}

static void test_a_known_size_shows_its_bits(void) {
    assert_suffix((key_size){KEY_SIZE_KNOWN, SAMPLE_BITS}, "-2048");
}

static void test_an_unresolved_size_says_so(void) {
    assert_suffix((key_size){KEY_SIZE_UNKNOWN, 0}, "-unknown");
}

static void test_no_size_shows_nothing(void) {
    assert_suffix((key_size){KEY_SIZE_NOT_APPLICABLE, 0}, "");
}

static void test_the_largest_size_fits(void) {
    const unsigned largest = UINT_MAX;
    char expected[KEY_SIZE_SUFFIX_SIZE];
    const int len = snprintf(expected, sizeof(expected), "-%u", largest);
    TEST_ASSERT_GREATER_THAN_INT(0, len);
    assert_suffix((key_size){KEY_SIZE_KNOWN, largest}, expected);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_a_known_size_shows_its_bits);
    RUN_TEST(test_an_unresolved_size_says_so);
    RUN_TEST(test_no_size_shows_nothing);
    RUN_TEST(test_the_largest_size_fits);
    return UNITY_END();
}
