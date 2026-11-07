/* SPDX-License-Identifier: Apache-2.0 */
#include "unity.h"
#include <fcntl.h>
#include <sys/stat.h>

void setUp(void) {}

void tearDown(void) {}

/* The real assertion is that this file compiles under -std=c11: each name is one that
 * the strict mode hides on a platform unless cmake/posix.cmake requests it. */
static void test_posix_names_are_visible(void) {
    struct stat info;
    TEST_ASSERT_EQUAL_INT(0, lstat(".", &info));
    TEST_ASSERT_NOT_EQUAL_INT(0, O_NOFOLLOW);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_posix_names_are_visible);
    return UNITY_END();
}
