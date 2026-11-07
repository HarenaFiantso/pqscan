/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/version.h"
#include "unity.h"

void setUp(void) {}

void tearDown(void) {}

static void test_version_matches_cmake_project_version(void) {
    TEST_ASSERT_EQUAL_STRING(PQSCAN_EXPECTED_VERSION, pqscan_version());
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_version_matches_cmake_project_version);
    return UNITY_END();
}
