/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/status.h"
#include "unity.h"

void setUp(void) {}

void tearDown(void) {}

static void test_every_status_has_a_distinct_message(void) {
    TEST_ASSERT_EQUAL_STRING("success", pqscan_status_message(PQSCAN_OK));
    TEST_ASSERT_EQUAL_STRING("out of memory", pqscan_status_message(PQSCAN_ERR_NOMEM));
    TEST_ASSERT_EQUAL_STRING("skipped, binary file", pqscan_status_message(PQSCAN_ERR_BINARY));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_every_status_has_a_distinct_message);
    return UNITY_END();
}
