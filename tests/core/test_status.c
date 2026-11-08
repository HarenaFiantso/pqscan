/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/status.h"
#include "unity.h"

void setUp(void) {}

void tearDown(void) {}

static void test_every_status_has_a_distinct_message(void) {
    TEST_ASSERT_EQUAL_STRING("success", pqscan_status_message(PQSCAN_OK));
    TEST_ASSERT_EQUAL_STRING("out of memory", pqscan_status_message(PQSCAN_ERR_NOMEM));
    TEST_ASSERT_EQUAL_STRING("skipped, binary file", pqscan_status_message(PQSCAN_ERR_BINARY));
    TEST_ASSERT_EQUAL_STRING("skipped, cannot parse source in time",
                             pqscan_status_message(PQSCAN_ERR_PARSE));
    TEST_ASSERT_EQUAL_STRING("invalid rules", pqscan_status_message(PQSCAN_ERR_RULES));
    TEST_ASSERT_EQUAL_STRING("skipped, scan time budget used up",
                             pqscan_status_message(PQSCAN_ERR_BUDGET));
    TEST_ASSERT_EQUAL_STRING("skipped, encrypted key", pqscan_status_message(PQSCAN_ERR_ENCRYPTED));
    TEST_ASSERT_EQUAL_STRING("skipped, not a certificate or key that can be read",
                             pqscan_status_message(PQSCAN_ERR_MALFORMED));
    TEST_ASSERT_EQUAL_STRING("skipped, malformed ELF file",
                             pqscan_status_message(PQSCAN_ERR_ELF_MALFORMED));
    TEST_ASSERT_EQUAL_STRING("skipped, not a 64-bit ELF file",
                             pqscan_status_message(PQSCAN_ERR_ELF_UNSUPPORTED));
    TEST_ASSERT_EQUAL_STRING("skipped, ELF file without a symbol table",
                             pqscan_status_message(PQSCAN_ERR_ELF_NO_SYMBOLS));
    TEST_ASSERT_EQUAL_STRING("invalid project file", pqscan_status_message(PQSCAN_ERR_PROJECT));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_every_status_has_a_distinct_message);
    return UNITY_END();
}
