/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/clock.h"
#include "unity.h"

#include <time.h>

/* The year this test was written. A clock that reads earlier is wrong. */
enum { WRITTEN_IN = 2026, LAST_YEAR = 9999 };

void setUp(void) {}

void tearDown(void) {}

static void test_reads_a_plausible_year(void) {
    int year = 0;
    TEST_ASSERT_TRUE(pqscan_current_utc_year(&year));
    TEST_ASSERT_GREATER_OR_EQUAL_INT(WRITTEN_IN, year);
    TEST_ASSERT_LESS_OR_EQUAL_INT(LAST_YEAR, year);
}

static void test_the_monotonic_clock_does_not_go_back(void) {
    const time_t first = pqscan_monotonic_seconds();
    TEST_ASSERT_GREATER_OR_EQUAL_INT64((long long)first, (long long)pqscan_monotonic_seconds());
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_reads_a_plausible_year);
    RUN_TEST(test_the_monotonic_clock_does_not_go_back);
    return UNITY_END();
}
