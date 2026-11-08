/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/finding.h"
#include "pqscan/core/key_size.h"
#include "pqscan/core/primitive.h"
#include "pqscan/core/status.h"
#include "pqscan/core/utc_time.h"
#include "pqscan/report/report_summary.h"
#include "pqscan/risk/priority.h"
#include "pqscan/risk/risk.h"
#include "unity.h"

void setUp(void) {}

void tearDown(void) {}

static void add_finding(finding_list *list, risk_level risk) {
    const finding item = {
        "a.c",
        1,
        "X",
        risk,
        {KEY_SIZE_NOT_APPLICABLE, 0},
        PRIMITIVE_UNSPECIFIED,
        "x",
        utc_time_none(),
        priority_none(),
    };
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, finding_list_add(list, &item));
}

static void test_counts_each_level(void) {
    finding_list *list = finding_list_create();
    TEST_ASSERT_NOT_NULL(list);
    add_finding(list, RISK_REVIEW);
    add_finding(list, RISK_CLASSICALLY_WEAK);
    add_finding(list, RISK_REVIEW);

    const risk_counts counts = risk_counts_of(list);
    finding_list_destroy(list);
    TEST_ASSERT_EQUAL_size_t(0, counts.by_level[RISK_OK]);
    TEST_ASSERT_EQUAL_size_t(2, counts.by_level[RISK_REVIEW]);
    TEST_ASSERT_EQUAL_size_t(0, counts.by_level[RISK_QUANTUM_VULNERABLE]);
    TEST_ASSERT_EQUAL_size_t(1, counts.by_level[RISK_CLASSICALLY_WEAK]);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_counts_each_level);
    return UNITY_END();
}
