/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/finding.h"
#include "pqscan/core/key_size.h"
#include "pqscan/core/primitive.h"
#include "pqscan/core/status.h"
#include "pqscan/core/utc_time.h"
#include "pqscan/risk/priority.h"
#include "pqscan/risk/risk.h"
#include "unity.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

enum { MANY_FINDINGS = 100, SAMPLE_LINE = 7, SAMPLE_BITS = 2048 };

static finding_list *list;

void setUp(void) {
    list = finding_list_create();
    TEST_ASSERT_NOT_NULL(list);
}

void tearDown(void) { finding_list_destroy(list); }

static void test_new_list_is_empty(void) {
    TEST_ASSERT_EQUAL_size_t(0, finding_list_count(list));
    TEST_ASSERT_NULL(finding_list_get(list, 0));
}

static void test_add_copies_the_path(void) {
    char *path = strdup("a.c");
    TEST_ASSERT_NOT_NULL(path);
    const finding item = {
        path,
        SAMPLE_LINE,
        "RSA",
        RISK_QUANTUM_VULNERABLE,
        {KEY_SIZE_KNOWN, SAMPLE_BITS},
        PRIMITIVE_SIGNATURE,
        "RSA_sign",
        utc_time_none(),
        priority_none(),
    };
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, finding_list_add(list, &item));
    free(path);

    const finding *stored = finding_list_get(list, 0);
    TEST_ASSERT_NOT_NULL(stored);
    TEST_ASSERT_EQUAL_STRING("a.c", stored->path);
    TEST_ASSERT_EQUAL_size_t(SAMPLE_LINE, stored->line);
    TEST_ASSERT_EQUAL_STRING("RSA", stored->algorithm);
    TEST_ASSERT_EQUAL_INT(RISK_QUANTUM_VULNERABLE, stored->risk);
    TEST_ASSERT_EQUAL_INT(KEY_SIZE_KNOWN, stored->size.kind);
    TEST_ASSERT_EQUAL_UINT(SAMPLE_BITS, stored->size.bits);
    TEST_ASSERT_EQUAL_INT(PRIMITIVE_SIGNATURE, stored->primitive);
    TEST_ASSERT_EQUAL_STRING("RSA_sign", stored->symbol);
}

static void test_grows_and_keeps_order(void) {
    for (size_t line = 1; line <= MANY_FINDINGS; line++) {
        const finding item = {
            "a.c",
            line,
            "MD5",
            RISK_CLASSICALLY_WEAK,
            {KEY_SIZE_NOT_APPLICABLE, 0},
            PRIMITIVE_HASH,
            "MD5",
            utc_time_none(),
            priority_none(),
        };
        TEST_ASSERT_EQUAL_INT(PQSCAN_OK, finding_list_add(list, &item));
    }
    TEST_ASSERT_EQUAL_size_t(MANY_FINDINGS, finding_list_count(list));
    TEST_ASSERT_EQUAL_size_t(1, finding_list_get(list, 0)->line);
    TEST_ASSERT_EQUAL_size_t(MANY_FINDINGS, finding_list_get(list, MANY_FINDINGS - 1)->line);
}

static void test_pointers_follow_the_list_order(void) {
    for (size_t line = 1; line <= MANY_FINDINGS; line++) {
        const finding item = {
            "a.c",
            line,
            "MD5",
            RISK_CLASSICALLY_WEAK,
            {KEY_SIZE_NOT_APPLICABLE, 0},
            PRIMITIVE_HASH,
            "MD5",
            utc_time_none(),
            priority_none(),
        };
        TEST_ASSERT_EQUAL_INT(PQSCAN_OK, finding_list_add(list, &item));
    }
    const finding **pointers = finding_list_pointers(list);
    TEST_ASSERT_NOT_NULL(pointers);
    for (size_t i = 0; i < MANY_FINDINGS; i++) {
        TEST_ASSERT_EQUAL_PTR(finding_list_get(list, i), pointers[i]);
    }
    free((void *)pointers);
}

static void test_an_empty_list_has_pointers_to_free(void) {
    const finding **pointers = finding_list_pointers(list);
    TEST_ASSERT_NOT_NULL(pointers);
    free((void *)pointers);
}

static void add_line(size_t line) {
    const finding item = {
        "a.c",          line,  "MD5",           RISK_CLASSICALLY_WEAK, {KEY_SIZE_NOT_APPLICABLE, 0},
        PRIMITIVE_HASH, "MD5", utc_time_none(), priority_none(),
    };
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, finding_list_add(list, &item));
}

static void test_a_new_finding_keeps_the_priority_it_was_given(void) {
    add_line(1);
    TEST_ASSERT_EQUAL_UINT(0, finding_list_get(list, 0)->priority.score);
    TEST_ASSERT_FALSE(finding_list_get(list, 0)->priority.timeline.applies);
}

static void test_sets_the_priority_of_one_finding(void) {
    add_line(1);
    add_line(2);
    priority urgent = priority_none();
    urgent.score = PRIORITY_MAX_SCORE;
    urgent.component = "vault";
    finding_list_set_priority(list, 1, urgent);
    TEST_ASSERT_EQUAL_UINT(0, finding_list_get(list, 0)->priority.score);
    TEST_ASSERT_EQUAL_UINT(PRIORITY_MAX_SCORE, finding_list_get(list, 1)->priority.score);
    TEST_ASSERT_EQUAL_STRING("vault", finding_list_get(list, 1)->priority.component);
}

static void test_setting_a_priority_out_of_range_does_nothing(void) {
    finding_list_set_priority(list, 0, priority_none());
    TEST_ASSERT_EQUAL_size_t(0, finding_list_count(list));
}

static int by_line_descending(const void *left, const void *right) {
    const finding *first = left;
    const finding *second = right;
    return (first->line < second->line) - (first->line > second->line);
}

static void test_sorts_with_the_given_order_and_keeps_every_path(void) {
    for (size_t line = 1; line <= MANY_FINDINGS; line++) {
        add_line(line);
    }
    finding_list_sort(list, by_line_descending);
    for (size_t i = 0; i < MANY_FINDINGS; i++) {
        TEST_ASSERT_EQUAL_size_t(MANY_FINDINGS - i, finding_list_get(list, i)->line);
        TEST_ASSERT_EQUAL_STRING("a.c", finding_list_get(list, i)->path);
    }
}

static void test_sorting_an_empty_list_does_nothing(void) {
    finding_list_sort(list, by_line_descending);
    TEST_ASSERT_EQUAL_size_t(0, finding_list_count(list));
}

static void test_destroy_accepts_null(void) { finding_list_destroy(NULL); }

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_new_list_is_empty);
    RUN_TEST(test_add_copies_the_path);
    RUN_TEST(test_grows_and_keeps_order);
    RUN_TEST(test_pointers_follow_the_list_order);
    RUN_TEST(test_an_empty_list_has_pointers_to_free);
    RUN_TEST(test_a_new_finding_keeps_the_priority_it_was_given);
    RUN_TEST(test_sets_the_priority_of_one_finding);
    RUN_TEST(test_setting_a_priority_out_of_range_does_nothing);
    RUN_TEST(test_sorts_with_the_given_order_and_keeps_every_path);
    RUN_TEST(test_sorting_an_empty_list_does_nothing);
    RUN_TEST(test_destroy_accepts_null);
    return UNITY_END();
}
