/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/utc_time.h"
#include "unity.h"

enum {
    SAMPLE_YEAR = 2031,
    SAMPLE_MONTH = 5,
    SAMPLE_DAY = 1,
    SAMPLE_HOUR = 12,
    SAMPLE_MINUTE = 3,
    SAMPLE_SECOND = 9,
    LAST_YEAR = 9999,
    LAST_MONTH = 12,
    LAST_DAY = 31,
    LAST_HOUR = 23,
    LAST_MINUTE = 59,
    LEAP_SECOND = 60,
};

void setUp(void) {}

void tearDown(void) {}

static const utc_time SAMPLE = {
    true, SAMPLE_YEAR, SAMPLE_MONTH, SAMPLE_DAY, SAMPLE_HOUR, SAMPLE_MINUTE, SAMPLE_SECOND,
};

static void test_writes_iso_8601_in_utc(void) {
    char text[UTC_TIME_TEXT_SIZE];
    utc_time_format(&SAMPLE, text, sizeof(text));
    TEST_ASSERT_EQUAL_STRING("2031-05-01T12:03:09Z", text);
}

static void test_writes_the_date_alone(void) {
    char text[UTC_TIME_TEXT_SIZE];
    utc_time_format_date(&SAMPLE, text, sizeof(text));
    TEST_ASSERT_EQUAL_STRING("2031-05-01", text);
}

static void test_pads_an_early_year(void) {
    const utc_time early = {true, 1, 1, 1, 0, 0, 0};
    char text[UTC_TIME_TEXT_SIZE];
    utc_time_format(&early, text, sizeof(text));
    TEST_ASSERT_EQUAL_STRING("0001-01-01T00:00:00Z", text);
}

static void test_the_latest_moment_fits(void) {
    const utc_time latest = {
        true, LAST_YEAR, LAST_MONTH, LAST_DAY, LAST_HOUR, LAST_MINUTE, LEAP_SECOND,
    };
    char text[UTC_TIME_TEXT_SIZE];
    utc_time_format(&latest, text, sizeof(text));
    TEST_ASSERT_EQUAL_STRING("9999-12-31T23:59:60Z", text);
}

static void test_no_moment_writes_nothing(void) {
    const utc_time none = utc_time_none();
    TEST_ASSERT_FALSE(none.known);
    char text[UTC_TIME_TEXT_SIZE] = "unchanged";
    utc_time_format(&none, text, sizeof(text));
    TEST_ASSERT_EQUAL_STRING("", text);
    char date[UTC_TIME_TEXT_SIZE] = "unchanged";
    utc_time_format_date(&none, date, sizeof(date));
    TEST_ASSERT_EQUAL_STRING("", date);
}

static void test_a_short_buffer_is_truncated_not_overrun(void) {
    char text[5];
    utc_time_format(&SAMPLE, text, sizeof(text));
    TEST_ASSERT_EQUAL_STRING("2031", text);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_writes_iso_8601_in_utc);
    RUN_TEST(test_writes_the_date_alone);
    RUN_TEST(test_pads_an_early_year);
    RUN_TEST(test_the_latest_moment_fits);
    RUN_TEST(test_no_moment_writes_nothing);
    RUN_TEST(test_a_short_buffer_is_truncated_not_overrun);
    return UNITY_END();
}
