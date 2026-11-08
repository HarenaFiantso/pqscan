/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_CORE_UTC_TIME_H
#define PQSCAN_CORE_UTC_TIME_H

#include <stdbool.h>
#include <stddef.h>

/** Room for "YYYY-MM-DDTHH:MM:SSZ" and its NUL. */
enum { UTC_TIME_TEXT_SIZE = 21 };

/** A moment in UTC, to the second, such as the end of a certificate's validity. */
typedef struct utc_time {
    bool known; /**< false when there is no such moment. The other fields are then 0. */
    int year;   /**< From 0 to 9999. */
    int month;  /**< From 1 to 12. */
    int day;    /**< From 1 to 31. */
    int hour;   /**< From 0 to 23. */
    int minute; /**< From 0 to 59. */
    int second; /**< From 0 to 60, as a leap second can be stated. */
} utc_time;

/**
 * @brief Make the value that stands for no moment at all.
 *
 * @return A utc_time whose known is false.
 */
utc_time utc_time_none(void);

/**
 * @brief Write a moment in ISO 8601, as "2031-05-01T12:00:00Z".
 *
 * @param time The moment.
 * @param text Out: the text, NUL-terminated, or empty if @p time is not known.
 * @param capacity The size of @p text. UTC_TIME_TEXT_SIZE is always enough for fields in range.
 */
void utc_time_format(const utc_time *time, char *text, size_t capacity);

/**
 * @brief Write only the date of a moment, as "2031-05-01".
 *
 * @param time The moment.
 * @param text Out: the text, NUL-terminated, or empty if @p time is not known.
 * @param capacity The size of @p text. UTC_TIME_TEXT_SIZE is always enough for fields in range.
 */
void utc_time_format_date(const utc_time *time, char *text, size_t capacity);

#endif /* PQSCAN_CORE_UTC_TIME_H */
