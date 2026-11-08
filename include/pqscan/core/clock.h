/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_CORE_CLOCK_H
#define PQSCAN_CORE_CLOCK_H

#include <stdbool.h>
#include <time.h>

/**
 * @brief Read a clock that only moves forward, which makes it safe for deadlines.
 *
 * @return The seconds since an arbitrary start, or 0 if the system has no such clock.
 */
time_t pqscan_monotonic_seconds(void);

/**
 * @brief Read the current year in UTC from the wall clock.
 *
 * @param year Out: on success, the year, such as 2026. Untouched on failure.
 * @return true on success, false if the system cannot tell the date.
 */
bool pqscan_current_utc_year(int *year);

#endif /* PQSCAN_CORE_CLOCK_H */
