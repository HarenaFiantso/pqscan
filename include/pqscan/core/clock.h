/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_CORE_CLOCK_H
#define PQSCAN_CORE_CLOCK_H

#include <time.h>

/**
 * @brief Read a clock that only moves forward, which makes it safe for deadlines.
 *
 * @return The seconds since an arbitrary start, or 0 if the system has no such clock.
 */
time_t pqscan_monotonic_seconds(void);

#endif /* PQSCAN_CORE_CLOCK_H */
