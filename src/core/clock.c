/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/clock.h"

#include <stdbool.h>
#include <time.h>

time_t pqscan_monotonic_seconds(void) {
    struct timespec now;
    return (clock_gettime(CLOCK_MONOTONIC, &now) == 0) ? now.tv_sec : 0;
}

/* struct tm counts years from 1900. */
enum { TM_YEAR_BASE = 1900 };

bool pqscan_current_utc_year(int *year) {
    const time_t now = time(NULL);
    struct tm parts;
    if (now == (time_t)-1 || gmtime_r(&now, &parts) == NULL) {
        return false;
    }
    *year = parts.tm_year + TM_YEAR_BASE;
    return true;
}
