/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/clock.h"

#include <time.h>

time_t pqscan_monotonic_seconds(void) {
    struct timespec now;
    return (clock_gettime(CLOCK_MONOTONIC, &now) == 0) ? now.tv_sec : 0;
}
