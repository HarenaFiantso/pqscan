/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/utc_time.h"

#include <stddef.h>
#include <stdio.h>

utc_time utc_time_none(void) {
    const utc_time none = {false, 0, 0, 0, 0, 0, 0};
    return none;
}

static void clear_text(char *text, size_t capacity) {
    if (capacity > 0) {
        text[0] = '\0';
    }
}

void utc_time_format(const utc_time *time, char *text, size_t capacity) {
    if (!time->known) {
        clear_text(text, capacity);
        return;
    }
    (void)snprintf(text, capacity, "%04d-%02d-%02dT%02d:%02d:%02dZ", time->year, time->month,
                   time->day, time->hour, time->minute, time->second);
}

void utc_time_format_date(const utc_time *time, char *text, size_t capacity) {
    if (!time->known) {
        clear_text(text, capacity);
        return;
    }
    (void)snprintf(text, capacity, "%04d-%02d-%02d", time->year, time->month, time->day);
}
