/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/key_size.h"

#include <stddef.h>
#include <stdio.h>

void key_size_format_suffix(key_size size, char *suffix, size_t capacity) {
    suffix[0] = '\0';
    if (size.kind == KEY_SIZE_KNOWN) {
        (void)snprintf(suffix, capacity, "-%u", size.bits);
    } else if (size.kind == KEY_SIZE_UNKNOWN) {
        (void)snprintf(suffix, capacity, "-unknown");
    }
}
