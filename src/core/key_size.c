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

static int compare_numbers(unsigned left, unsigned right) {
    return (left > right) - (left < right);
}

/* The bits of a size that is not known mean nothing, so they never break a tie. */
int key_size_compare(key_size left, key_size right) {
    const int order = compare_numbers((unsigned)left.kind, (unsigned)right.kind);
    if (order != 0 || left.kind != KEY_SIZE_KNOWN) {
        return order;
    }
    return compare_numbers(left.bits, right.bits);
}
