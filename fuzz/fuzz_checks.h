/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_FUZZ_FUZZ_CHECKS_H
#define PQSCAN_FUZZ_FUZZ_CHECKS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** An input, as integers. A buggy parser could return a pointer outside it, and comparing
 *  pointers into different objects is undefined, so addresses are compared as integers. */
typedef struct fuzz_input {
    uintptr_t start;
    size_t len;
} fuzz_input;

/**
 * @brief Tell whether a range of bytes lies inside the input.
 *
 * @param input The input.
 * @param text The start of the range.
 * @param len Its length.
 * @return true if every byte of the range is a byte of the input.
 */
static inline bool fuzz_lies_inside(const fuzz_input *input, const char *text, size_t len) {
    const uintptr_t start = (uintptr_t)text;
    return start >= input->start && start - input->start <= input->len &&
           len <= input->len - (start - input->start);
}

/**
 * @brief Count the lines of an input, as scanners number them: one more than its line breaks.
 *
 * @param data The input.
 * @param size How many bytes it has.
 * @return The number of lines, at least 1.
 */
static inline size_t fuzz_count_lines(const uint8_t *data, size_t size) {
    size_t lines = 1;
    for (size_t i = 0; i < size; i++) {
        lines += (data[i] == '\n') ? 1 : 0;
    }
    return lines;
}

#endif /* PQSCAN_FUZZ_FUZZ_CHECKS_H */
