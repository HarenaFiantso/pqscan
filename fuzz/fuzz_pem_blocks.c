/* SPDX-License-Identifier: Apache-2.0 */
#include "fuzz_checks.h"
#include "fuzz_target.h"

#include "pqscan/scan/pem_blocks.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/* The label is part of the BEGIN line, so it lies inside the block. */
static bool is_sound(const pem_block *block, const fuzz_input *input) {
    const fuzz_input inside = {(uintptr_t)block->text, block->len};
    return block->line > 0 && block->len > 0 && fuzz_lies_inside(input, block->text, block->len) &&
           fuzz_lies_inside(&inside, block->label, block->label_len);
}

/* Blocks come in order and never overlap, as a truncated block stops before the next one. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const fuzz_input input = {(uintptr_t)data, size};
    pem_finder finder;
    pem_finder_init(&finder, (const char *)data, size);
    pem_block block;
    uintptr_t previous_end = input.start;
    size_t previous_line = 0;
    while (pem_finder_next(&finder, &block)) {
        const uintptr_t start = (uintptr_t)block.text;
        if (!is_sound(&block, &input) || start < previous_end || block.line <= previous_line) {
            abort();
        }
        previous_end = start + block.len;
        previous_line = block.line;
    }
    return 0;
}
