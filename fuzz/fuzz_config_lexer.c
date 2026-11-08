/* SPDX-License-Identifier: Apache-2.0 */
#include "fuzz_checks.h"
#include "fuzz_target.h"

#include "pqscan/scan/config_lexer.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

static bool is_sound(const config_statement *statement, const fuzz_input *input, size_t lines) {
    if (statement->count == 0 || statement->count > CONFIG_MAX_WORDS) {
        return false;
    }
    for (size_t i = 0; i < statement->count; i++) {
        const config_word *word = &statement->words[i];
        if (!fuzz_lies_inside(input, word->text, word->len) || word->line == 0 ||
            word->line > lines) {
            return false;
        }
    }
    return true;
}

/* Every statement takes at least one byte, so more statements than bytes means a loop. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const fuzz_input input = {(uintptr_t)data, size};
    const size_t lines = fuzz_count_lines(data, size);
    config_lexer lexer;
    config_lexer_init(&lexer, (const char *)data, size);
    config_statement statement;
    size_t statements = 0;
    while (config_lexer_next(&lexer, &statement)) {
        if (!is_sound(&statement, &input, lines) || ++statements > size) {
            abort();
        }
    }
    return 0;
}
