/* SPDX-License-Identifier: Apache-2.0 */
#include "fuzz_target.h"

#include "pqscan/core/status.h"
#include "pqscan/scan/elf_reader.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct fuzz_input {
    uintptr_t start;
    size_t len;
} fuzz_input;

/* Addresses are compared as integers, since a buggy name could point outside the input, and
 * comparing pointers into different objects is undefined. */
static bool lies_inside(const fuzz_input *input, const elf_symbol *symbol) {
    const uintptr_t name = (uintptr_t)symbol->name;
    return name >= input->start && symbol->len < input->len &&
           name - input->start < input->len - symbol->len;
}

// cppcheck-suppress constParameterCallback
static pqscan_status check_symbol(const elf_symbol *symbol, void *context) {
    const fuzz_input *input = context;
    if (!lies_inside(input, symbol) || symbol->name[symbol->len] != '\0' ||
        symbol->len > ELF_MAX_SYMBOL_NAME) {
        abort();
    }
    return PQSCAN_OK;
}

static bool is_expected(pqscan_status status) {
    return status == PQSCAN_OK || status == PQSCAN_ERR_ELF_MALFORMED ||
           status == PQSCAN_ERR_ELF_UNSUPPORTED || status == PQSCAN_ERR_ELF_NO_SYMBOLS;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    fuzz_input input = {(uintptr_t)data, size};
    const elf_symbol_sink sink = {check_symbol, &input};
    if (!is_expected(elf_read_symbols(data, size, &sink))) {
        abort();
    }
    return 0;
}
