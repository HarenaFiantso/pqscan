/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Runs a fuzz target without libFuzzer, so that every build exercises it, including with
 * compilers that have no libFuzzer, such as Apple's Clang. Each file named on the command line
 * is run as it is, then cut at every length, then edited a fixed number of times by a seeded
 * generator, so a run is the same everywhere. Each input is an exact-size heap copy, so the
 * sanitizers catch a read past its end.
 */
#include "fuzz_target.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { MAX_SEED_SIZE = 1024 * 1024, EDITS_PER_SEED = 20000, MAX_CHANGES = 4 };

static const uint64_t GENERATOR_SEED = 0x9e3779b97f4a7c15U;
/* Marsaglia's shifts for a full-period 64-bit xorshift. */
static const unsigned SHIFT_A = 13U;
static const unsigned SHIFT_B = 7U;
static const unsigned SHIFT_C = 17U;

/* Values that tend to break size and offset arithmetic, written over a field. */
static const uint64_t TRICKY_VALUES[] = {
    0, 1, 24, 64, 0xff00U, 0x7fffffffU, 0xffffffffU, 0x8000000000000000U, UINT64_MAX,
};

typedef struct seed {
    unsigned char *data;
    size_t len;
} seed;

/* xorshift64: tiny, deterministic, and good enough to choose edits. */
static uint64_t next_random(uint64_t *state) {
    *state ^= *state << SHIFT_A;
    *state ^= *state >> SHIFT_B;
    *state ^= *state << SHIFT_C;
    return *state;
}

static void run_exact_copy(const unsigned char *data, size_t len) {
    unsigned char *copy = malloc((len > 0) ? len : 1);
    if (copy == NULL) {
        abort();
    }
    if (len > 0) {
        memcpy(copy, data, len);
    }
    (void)LLVMFuzzerTestOneInput(copy, len);
    free(copy);
}

static void write_tricky_value(unsigned char *data, size_t len, uint64_t *state) {
    const uint64_t value =
        TRICKY_VALUES[next_random(state) % (sizeof(TRICKY_VALUES) / sizeof(TRICKY_VALUES[0]))];
    const size_t width = sizeof(value);
    if (len < width) {
        return;
    }
    const size_t start = (size_t)(next_random(state) % (len - width + 1));
    memcpy(data + start, &value, width);
}

static void change_once(unsigned char *data, size_t len, uint64_t *state) {
    if (next_random(state) % 2 == 0) {
        write_tricky_value(data, len, state);
    } else {
        data[next_random(state) % len] = (unsigned char)next_random(state);
    }
}

static void run_edits(const seed *input, unsigned char *scratch, uint64_t *state) {
    for (size_t edit = 0; edit < EDITS_PER_SEED; edit++) {
        memcpy(scratch, input->data, input->len);
        const uint64_t changes = 1 + (next_random(state) % MAX_CHANGES);
        for (uint64_t i = 0; i < changes; i++) {
            change_once(scratch, input->len, state);
        }
        run_exact_copy(scratch, input->len);
    }
}

static void run_seed(const seed *input, uint64_t *state) {
    for (size_t len = 0; len <= input->len; len++) {
        run_exact_copy(input->data, len);
    }
    if (input->len == 0) {
        return;
    }
    unsigned char *scratch = malloc(input->len);
    if (scratch == NULL) {
        abort();
    }
    run_edits(input, scratch, state);
    free(scratch);
}

static bool read_seed(const char *path, seed *input) {
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        return false;
    }
    input->data = malloc(MAX_SEED_SIZE);
    input->len = (input->data != NULL) ? fread(input->data, 1, MAX_SEED_SIZE, file) : 0;
    const bool read = input->data != NULL && ferror(file) == 0 && feof(file) != 0;
    (void)fclose(file);
    return read;
}

int main(int argc, char **argv) {
    uint64_t state = GENERATOR_SEED;
    for (int i = 1; i < argc; i++) {
        seed input = {NULL, 0};
        const bool read = read_seed(argv[i], &input);
        if (read) {
            run_seed(&input, &state);
        }
        free(input.data);
        if (!read) {
            (void)fprintf(stderr, "replay: cannot read %s, or it is over 1 MiB\n", argv[i]);
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}
