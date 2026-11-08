/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_FUZZ_FUZZ_TARGET_H
#define PQSCAN_FUZZ_FUZZ_TARGET_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Run one input through the code under test. libFuzzer calls it, and so does the
 *        replay driver, so every fuzz target defines it.
 *
 * @param data The input. Not modified, and only valid during the call.
 * @param size How many bytes it has.
 * @return 0. A bug makes it abort instead.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#endif /* PQSCAN_FUZZ_FUZZ_TARGET_H */
