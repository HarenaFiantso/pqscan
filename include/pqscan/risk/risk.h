/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_RISK_RISK_H
#define PQSCAN_RISK_RISK_H

#include "pqscan/core/key_size.h"

#include <stdbool.h>

/** How urgent a finding is. Values are ordered by severity, so they compare with <. */
typedef enum risk_level {
    RISK_OK = 0,
    RISK_REVIEW,
    RISK_QUANTUM_VULNERABLE,
    RISK_CLASSICALLY_WEAK,
} risk_level;

/** How many levels there are. Levels run from 0, so this also sizes an array indexed by level. */
enum { RISK_LEVEL_COUNT = RISK_CLASSICALLY_WEAK + 1 };

/** How a normalized algorithm is classified. */
typedef struct algorithm_policy {
    const char *name;         /**< Normalized name, such as "RSA". Not owned by this struct. */
    risk_level risk;          /**< The level at any key size. */
    unsigned weak_below_bits; /**< Keys below this are classically weak. 0 if none are. */
} algorithm_policy;

/**
 * @brief Name a risk level as it appears in reports.
 *
 * @param risk The risk level.
 * @return The name, such as "QUANTUM_VULNERABLE". Never NULL. The string has static
 *         storage duration: the caller must not modify or free it.
 */
const char *risk_level_name(risk_level risk);

/**
 * @brief Find the risk level with a given report name.
 *
 * @param name The name, such as "QUANTUM_VULNERABLE". Case-sensitive.
 * @param out On success, the level. Untouched on failure.
 * @return true on success, false if no level has this name.
 */
bool risk_level_parse(const char *name, risk_level *out);

/**
 * @brief Classify one use of an algorithm, keeping the most severe level that applies.
 *
 * A key size that is not known never changes the level, because guessing would hide or
 * invent a weakness.
 *
 * @param policy The algorithm.
 * @param size The key size of this use.
 * @return The risk level.
 */
risk_level risk_classify(const algorithm_policy *policy, key_size size);

#endif /* PQSCAN_RISK_RISK_H */
