/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_SCAN_CALL_ARGUMENTS_H
#define PQSCAN_SCAN_CALL_ARGUMENTS_H

#include "pqscan/core/key_size.h"
#include "pqscan/flow/constant_flow.h"
#include "pqscan/scan/syntax_parser.h"

#include <stdbool.h>
#include <stdint.h>
#include <tree_sitter/api.h>

/** One argument of a call. */
typedef struct call_argument {
    TSNode call;    /**< A call_expression node. */
    uint32_t index; /**< The position of the argument, from zero. */
} call_argument;

/** A string found in an argument. */
typedef struct string_argument {
    TSNode node;      /**< The argument itself, which may be a name for the string. */
    syntax_text text; /**< The text between the quotes, borrowed from the file. */
} string_argument;

/**
 * @brief Read an argument as a key size, resolving constants where it can be proved.
 *
 * @param argument The argument.
 * @param flow What names mean at this point.
 * @return KEY_SIZE_KNOWN for a resolved value, KEY_SIZE_UNKNOWN for any other expression, and
 *         KEY_SIZE_NOT_APPLICABLE if the argument is missing or a string, as when
 *         EVP_PKEY_Q_keygen() receives a curve name instead of a size.
 */
key_size call_key_size(const call_argument *argument, const constant_flow *flow);

/**
 * @brief Read an argument as a string, resolving constants where it can be proved.
 *
 * @param argument The argument.
 * @param flow What names mean at this point.
 * @param out On success, the string. Untouched on failure.
 * @return true on success, false if the argument is missing, does not resolve to a string,
 *         or holds escape sequences.
 */
bool call_string_argument(const call_argument *argument, const constant_flow *flow,
                          string_argument *out);

#endif /* PQSCAN_SCAN_CALL_ARGUMENTS_H */
