/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_SCAN_CALL_ARGUMENTS_H
#define PQSCAN_SCAN_CALL_ARGUMENTS_H

#include "pqscan/core/finding.h"
#include "pqscan/scan/file_reader.h"

#include <stdbool.h>
#include <stdint.h>
#include <tree_sitter/api.h>

/**
 * @brief Read an argument of a call as a key size.
 *
 * Only literals resolve, including through casts and parentheses, such as (int)2048 or
 * 0x800u. Nothing is computed, so 1 << 11 or a variable stays unknown.
 *
 * @param call A call_expression node.
 * @param index The position of the argument, from zero.
 * @param file The file the node was parsed from.
 * @return KEY_SIZE_KNOWN for a literal, KEY_SIZE_UNKNOWN for any other expression, and
 *         KEY_SIZE_NOT_APPLICABLE if the argument is missing or a string, as when
 *         EVP_PKEY_Q_keygen() receives a curve name instead of a size.
 */
key_size call_key_size(TSNode call, uint32_t index, const file_contents *file);

/**
 * @brief Find the text of an argument that is a plain string literal.
 *
 * @param call A call_expression node.
 * @param index The position of the argument, from zero.
 * @param out On success, the node holding the text between the quotes. Untouched on failure.
 * @return true on success, false if the argument is missing, is not a string literal, or
 *         holds escape sequences.
 */
bool call_string_argument(TSNode call, uint32_t index, TSNode *out);

#endif /* PQSCAN_SCAN_CALL_ARGUMENTS_H */
