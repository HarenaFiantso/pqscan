/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_REPORT_KEY_SIZE_JSON_H
#define PQSCAN_REPORT_KEY_SIZE_JSON_H

#include "pqscan/core/key_size.h"
#include "pqscan/report/json_writer.h"

/** What a key size the code hides is written as, in place of its bits. */
#define KEY_SIZE_JSON_UNKNOWN "unknown"

/**
 * @brief Write a key size as a JSON value: its bits, "unknown" when the code hides it, and null
 *        when the algorithm has none. Every JSON file pqscan writes uses this form.
 *
 * @param json The writer, where a value is expected.
 * @param size The key size.
 */
void key_size_json_write(json_writer *json, key_size size);

#endif /* PQSCAN_REPORT_KEY_SIZE_JSON_H */
