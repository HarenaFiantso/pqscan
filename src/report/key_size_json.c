/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/report/key_size_json.h"

#include "pqscan/core/key_size.h"
#include "pqscan/report/json_writer.h"

void key_size_json_write(json_writer *json, key_size size) {
    if (size.kind == KEY_SIZE_KNOWN) {
        json_uint(json, size.bits);
    } else if (size.kind == KEY_SIZE_UNKNOWN) {
        json_string(json, KEY_SIZE_JSON_UNKNOWN);
    } else {
        json_null(json);
    }
}
