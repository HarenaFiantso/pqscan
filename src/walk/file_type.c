/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/walk/file_type.h"

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

static const char *const SOURCE_EXTENSIONS[] = {".c", ".h", ".cpp", ".hpp"};

bool file_type_is_source(const char *path) {
    const char *extension = strrchr(path, '.');
    if (extension == NULL) {
        return false;
    }
    for (size_t i = 0; i < sizeof(SOURCE_EXTENSIONS) / sizeof(SOURCE_EXTENSIONS[0]); i++) {
        if (strcmp(extension, SOURCE_EXTENSIONS[i]) == 0) {
            return true;
        }
    }
    return false;
}
