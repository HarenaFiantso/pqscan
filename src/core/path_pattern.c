/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/path_pattern.h"

#include "pqscan/core/relative_path.h"
#include "pqscan/core/string_list.h"

#include <fnmatch.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

static const char *last_component(const char *path) {
    const char *separator = strrchr(path, '/');
    return (separator == NULL) ? path : separator + 1;
}

bool path_pattern_matches(const string_list *patterns, const char *path) {
    const char *relative = relative_path_of(path);
    const char *name = last_component(relative);
    for (size_t i = 0; i < string_list_count(patterns); i++) {
        const char *pattern = string_list_get(patterns, i);
        if (fnmatch(pattern, name, 0) == 0 || fnmatch(pattern, relative, 0) == 0) {
            return true;
        }
    }
    return false;
}
