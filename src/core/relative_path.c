/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/relative_path.h"

#include <string.h>

const char *relative_path_of(const char *path) {
    const char *rest = path;
    while (rest[0] == '.' && rest[1] == '/') {
        rest += strspn(rest + 1, "/") + 1;
    }
    return rest;
}
