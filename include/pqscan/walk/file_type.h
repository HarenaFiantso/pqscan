/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_WALK_FILE_TYPE_H
#define PQSCAN_WALK_FILE_TYPE_H

#include <stdbool.h>

/**
 * @brief Tell whether a path names a C or C++ source file, by its extension.
 *
 * @param path The path. It is not opened.
 * @return true for .c, .h, .cpp and .hpp files. The match is case-sensitive.
 */
bool file_type_is_source(const char *path);

#endif /* PQSCAN_WALK_FILE_TYPE_H */
