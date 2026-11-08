/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_CORE_PATH_PATTERN_H
#define PQSCAN_CORE_PATH_PATTERN_H

#include "pqscan/core/string_list.h"

#include <stdbool.h>

/**
 * @brief Tell whether a path matches any of a list of patterns.
 *
 * A pattern is an fnmatch(3) glob, compared with the last component of the path and with
 * the whole path as relative_path_of() gives it. A * also matches "/", so a pattern ending in
 * one covers a whole subtree.
 *
 * @param patterns The patterns. Not modified.
 * @param path The path to test.
 * @return true if at least one pattern matches.
 */
bool path_pattern_matches(const string_list *patterns, const char *path);

#endif /* PQSCAN_CORE_PATH_PATTERN_H */
