/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_WALK_IGNORE_H
#define PQSCAN_WALK_IGNORE_H

#include "pqscan/core/string_list.h"

#include <stdbool.h>

/**
 * @brief Tell whether a path matches any ignore pattern.
 *
 * A pattern is an fnmatch(3) glob, compared with the last component of the path and with
 * the whole path without any leading "./". A * also matches "/", so a pattern ending in
 * one covers a whole subtree.
 *
 * @param patterns The patterns. Not modified.
 * @param path The path to test.
 * @return true if at least one pattern matches.
 */
bool ignore_matches(const string_list *patterns, const char *path);

#endif /* PQSCAN_WALK_IGNORE_H */
