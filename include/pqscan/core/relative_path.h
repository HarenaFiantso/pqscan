/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_CORE_RELATIVE_PATH_H
#define PQSCAN_CORE_RELATIVE_PATH_H

/**
 * @brief Skip the leading "./" components of a path, so that "./src/a.c", ".//src/a.c" and
 *        "src/a.c" name a file the same way.
 *
 * @param path The path, NUL-terminated.
 * @return A pointer into @p path, past every leading "./" and the slashes that follow it. It
 *         points at the terminating NUL if nothing else is left, as in "./". Borrowed from
 *         @p path, so it is valid as long as @p path is.
 */
const char *relative_path_of(const char *path);

#endif /* PQSCAN_CORE_RELATIVE_PATH_H */
