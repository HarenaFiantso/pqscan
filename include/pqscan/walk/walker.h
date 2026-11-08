/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_WALK_WALKER_H
#define PQSCAN_WALK_WALKER_H

#include "pqscan/core/status.h"
#include "pqscan/core/string_list.h"

/**
 * @brief Called for each regular file.
 *
 * @param path The file. Valid only during the call.
 * @param context The context from walk_callbacks.
 * @return PQSCAN_OK to continue. Anything else stops the walk, and walk_tree() returns it.
 */
typedef pqscan_status (*walk_visit_fn)(const char *path, void *context);

/**
 * @brief Called for each path the walk skips, such as a symlink or an unreadable directory.
 *
 * @param path The skipped path. Valid only during the call.
 * @param reason Why it was skipped.
 * @param context The context from walk_callbacks.
 */
typedef void (*walk_warn_fn)(const char *path, pqscan_status reason, void *context);

/** What walk_tree() reports to. */
typedef struct walk_callbacks {
    walk_visit_fn visit;
    walk_warn_fn warn;
    void *context; /**< Passed to both callbacks, unchanged. */
} walk_callbacks;

/**
 * @brief Visit every regular file under a path, in a deterministic order.
 *
 * Entries of a directory are visited in byte order of their names. Symlinks are never
 * followed. Ignore patterns apply to everything below @p root, but not to @p root itself.
 *
 * @param root A directory or a regular file.
 * @param ignores Patterns for path_pattern_matches(). Not modified.
 * @param callbacks Where to report. Not modified.
 * @return PQSCAN_OK when the walk completed, even if it skipped paths.
 *         PQSCAN_ERR_NOT_FOUND if @p root does not exist, PQSCAN_ERR_IO if it cannot be
 *         inspected, PQSCAN_ERR_NOMEM, or the status that stopped the walk.
 */
pqscan_status walk_tree(const char *root, const string_list *ignores,
                        const walk_callbacks *callbacks);

#endif /* PQSCAN_WALK_WALKER_H */
