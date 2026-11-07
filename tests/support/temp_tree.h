/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_TESTS_TEMP_TREE_H
#define PQSCAN_TESTS_TEMP_TREE_H

/**
 * A directory tree built by a test and deleted afterwards. It lives under the working
 * directory, so tests running in parallel stay independent. Any failure fails the test.
 */
typedef struct temp_tree temp_tree;

/**
 * @brief Create an empty tree.
 *
 * @return The tree, freed with temp_tree_destroy().
 */
temp_tree *temp_tree_create(void);

/**
 * @brief Delete everything the tree created, then free it.
 *
 * @param tree The tree. May be NULL.
 */
void temp_tree_destroy(temp_tree *tree);

/**
 * @brief Get the root directory.
 *
 * @param tree The tree.
 * @return The path, owned by the tree.
 */
const char *temp_tree_root(const temp_tree *tree);

/**
 * @brief Create a directory. Its parent must already exist.
 *
 * @param tree The tree.
 * @param relative_path The path from the root.
 * @return The full path, owned by the tree.
 */
const char *temp_tree_add_dir(temp_tree *tree, const char *relative_path);

/**
 * @brief Create a file. Its parent must already exist.
 *
 * @param tree The tree.
 * @param relative_path The path from the root.
 * @param contents The text to write.
 * @return The full path, owned by the tree.
 */
const char *temp_tree_add_file(temp_tree *tree, const char *relative_path, const char *contents);

/**
 * @brief Create a symlink. Its parent must already exist.
 *
 * @param tree The tree.
 * @param relative_path The path of the link, from the root.
 * @param target What the link points to, stored as given.
 * @return The full path of the link, owned by the tree.
 */
const char *temp_tree_add_symlink(temp_tree *tree, const char *relative_path, const char *target);

#endif /* PQSCAN_TESTS_TEMP_TREE_H */
