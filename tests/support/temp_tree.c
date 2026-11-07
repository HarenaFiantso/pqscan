/* SPDX-License-Identifier: Apache-2.0 */
#include "temp_tree.h"

#include "pqscan/core/status.h"
#include "pqscan/core/string_list.h"
#include "unity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum { PATH_BUFFER_SIZE = 1024 };

struct temp_tree {
    char root[PATH_BUFFER_SIZE];
    string_list *created;
};

temp_tree *temp_tree_create(void) {
    temp_tree *tree = calloc(1, sizeof(temp_tree));
    TEST_ASSERT_NOT_NULL(tree);
    tree->created = string_list_create();
    TEST_ASSERT_NOT_NULL(tree->created);
    TEST_ASSERT_GREATER_THAN_INT(0, snprintf(tree->root, sizeof(tree->root), "pqscan-XXXXXX"));
    TEST_ASSERT_NOT_NULL(mkdtemp(tree->root));
    return tree;
}

void temp_tree_destroy(temp_tree *tree) {
    if (tree == NULL) {
        return;
    }
    for (char *path = string_list_pop(tree->created); path != NULL;
         path = string_list_pop(tree->created)) {
        TEST_ASSERT_EQUAL_INT(0, remove(path));
        free(path);
    }
    TEST_ASSERT_EQUAL_INT(0, remove(tree->root));
    string_list_destroy(tree->created);
    free(tree);
}

const char *temp_tree_root(const temp_tree *tree) { return tree->root; }

/* Recorded before creation, so the path is deleted in reverse order of creation. */
static const char *record_path(temp_tree *tree, const char *relative_path) {
    char path[PATH_BUFFER_SIZE];
    const int written = snprintf(path, sizeof(path), "%s/%s", tree->root, relative_path);
    TEST_ASSERT_GREATER_THAN_INT(0, written);
    TEST_ASSERT_LESS_THAN_size_t(sizeof(path), (size_t)written);
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, string_list_add(tree->created, path));
    return string_list_get(tree->created, string_list_count(tree->created) - 1);
}

const char *temp_tree_add_dir(temp_tree *tree, const char *relative_path) {
    const char *path = record_path(tree, relative_path);
    TEST_ASSERT_EQUAL_INT(0, mkdir(path, S_IRWXU));
    return path;
}

const char *temp_tree_add_file(temp_tree *tree, const char *relative_path, const char *contents) {
    const char *path = record_path(tree, relative_path);
    FILE *file = fopen(path, "wb");
    TEST_ASSERT_NOT_NULL(file);
    const size_t length = strlen(contents);
    TEST_ASSERT_EQUAL_size_t(length, fwrite(contents, 1, length, file));
    const int closed = fclose(file);
    TEST_ASSERT_EQUAL_INT(0, closed);
    return path;
}

const char *temp_tree_add_symlink(temp_tree *tree, const char *relative_path, const char *target) {
    const char *path = record_path(tree, relative_path);
    TEST_ASSERT_EQUAL_INT(0, symlink(target, path));
    return path;
}
