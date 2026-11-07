/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/status.h"
#include "pqscan/core/string_list.h"
#include "pqscan/walk/walker.h"
#include "temp_tree.h"
#include "unity.h"

#include <stddef.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

enum { DEEP_LEVELS = 200, NAME_SIZE = 512 };

static temp_tree *tree;
static string_list *ignores;
static string_list *visited;
static string_list *warned;

void setUp(void) {
    tree = temp_tree_create();
    ignores = string_list_create();
    visited = string_list_create();
    warned = string_list_create();
    TEST_ASSERT_NOT_NULL(ignores);
    TEST_ASSERT_NOT_NULL(visited);
    TEST_ASSERT_NOT_NULL(warned);
}

void tearDown(void) {
    string_list_destroy(warned);
    string_list_destroy(visited);
    string_list_destroy(ignores);
    temp_tree_destroy(tree);
}

static pqscan_status record_visit(const char *path, void *context) {
    (void)context;
    return string_list_add(visited, path);
}

static pqscan_status refuse_visit(const char *path, void *context) {
    (void)path;
    (void)context;
    return PQSCAN_ERR_NOMEM;
}

static void record_warning(const char *path, pqscan_status reason, void *context) {
    (void)reason;
    (void)context;
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, string_list_add(warned, path));
}

static const walk_callbacks RECORDING = {record_visit, record_warning, NULL};

static pqscan_status walk_root(void) {
    return walk_tree(temp_tree_root(tree), ignores, &RECORDING);
}

static void assert_visited(size_t index, const char *relative_path) {
    char expected[NAME_SIZE];
    const int written =
        snprintf(expected, sizeof(expected), "%s/%s", temp_tree_root(tree), relative_path);
    TEST_ASSERT_GREATER_THAN_INT(0, written);
    TEST_ASSERT_EQUAL_STRING(expected, string_list_get(visited, index));
}

static void test_empty_directory_visits_nothing(void) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, walk_root());
    TEST_ASSERT_EQUAL_size_t(0, string_list_count(visited));
    TEST_ASSERT_EQUAL_size_t(0, string_list_count(warned));
}

static void test_visits_entries_in_sorted_order(void) {
    temp_tree_add_file(tree, "b.c", "");
    temp_tree_add_dir(tree, "sub");
    temp_tree_add_file(tree, "sub/z.c", "");
    temp_tree_add_file(tree, "sub/a.c", "");
    temp_tree_add_file(tree, "a.c", "");

    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, walk_root());
    TEST_ASSERT_EQUAL_size_t(4, string_list_count(visited));
    assert_visited(0, "a.c");
    assert_visited(1, "b.c");
    assert_visited(2, "sub/a.c");
    assert_visited(3, "sub/z.c");
}

static void test_a_pattern_can_be_relative_to_the_root(void) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, string_list_add(ignores, "vendor/*"));
    temp_tree_add_dir(tree, "vendor");
    temp_tree_add_file(tree, "vendor/a.c", "");
    temp_tree_add_file(tree, "kept.c", "");

    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, walk_root());
    TEST_ASSERT_EQUAL_size_t(1, string_list_count(visited));
    assert_visited(0, "kept.c");
}

static void test_a_root_with_a_trailing_slash_gives_the_same_relative_paths(void) {
    char root[NAME_SIZE];
    TEST_ASSERT_GREATER_THAN_INT(0, snprintf(root, sizeof(root), "%s/", temp_tree_root(tree)));
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, string_list_add(ignores, "vendor/*"));
    temp_tree_add_dir(tree, "vendor");
    temp_tree_add_file(tree, "vendor/a.c", "");

    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, walk_tree(root, ignores, &RECORDING));
    TEST_ASSERT_EQUAL_size_t(0, string_list_count(visited));
}

static void test_root_can_be_a_file(void) {
    const char *file = temp_tree_add_file(tree, "a.c", "");
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, walk_tree(file, ignores, &RECORDING));
    TEST_ASSERT_EQUAL_STRING(file, string_list_get(visited, 0));
}

static void test_ignored_directory_is_not_entered(void) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, string_list_add(ignores, "skipped"));
    temp_tree_add_dir(tree, "skipped");
    temp_tree_add_file(tree, "skipped/a.c", "");
    temp_tree_add_file(tree, "kept.c", "");

    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, walk_root());
    TEST_ASSERT_EQUAL_size_t(1, string_list_count(visited));
    assert_visited(0, "kept.c");
}

static void test_ignores_do_not_apply_to_the_root(void) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, string_list_add(ignores, temp_tree_root(tree)));
    temp_tree_add_file(tree, "a.c", "");
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, walk_root());
    TEST_ASSERT_EQUAL_size_t(1, string_list_count(visited));
}

static void test_symlink_to_parent_does_not_loop(void) {
    temp_tree_add_file(tree, "a.c", "");
    const char *link = temp_tree_add_symlink(tree, "loop", ".");

    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, walk_root());
    TEST_ASSERT_EQUAL_size_t(1, string_list_count(visited));
    TEST_ASSERT_EQUAL_STRING(link, string_list_get(warned, 0));
}

static void test_symlink_to_file_is_not_followed(void) {
    temp_tree_add_file(tree, "a.c", "");
    temp_tree_add_symlink(tree, "link.c", "a.c");

    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, walk_root());
    TEST_ASSERT_EQUAL_size_t(1, string_list_count(visited));
    TEST_ASSERT_EQUAL_size_t(1, string_list_count(warned));
}

static void test_broken_symlink_is_skipped(void) {
    temp_tree_add_symlink(tree, "dangling", "nowhere");
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, walk_root());
    TEST_ASSERT_EQUAL_size_t(0, string_list_count(visited));
    TEST_ASSERT_EQUAL_size_t(1, string_list_count(warned));
}

static void test_unreadable_directory_warns_and_continues(void) {
    if (geteuid() == 0) {
        TEST_IGNORE_MESSAGE("root reads every directory");
    }
    const char *locked = temp_tree_add_dir(tree, "locked");
    temp_tree_add_file(tree, "z.c", "");
    TEST_ASSERT_EQUAL_INT(0, chmod(locked, 0));

    const pqscan_status status = walk_root();
    TEST_ASSERT_EQUAL_INT(0, chmod(locked, S_IRWXU));

    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, status);
    TEST_ASSERT_EQUAL_size_t(1, string_list_count(visited));
    TEST_ASSERT_EQUAL_STRING(locked, string_list_get(warned, 0));
}

static void test_missing_root_is_reported(void) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_NOT_FOUND, walk_tree("no-such-path", ignores, &RECORDING));
}

static void test_visit_failure_stops_the_walk(void) {
    temp_tree_add_file(tree, "a.c", "");
    temp_tree_add_file(tree, "b.c", "");
    const walk_callbacks refusing = {refuse_visit, record_warning, NULL};
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_NOMEM, walk_tree(temp_tree_root(tree), ignores, &refusing));
}

static void test_deep_tree_is_walked(void) {
    char relative[NAME_SIZE] = "d";
    temp_tree_add_dir(tree, relative);
    for (int level = 1; level < DEEP_LEVELS; level++) {
        char deeper[NAME_SIZE];
        TEST_ASSERT_GREATER_THAN_INT(0, snprintf(deeper, sizeof(deeper), "%s/d", relative));
        TEST_ASSERT_GREATER_THAN_INT(0, snprintf(relative, sizeof(relative), "%s", deeper));
        temp_tree_add_dir(tree, relative);
    }
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, walk_root());
    TEST_ASSERT_EQUAL_size_t(0, string_list_count(warned));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_empty_directory_visits_nothing);
    RUN_TEST(test_visits_entries_in_sorted_order);
    RUN_TEST(test_a_pattern_can_be_relative_to_the_root);
    RUN_TEST(test_a_root_with_a_trailing_slash_gives_the_same_relative_paths);
    RUN_TEST(test_root_can_be_a_file);
    RUN_TEST(test_ignored_directory_is_not_entered);
    RUN_TEST(test_ignores_do_not_apply_to_the_root);
    RUN_TEST(test_symlink_to_parent_does_not_loop);
    RUN_TEST(test_symlink_to_file_is_not_followed);
    RUN_TEST(test_broken_symlink_is_skipped);
    RUN_TEST(test_unreadable_directory_warns_and_continues);
    RUN_TEST(test_missing_root_is_reported);
    RUN_TEST(test_visit_failure_stops_the_walk);
    RUN_TEST(test_deep_tree_is_walked);
    return UNITY_END();
}
