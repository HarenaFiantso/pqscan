/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/status.h"
#include "pqscan/scan/file_reader.h"
#include "temp_tree.h"
#include "unity.h"

#include <stddef.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static temp_tree *tree;
static file_contents *file;

void setUp(void) {
    tree = temp_tree_create();
    file = NULL;
}

void tearDown(void) {
    file_contents_destroy(file);
    temp_tree_destroy(tree);
}

static void test_reads_a_whole_file(void) {
    const char *path = temp_tree_add_file(tree, "a.c", "int x;\n");
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, file_contents_read(path, &file));
    TEST_ASSERT_EQUAL_size_t(sizeof("int x;\n") - 1, file->len);
    TEST_ASSERT_EQUAL_STRING("int x;\n", file->data);
}

static void test_empty_file_has_terminated_data(void) {
    const char *path = temp_tree_add_file(tree, "empty.c", "");
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, file_contents_read(path, &file));
    TEST_ASSERT_EQUAL_size_t(0, file->len);
    TEST_ASSERT_EQUAL_STRING("", file->data);
}

static void test_keeps_embedded_nul_bytes(void) {
    static const char bytes[] = {'a', '\0', 'b'};
    const char *path = temp_tree_add_file(tree, "bin", "");
    FILE *out = fopen(path, "wb");
    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_EQUAL_size_t(sizeof(bytes), fwrite(bytes, 1, sizeof(bytes), out));
    const int closed = fclose(out);
    TEST_ASSERT_EQUAL_INT(0, closed);

    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, file_contents_read(path, &file));
    TEST_ASSERT_EQUAL_MEMORY(bytes, file->data, sizeof(bytes));
    TEST_ASSERT_EQUAL_size_t(sizeof(bytes), file->len);
}

static void test_missing_file_is_reported(void) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_NOT_FOUND, file_contents_read("no-such-file", &file));
    TEST_ASSERT_NULL(file);
}

static void test_refuses_a_symlink(void) {
    temp_tree_add_file(tree, "real.c", "");
    const char *link = temp_tree_add_symlink(tree, "link.c", "real.c");
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_NOT_REGULAR, file_contents_read(link, &file));
}

static void test_refuses_a_directory(void) {
    const char *dir = temp_tree_add_dir(tree, "dir");
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_NOT_REGULAR, file_contents_read(dir, &file));
}

static void test_refuses_a_fifo_without_blocking(void) {
    const char *fifo = temp_tree_add_file(tree, "fifo", "");
    TEST_ASSERT_EQUAL_INT(0, remove(fifo));
    TEST_ASSERT_EQUAL_INT(0, mkfifo(fifo, S_IRUSR | S_IWUSR));
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_NOT_REGULAR, file_contents_read(fifo, &file));
}

static void test_refuses_an_unreadable_file(void) {
    if (geteuid() == 0) {
        TEST_IGNORE_MESSAGE("root reads every file");
    }
    const char *path = temp_tree_add_file(tree, "locked.c", "");
    TEST_ASSERT_EQUAL_INT(0, chmod(path, 0));
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_IO, file_contents_read(path, &file));
}

static void test_accepts_a_file_at_the_size_limit(void) {
    const char *path = temp_tree_add_file(tree, "limit.c", "");
    TEST_ASSERT_EQUAL_INT(0, truncate(path, (off_t)PQSCAN_MAX_FILE_SIZE));
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, file_contents_read(path, &file));
    TEST_ASSERT_EQUAL_size_t(PQSCAN_MAX_FILE_SIZE, file->len);
}

static void test_refuses_a_file_over_the_size_limit(void) {
    const char *path = temp_tree_add_file(tree, "huge.c", "");
    TEST_ASSERT_EQUAL_INT(0, truncate(path, (off_t)PQSCAN_MAX_FILE_SIZE + 1));
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_TOO_LARGE, file_contents_read(path, &file));
}

static void test_destroy_accepts_null(void) { file_contents_destroy(NULL); }

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_reads_a_whole_file);
    RUN_TEST(test_empty_file_has_terminated_data);
    RUN_TEST(test_keeps_embedded_nul_bytes);
    RUN_TEST(test_missing_file_is_reported);
    RUN_TEST(test_refuses_a_symlink);
    RUN_TEST(test_refuses_a_directory);
    RUN_TEST(test_refuses_a_fifo_without_blocking);
    RUN_TEST(test_refuses_an_unreadable_file);
    RUN_TEST(test_accepts_a_file_at_the_size_limit);
    RUN_TEST(test_refuses_a_file_over_the_size_limit);
    RUN_TEST(test_destroy_accepts_null);
    return UNITY_END();
}
