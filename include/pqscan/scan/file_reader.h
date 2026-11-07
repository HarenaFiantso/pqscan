/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_SCAN_FILE_READER_H
#define PQSCAN_SCAN_FILE_READER_H

#include "pqscan/core/status.h"

#include <stddef.h>

/** Files above this size are skipped, so a hostile repository cannot exhaust memory. */
enum { PQSCAN_MAX_FILE_SIZE = 64 * 1024 * 1024 };

/** The bytes of a file. */
typedef struct file_contents {
    char *data; /**< Never NULL. A NUL follows the last byte, but data may also hold NULs. */
    size_t len; /**< Number of bytes, without the added NUL. */
} file_contents;

/**
 * @brief Read a whole regular file into memory.
 *
 * Refuses symlinks and special files by inspecting what was actually opened, so swapping
 * the file after an earlier check cannot redirect the read or block it on a FIFO.
 *
 * @param path The file.
 * @param out On success, the contents, owned by the caller and freed with
 *            file_contents_destroy(). Untouched on failure.
 * @return PQSCAN_OK, PQSCAN_ERR_NOT_FOUND, PQSCAN_ERR_NOT_REGULAR, PQSCAN_ERR_TOO_LARGE,
 *         PQSCAN_ERR_IO or PQSCAN_ERR_NOMEM.
 */
pqscan_status file_contents_read(const char *path, file_contents **out);

/**
 * @brief Free file contents.
 *
 * @param file The contents to free. May be NULL.
 */
void file_contents_destroy(file_contents *file);

#endif /* PQSCAN_SCAN_FILE_READER_H */
