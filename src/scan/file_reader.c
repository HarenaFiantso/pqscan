/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/scan/file_reader.h"

#include "pqscan/core/status.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static pqscan_status status_from_open_error(int error) {
    switch (error) {
    case ENOENT:
        return PQSCAN_ERR_NOT_FOUND;
    case ELOOP:
        return PQSCAN_ERR_NOT_REGULAR;
    default:
        return PQSCAN_ERR_IO;
    }
}

static pqscan_status measure_regular_file(int fd, size_t *size) {
    struct stat info;
    if (fstat(fd, &info) != 0) {
        return PQSCAN_ERR_IO;
    }
    if (!S_ISREG(info.st_mode)) {
        return PQSCAN_ERR_NOT_REGULAR;
    }
    if (info.st_size < 0 || info.st_size > PQSCAN_MAX_FILE_SIZE) {
        return PQSCAN_ERR_TOO_LARGE;
    }
    *size = (size_t)info.st_size;
    return PQSCAN_OK;
}

/* read() may return fewer bytes than asked. A file growing after fstat() is cut at capacity. */
static pqscan_status read_up_to(int fd, file_contents *file, size_t capacity) {
    size_t total = 0;
    while (total < capacity) {
        const ssize_t count = read(fd, file->data + total, capacity - total);
        if (count == 0) {
            break;
        }
        if (count > 0) {
            total += (size_t)count;
        } else if (errno != EINTR) {
            return PQSCAN_ERR_IO;
        }
    }
    file->len = total;
    return PQSCAN_OK;
}

static pqscan_status load_contents(int fd, size_t size, file_contents **out) {
    file_contents *file = calloc(1, sizeof(file_contents));
    if (file == NULL) {
        return PQSCAN_ERR_NOMEM;
    }
    file->data = malloc(size + 1);
    if (file->data == NULL) {
        file_contents_destroy(file);
        return PQSCAN_ERR_NOMEM;
    }
    const pqscan_status status = read_up_to(fd, file, size);
    if (status != PQSCAN_OK) {
        file_contents_destroy(file);
        return status;
    }
    file->data[file->len] = '\0';
    *out = file;
    return PQSCAN_OK;
}

pqscan_status file_contents_read(const char *path, file_contents **out) {
    const int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        return status_from_open_error(errno);
    }
    size_t size = 0;
    pqscan_status status = measure_regular_file(fd, &size);
    if (status == PQSCAN_OK) {
        status = load_contents(fd, size, out);
    }
    if (close(fd) != 0 && status == PQSCAN_OK) {
        file_contents_destroy(*out);
        *out = NULL;
        status = PQSCAN_ERR_IO;
    }
    return status;
}

void file_contents_destroy(file_contents *file) {
    if (file == NULL) {
        return;
    }
    free(file->data);
    free(file);
}
