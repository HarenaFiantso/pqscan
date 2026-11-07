/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/walk/walker.h"

#include "pqscan/core/status.h"
#include "pqscan/core/string_list.h"
#include "pqscan/walk/ignore.h"

#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

typedef struct walker {
    string_list *pending; /* A stack: the walk is iterative so a deep tree cannot overflow. */
    const string_list *ignores;
    const walk_callbacks *callbacks;
} walker;

static void warn_skipped(const walker *state, const char *path, pqscan_status reason) {
    state->callbacks->warn(path, reason, state->callbacks->context);
}

static char *join_path(const char *dir, const char *name) {
    const size_t dir_len = strlen(dir);
    const size_t name_len = strlen(name);
    if (dir_len > SIZE_MAX - name_len - sizeof("/")) {
        return NULL;
    }
    const size_t size = dir_len + name_len + sizeof("/");
    char *path = malloc(size);
    if (path == NULL) {
        return NULL;
    }
    const bool has_separator = dir_len > 0 && dir[dir_len - 1] == '/';
    if (snprintf(path, size, "%s%s%s", dir, has_separator ? "" : "/", name) < 0) {
        free(path);
        return NULL;
    }
    return path;
}

static bool is_dot_entry(const char *name) {
    return strcmp(name, ".") == 0 || strcmp(name, "..") == 0;
}

static pqscan_status read_entry_names(DIR *dir, string_list *names) {
    errno = 0;
    for (const struct dirent *entry = readdir(dir); entry != NULL; entry = readdir(dir)) {
        if (!is_dot_entry(entry->d_name)) {
            const pqscan_status status = string_list_add(names, entry->d_name);
            if (status != PQSCAN_OK) {
                return status;
            }
        }
        errno = 0;
    }
    return (errno == 0) ? PQSCAN_OK : PQSCAN_ERR_IO;
}

static pqscan_status list_sorted_names(const char *path, string_list *names) {
    DIR *dir = opendir(path);
    if (dir == NULL) {
        return PQSCAN_ERR_IO;
    }
    pqscan_status status = read_entry_names(dir, names);
    if (closedir(dir) != 0 && status == PQSCAN_OK) {
        status = PQSCAN_ERR_IO;
    }
    string_list_sort(names);
    return status;
}

/* Pushed last to first, because the stack pops them back in sorted order. */
static pqscan_status push_children(const walker *state, const char *dir, const string_list *names) {
    for (size_t i = string_list_count(names); i > 0; i--) {
        char *child = join_path(dir, string_list_get(names, i - 1));
        if (child == NULL) {
            return PQSCAN_ERR_NOMEM;
        }
        if (ignore_matches(state->ignores, child)) {
            free(child);
            continue;
        }
        const pqscan_status status = string_list_add_owned(state->pending, child);
        if (status != PQSCAN_OK) {
            return status;
        }
    }
    return PQSCAN_OK;
}

static pqscan_status expand_directory(const walker *state, const char *path) {
    string_list *names = string_list_create();
    if (names == NULL) {
        return PQSCAN_ERR_NOMEM;
    }
    pqscan_status status = list_sorted_names(path, names);
    if (status == PQSCAN_OK) {
        status = push_children(state, path, names);
    } else if (status == PQSCAN_ERR_IO) {
        warn_skipped(state, path, status);
        status = PQSCAN_OK;
    }
    string_list_destroy(names);
    return status;
}

static pqscan_status walk_path(const walker *state, const char *path) {
    struct stat info;
    if (lstat(path, &info) != 0) {
        warn_skipped(state, path, PQSCAN_ERR_IO);
        return PQSCAN_OK;
    }
    if (S_ISDIR(info.st_mode)) {
        return expand_directory(state, path);
    }
    if (S_ISREG(info.st_mode)) {
        return state->callbacks->visit(path, state->callbacks->context);
    }
    warn_skipped(state, path, PQSCAN_ERR_NOT_REGULAR);
    return PQSCAN_OK;
}

static pqscan_status check_root(const char *root) {
    struct stat info;
    if (lstat(root, &info) == 0) {
        return PQSCAN_OK;
    }
    return (errno == ENOENT || errno == ENOTDIR) ? PQSCAN_ERR_NOT_FOUND : PQSCAN_ERR_IO;
}

pqscan_status walk_tree(const char *root, const string_list *ignores,
                        const walk_callbacks *callbacks) {
    pqscan_status status = check_root(root);
    if (status != PQSCAN_OK) {
        return status;
    }
    string_list *pending = string_list_create();
    if (pending == NULL) {
        return PQSCAN_ERR_NOMEM;
    }
    const walker state = {pending, ignores, callbacks};
    status = string_list_add(pending, root);
    while (status == PQSCAN_OK && string_list_count(pending) > 0) {
        char *path = string_list_pop(pending);
        status = walk_path(&state, path);
        free(path);
    }
    string_list_destroy(pending);
    return status;
}
