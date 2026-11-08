/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/walk/file_type.h"

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

static const char *const SOURCE_EXTENSIONS[] = {
    ".c", ".h", ".cpp", ".hpp", ".cc", ".cxx", ".C", ".hh", ".hxx", ".ipp", ".inl", ".tcc",
};
static const char *const CONFIG_EXTENSIONS[] = {".conf", ".cnf"};
static const char *const CONFIG_NAMES[] = {"sshd_config", "ssh_config", ".htaccess"};
static const char *const CONFIG_DIRECTORIES[] = {"sites-available", "sites-enabled"};
static const char C_EXTENSION[] = ".c";

typedef struct name_list {
    const char *const *names;
    size_t count;
} name_list;

static bool is_listed(const char *name, size_t len, name_list list) {
    for (size_t i = 0; i < list.count; i++) {
        if (strlen(list.names[i]) == len && strncmp(name, list.names[i], len) == 0) {
            return true;
        }
    }
    return false;
}

static bool has_extension(const char *path, name_list extensions) {
    const char *extension = strrchr(path, '.');
    return extension != NULL && is_listed(extension, strlen(extension), extensions);
}

static const char *base_name(const char *path) {
    const char *slash = strrchr(path, '/');
    return (slash != NULL) ? slash + 1 : path;
}

static bool is_in_listed_directory(const char *path, name_list directories) {
    const char *name = base_name(path);
    if (name == path) {
        return false;
    }
    const char *end = name - 1;
    const char *start = end;
    while (start > path && start[-1] != '/') {
        start--;
    }
    return is_listed(start, (size_t)(end - start), directories);
}

bool file_type_is_source(const char *path) {
    const name_list extensions = {SOURCE_EXTENSIONS,
                                  sizeof(SOURCE_EXTENSIONS) / sizeof(SOURCE_EXTENSIONS[0])};
    return has_extension(path, extensions);
}

bool file_type_is_config(const char *path) {
    const name_list extensions = {CONFIG_EXTENSIONS,
                                  sizeof(CONFIG_EXTENSIONS) / sizeof(CONFIG_EXTENSIONS[0])};
    const name_list names = {CONFIG_NAMES, sizeof(CONFIG_NAMES) / sizeof(CONFIG_NAMES[0])};
    const name_list directories = {CONFIG_DIRECTORIES,
                                   sizeof(CONFIG_DIRECTORIES) / sizeof(CONFIG_DIRECTORIES[0])};
    const char *name = base_name(path);
    return has_extension(path, extensions) || is_listed(name, strlen(name), names) ||
           is_in_listed_directory(path, directories);
}

source_language file_type_source_language(const char *path) {
    const char *extension = strrchr(path, '.');
    const bool is_c = extension != NULL && strcmp(extension, C_EXTENSION) == 0;
    return is_c ? SOURCE_LANGUAGE_C : SOURCE_LANGUAGE_CPP;
}
