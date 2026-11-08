/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/walk/file_type.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static const char *const SOURCE_EXTENSIONS[] = {
    ".c", ".h", ".cpp", ".hpp", ".cc", ".cxx", ".C", ".hh", ".hxx", ".ipp", ".inl", ".tcc",
};
static const char *const CONFIG_EXTENSIONS[] = {".conf", ".cnf"};
static const char *const CRYPTO_OBJECT_EXTENSIONS[] = {
    ".pem", ".crt", ".cer", ".der", ".key", ".csr",
};
static const char *const CONFIG_NAMES[] = {"sshd_config", "ssh_config", ".htaccess"};
static const char *const CONFIG_DIRECTORIES[] = {"sites-available", "sites-enabled"};
static const char C_EXTENSION[] = ".c";
static const unsigned char ELF_MAGIC[] = {0x7f, 'E', 'L', 'F'};

typedef struct name_list {
    const char *const *names;
    size_t count;
} name_list;

static const name_list SOURCE_LIST = {
    SOURCE_EXTENSIONS,
    sizeof(SOURCE_EXTENSIONS) / sizeof(SOURCE_EXTENSIONS[0]),
};
static const name_list CRYPTO_OBJECT_LIST = {
    CRYPTO_OBJECT_EXTENSIONS,
    sizeof(CRYPTO_OBJECT_EXTENSIONS) / sizeof(CRYPTO_OBJECT_EXTENSIONS[0]),
};
static const name_list CONFIG_EXTENSION_LIST = {
    CONFIG_EXTENSIONS,
    sizeof(CONFIG_EXTENSIONS) / sizeof(CONFIG_EXTENSIONS[0]),
};
static const name_list CONFIG_NAME_LIST = {
    CONFIG_NAMES,
    sizeof(CONFIG_NAMES) / sizeof(CONFIG_NAMES[0]),
};
static const name_list CONFIG_DIRECTORY_LIST = {
    CONFIG_DIRECTORIES,
    sizeof(CONFIG_DIRECTORIES) / sizeof(CONFIG_DIRECTORIES[0]),
};

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

bool file_type_is_source(const char *path) { return has_extension(path, SOURCE_LIST); }

bool file_type_is_crypto_object(const char *path) {
    return has_extension(path, CRYPTO_OBJECT_LIST);
}

bool file_type_is_config(const char *path) {
    const char *name = base_name(path);
    return has_extension(path, CONFIG_EXTENSION_LIST) ||
           is_listed(name, strlen(name), CONFIG_NAME_LIST) ||
           is_in_listed_directory(path, CONFIG_DIRECTORY_LIST);
}

bool file_type_has_elf_magic(const unsigned char *data, size_t len) {
    return len >= sizeof(ELF_MAGIC) && memcmp(data, ELF_MAGIC, sizeof(ELF_MAGIC)) == 0;
}

static bool is_regular_file(int fd) {
    struct stat info;
    return fstat(fd, &info) == 0 && S_ISREG(info.st_mode);
}

/* read() may return fewer bytes than asked, even from a regular file. */
static size_t read_prefix(int fd, unsigned char *prefix, size_t capacity) {
    size_t total = 0;
    while (total < capacity) {
        const ssize_t count = read(fd, prefix + total, capacity - total);
        if (count > 0) {
            total += (size_t)count;
        } else if (count == 0 || errno != EINTR) {
            break;
        }
    }
    return total;
}

static bool starts_with_elf_magic(int fd) {
    unsigned char prefix[sizeof(ELF_MAGIC)] = {0};
    const size_t len = read_prefix(fd, prefix, sizeof(prefix));
    return file_type_has_elf_magic(prefix, len);
}

bool file_type_is_elf(const char *path) {
    const int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }
    const bool is_elf = is_regular_file(fd) && starts_with_elf_magic(fd);
    /* Nothing was written, so a failed close loses nothing. */
    (void)close(fd);
    return is_elf;
}

source_language file_type_source_language(const char *path) {
    const char *extension = strrchr(path, '.');
    const bool is_c = extension != NULL && strcmp(extension, C_EXTENSION) == 0;
    return is_c ? SOURCE_LANGUAGE_C : SOURCE_LANGUAGE_CPP;
}
