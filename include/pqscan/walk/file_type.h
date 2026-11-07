/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_WALK_FILE_TYPE_H
#define PQSCAN_WALK_FILE_TYPE_H

#include <stdbool.h>

/** The grammar a source file is parsed with. */
typedef enum source_language {
    SOURCE_LANGUAGE_C,
    SOURCE_LANGUAGE_CPP,
} source_language;

/**
 * @brief Tell whether a path names a C or C++ source file, by its extension.
 *
 * @param path The path. It is not opened.
 * @return true for .c, .h, .cpp, .hpp, .cc, .cxx, .C, .hh, .hxx, .ipp, .inl and .tcc files.
 *         The match is case-sensitive, because .C is C++ where .c is C.
 */
bool file_type_is_source(const char *path);

/**
 * @brief Choose the grammar for a source file, by its extension.
 *
 * A .h file may be C or C++, and nothing in its name says which. It gets the C++ grammar
 * because that one accepts nearly all C, while the C grammar rejects every C++ construct.
 *
 * @param path A path accepted by file_type_is_source(). It is not opened.
 * @return SOURCE_LANGUAGE_C for .c files, SOURCE_LANGUAGE_CPP for anything else.
 */
source_language file_type_source_language(const char *path);

#endif /* PQSCAN_WALK_FILE_TYPE_H */
