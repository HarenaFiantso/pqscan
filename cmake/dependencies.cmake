# SPDX-License-Identifier: Apache-2.0
include(FetchContent)

set(PQSCAN_DOWNLOAD_DIR "${CMAKE_BINARY_DIR}/.downloads" CACHE PATH
    "Where third-party archives are kept, so presets and CI can reuse them")

# A download that stalls this long gives up, so that the next URL gets its turn.
set(PQSCAN_DOWNLOAD_INACTIVITY_SECONDS 30)

# Usage: pqscan_download(out_var FILE name SHA256 hash URLS url...)
# Downloads a file into PQSCAN_DOWNLOAD_DIR unless a copy with the right hash is already there,
# trying each URL in turn, and sets out_var to its path. FetchContent cannot do this itself: since
# CMake 3.30 it ignores DOWNLOAD_DIR and keeps each archive inside one build tree, so neither the
# presets nor the CI cache could share it. The lock stops two configures from writing one file.
function(pqscan_download out_var)
    cmake_parse_arguments(PARSE_ARGV 1 FETCH "" "FILE;SHA256" "URLS")
    set(path "${PQSCAN_DOWNLOAD_DIR}/${FETCH_FILE}")
    set(${out_var} "${path}" PARENT_SCOPE)
    file(LOCK "${path}.lock" GUARD FUNCTION)
    if(EXISTS "${path}")
        file(SHA256 "${path}" found)
        if(found STREQUAL FETCH_SHA256)
            return()
        endif()
        file(REMOVE "${path}")
    endif()
    foreach(url IN LISTS FETCH_URLS)
        file(DOWNLOAD "${url}" "${path}.part" STATUS status TLS_VERIFY ON
            INACTIVITY_TIMEOUT ${PQSCAN_DOWNLOAD_INACTIVITY_SECONDS})
        list(GET status 0 code)
        if(code EQUAL 0)
            file(SHA256 "${path}.part" found)
            if(found STREQUAL FETCH_SHA256)
                file(RENAME "${path}.part" "${path}")
                return()
            endif()
            set(status "SHA-256 ${found} instead of ${FETCH_SHA256}")
        endif()
        message(STATUS "Cannot download ${url}: ${status}")
        file(REMOVE "${path}.part")
    endforeach()
    message(FATAL_ERROR "Cannot download ${FETCH_FILE} from any of: ${FETCH_URLS}")
endfunction()

# Usage: pqscan_declare_github_archive(name REPOSITORY owner/repo TAG tag SHA256 hash [args...])
# github.com serves a release archive by redirecting to codeload.github.com, so asking codeload
# directly is a fallback for when github.com fails, as it did in a November 2026 incident. The
# bytes are the same, so one hash covers both URLs. Other arguments go to FetchContent_Declare().
function(pqscan_declare_github_archive name)
    cmake_parse_arguments(PARSE_ARGV 1 ARCHIVE "" "REPOSITORY;TAG;SHA256" "")
    pqscan_download(archive
        FILE "${name}-${ARCHIVE_TAG}.tar.gz"
        SHA256 ${ARCHIVE_SHA256}
        URLS "https://github.com/${ARCHIVE_REPOSITORY}/archive/refs/tags/${ARCHIVE_TAG}.tar.gz"
             "https://codeload.github.com/${ARCHIVE_REPOSITORY}/tar.gz/refs/tags/${ARCHIVE_TAG}")
    FetchContent_Declare(${name}
        URL "${archive}"
        URL_HASH SHA256=${ARCHIVE_SHA256}
        ${ARCHIVE_UNPARSED_ARGUMENTS})
endfunction()

# These archives ship their own CMakeLists.txt, and the grammars' can run the Tree-sitter CLI.
# Pointing SOURCE_SUBDIR at a missing directory makes FetchContent stop after extracting, so we
# build only the generated C files below.
pqscan_declare_github_archive(tree_sitter
    REPOSITORY tree-sitter/tree-sitter TAG v0.27.2
    SHA256 356528363bf7fbad12a2cfeb5a2678c0118ef886a4d69ad9a379db5fdef0735f
    SOURCE_SUBDIR none)
pqscan_declare_github_archive(tree_sitter_c
    REPOSITORY tree-sitter/tree-sitter-c TAG v0.24.2
    SHA256 2eeb4db31f8fa0865e45488503d13403923bcb485a1bdb637abff8c42dd97364
    SOURCE_SUBDIR none)
pqscan_declare_github_archive(tree_sitter_cpp
    REPOSITORY tree-sitter/tree-sitter-cpp TAG v0.23.4
    SHA256 7a2c55afe3028f4105f25762ea58cc16537d1f5a1dcd9cca90410b3cd5d46051
    SOURCE_SUBDIR none)
pqscan_declare_github_archive(cjson
    REPOSITORY DaveGamble/cJSON TAG v1.7.19
    SHA256 7fa616e3046edfa7a28a32d5f9eacfd23f92900fe1f8ccd988c1662f30454562
    SOURCE_SUBDIR none)
FetchContent_MakeAvailable(tree_sitter tree_sitter_c tree_sitter_cpp cjson)

add_library(pqscan_tree_sitter STATIC "${tree_sitter_SOURCE_DIR}/lib/src/lib.c")
target_include_directories(pqscan_tree_sitter PRIVATE "${tree_sitter_SOURCE_DIR}/lib/src")
target_include_directories(pqscan_tree_sitter SYSTEM PUBLIC "${tree_sitter_SOURCE_DIR}/lib/include")
# Tree-sitter's own Makefile asks for these: its endian helpers are not part of ISO C.
target_compile_definitions(pqscan_tree_sitter PRIVATE
    _POSIX_C_SOURCE=200112L _DEFAULT_SOURCE $<$<PLATFORM_ID:Darwin>:_DARWIN_C_SOURCE>)
# tree-sitter-cpp defines its scanner hook as f() and the runtime calls it as f(void). C says those
# types are compatible, but Clang's function check on Linux demands identical ones. Checks stay on
# everywhere else, because this flag only affects the calls made from this library.
target_compile_options(pqscan_tree_sitter PRIVATE $<$<C_COMPILER_ID:Clang>:-fno-sanitize=function>)

# One library per grammar, because each ships its own copy of tree_sitter/parser.h.
add_library(pqscan_grammar_c STATIC "${tree_sitter_c_SOURCE_DIR}/src/parser.c")
target_include_directories(pqscan_grammar_c PRIVATE "${tree_sitter_c_SOURCE_DIR}/src")

add_library(pqscan_grammar_cpp STATIC
    "${tree_sitter_cpp_SOURCE_DIR}/src/parser.c"
    "${tree_sitter_cpp_SOURCE_DIR}/src/scanner.c")
target_include_directories(pqscan_grammar_cpp PRIVATE "${tree_sitter_cpp_SOURCE_DIR}/src")

add_library(pqscan_cjson STATIC "${cjson_SOURCE_DIR}/cJSON.c")
target_include_directories(pqscan_cjson SYSTEM PUBLIC "${cjson_SOURCE_DIR}")
# macOS deprecates sprintf, which cJSON calls only in the printing code pqscan never uses.
target_compile_options(pqscan_cjson PRIVATE -Wno-deprecated-declarations)
