# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 3.20...3.31)

project(pqscan
    VERSION 0.0.0
    DESCRIPTION "Find quantum-vulnerable cryptography in C/C++ source, configs, certificates and ELF binaries"
    LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(cmake/posix.cmake)
include(cmake/warnings.cmake)
include(cmake/memcheck.cmake)

add_library(pqscan_core STATIC
    src/core/finding.c
    src/core/memory.c
    src/core/status.c
    src/core/string_list.c
    src/core/version.c
    src/risk/risk.c)
target_include_directories(pqscan_core PUBLIC include)
target_compile_definitions(pqscan_core PRIVATE PQSCAN_VERSION_STRING="${PROJECT_VERSION}")
target_link_libraries(pqscan_core PRIVATE pqscan_posix pqscan_warnings)

enable_testing()
add_subdirectory(tests)
