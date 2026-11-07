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

include(cmake/warnings.cmake)
