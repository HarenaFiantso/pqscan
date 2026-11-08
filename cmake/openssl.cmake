# SPDX-License-Identifier: Apache-2.0

# OpenSSL is the one dependency taken from the system: it builds with Perl, not CMake, so
# FetchContent cannot pin it the way it pins the others. Only libcrypto is needed.
set(PQSCAN_OPENSSL_MINIMUM 3.0)

# Homebrew installs OpenSSL keg-only, out of CMake's search path, so ask it where the 3.x
# series lives unless the caller already chose an OpenSSL.
if(APPLE AND NOT OPENSSL_ROOT_DIR AND NOT DEFINED ENV{OPENSSL_ROOT_DIR})
    find_program(PQSCAN_BREW_PROGRAM brew)
    if(PQSCAN_BREW_PROGRAM)
        execute_process(COMMAND "${PQSCAN_BREW_PROGRAM}" --prefix openssl@3
            OUTPUT_VARIABLE pqscan_brew_openssl
            OUTPUT_STRIP_TRAILING_WHITESPACE
            RESULT_VARIABLE pqscan_brew_result
            ERROR_QUIET)
        if(pqscan_brew_result EQUAL 0 AND IS_DIRECTORY "${pqscan_brew_openssl}")
            set(OPENSSL_ROOT_DIR "${pqscan_brew_openssl}" CACHE PATH "Where OpenSSL is installed")
        endif()
    endif()
endif()

if(PQSCAN_STATIC)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
endif()
find_package(OpenSSL ${PQSCAN_OPENSSL_MINIMUM} REQUIRED COMPONENTS Crypto)

# Our code may only call what OpenSSL 3.0 offers without deprecation, so that it builds the same
# against every later release, including those that remove deprecated functions.
add_library(pqscan_openssl INTERFACE)
target_link_libraries(pqscan_openssl INTERFACE OpenSSL::Crypto)
target_compile_definitions(pqscan_openssl INTERFACE OPENSSL_API_COMPAT=30000 OPENSSL_NO_DEPRECATED)
