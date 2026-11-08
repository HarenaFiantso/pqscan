# SPDX-License-Identifier: Apache-2.0
#
# Usage: cmake -DPQSCAN=path -P check_static.cmake
# Fails unless the binary needs nothing outside the operating system: on Linux no shared library
# at all, and on macOS only those in /usr/lib and /System, which every Mac has.

if(APPLE)
    execute_process(COMMAND otool -L "${PQSCAN}" OUTPUT_VARIABLE libraries RESULT_VARIABLE exit_code)
    if(NOT exit_code EQUAL 0)
        message(FATAL_ERROR "otool -L exited ${exit_code}")
    endif()
    string(REPLACE "\n" ";" lines "${libraries}")
    # The first line names the binary itself, and each library line starts with a tab.
    foreach(line IN LISTS lines)
        if(NOT line MATCHES "^\t([^ ]+)")
            continue()
        endif()
        set(library "${CMAKE_MATCH_1}")
        if(NOT library MATCHES "^/(usr/lib|System)/")
            message(FATAL_ERROR "pqscan needs ${library}, which is not part of macOS")
        endif()
    endforeach()
else()
    execute_process(COMMAND file -L "${PQSCAN}" OUTPUT_VARIABLE description RESULT_VARIABLE exit_code)
    if(NOT exit_code EQUAL 0)
        message(FATAL_ERROR "file exited ${exit_code}")
    endif()
    if(NOT description MATCHES "statically linked|static-pie linked")
        message(FATAL_ERROR "pqscan is not static: ${description}")
    endif()
endif()
