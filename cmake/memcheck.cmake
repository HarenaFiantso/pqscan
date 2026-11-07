# SPDX-License-Identifier: Apache-2.0

option(PQSCAN_ENABLE_MEMCHECK "Also run each test under Valgrind (Linux) or leaks (macOS)" OFF)

if(PQSCAN_ENABLE_MEMCHECK)
    if(APPLE)
        # Valgrind does not run on Apple Silicon. See docs/decisions/001-memory-checking.md.
        find_program(PQSCAN_LEAKS_PROGRAM leaks REQUIRED)
        set(PQSCAN_MEMCHECK_COMMAND "${PQSCAN_LEAKS_PROGRAM}" --atExit --)
    else()
        find_program(PQSCAN_VALGRIND_PROGRAM valgrind REQUIRED)
        set(PQSCAN_MEMCHECK_COMMAND "${PQSCAN_VALGRIND_PROGRAM}"
            --quiet --leak-check=full --show-leak-kinds=all --errors-for-leak-kinds=all
            --track-origins=yes --error-exitcode=99)
    endif()
endif()
