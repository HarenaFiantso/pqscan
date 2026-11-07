# SPDX-License-Identifier: Apache-2.0

option(PQSCAN_ENABLE_MEMCHECK "Also run each test under Valgrind (Linux) or leaks (macOS)" OFF)

if(PQSCAN_ENABLE_MEMCHECK)
    if(APPLE)
        # Valgrind does not run on Apple Silicon. leaks finds leaks only, and it exits 0 when
        # the test it wraps fails, so each test must also run plain to detect failures.
        find_program(PQSCAN_LEAKS_PROGRAM leaks REQUIRED)
        set(PQSCAN_MEMCHECK_COMMAND "${PQSCAN_LEAKS_PROGRAM}" --atExit --)
        set(PQSCAN_MEMCHECK_FAILURE_EXIT 1)
    else()
        find_program(PQSCAN_VALGRIND_PROGRAM valgrind REQUIRED)
        # Not 1, 2 or 3, so that a memory error is never mistaken for a pqscan exit code.
        set(PQSCAN_MEMCHECK_FAILURE_EXIT 99)
        set(PQSCAN_MEMCHECK_COMMAND "${PQSCAN_VALGRIND_PROGRAM}"
            --quiet --leak-check=full --show-leak-kinds=all --errors-for-leak-kinds=all
            --track-origins=yes --error-exitcode=${PQSCAN_MEMCHECK_FAILURE_EXIT})
    endif()
endif()
