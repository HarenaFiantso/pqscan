# SPDX-License-Identifier: Apache-2.0
#
# Runs pqscan once and compares its exit code and output with what the test expects.
# Inputs: PQSCAN, CASE_ARGS ("|"-separated), EXPECTED_EXIT, and optionally EXPECTED_STDOUT,
# EXPECTED_STDERR (paths to files), and STDOUT_SINK (a file that receives stdout instead).

string(REPLACE "|" ";" case_args "${CASE_ARGS}")

if(STDOUT_SINK)
    set(stdout_capture OUTPUT_FILE "${STDOUT_SINK}")
else()
    set(stdout_capture OUTPUT_VARIABLE actual_stdout)
endif()

execute_process(
    COMMAND "${PQSCAN}" ${case_args}
    RESULT_VARIABLE actual_exit
    ERROR_VARIABLE actual_stderr
    ${stdout_capture})

function(check_output stream actual expected_file)
    if(NOT expected_file)
        return()
    endif()
    file(READ "${expected_file}" expected)
    if(NOT "${actual}" STREQUAL "${expected}")
        message(FATAL_ERROR "${stream} differs.\n--- expected\n${expected}\n--- actual\n${actual}")
    endif()
endfunction()

if(NOT "${actual_exit}" STREQUAL "${EXPECTED_EXIT}")
    message(FATAL_ERROR "Expected exit ${EXPECTED_EXIT}, got ${actual_exit}.\n${actual_stderr}")
endif()
check_output(stdout "${actual_stdout}" "${EXPECTED_STDOUT}")
check_output(stderr "${actual_stderr}" "${EXPECTED_STDERR}")
