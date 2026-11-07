# SPDX-License-Identifier: Apache-2.0
#
# Runs pqscan once under the memory checker. Output is not compared, because leaks writes
# its report to stdout and hides the exit code of pqscan.
# Inputs: PQSCAN, CASE_ARGS and MEMCHECK ("|"-separated), MEMCHECK_FAILURE_EXIT.

string(REPLACE "|" ";" case_args "${CASE_ARGS}")
string(REPLACE "|" ";" memcheck "${MEMCHECK}")

execute_process(
    COMMAND ${memcheck} "${PQSCAN}" ${case_args}
    RESULT_VARIABLE actual_exit
    OUTPUT_VARIABLE checker_stdout
    ERROR_VARIABLE checker_stderr)

if(NOT actual_exit MATCHES "^[0-9]+$" OR actual_exit EQUAL MEMCHECK_FAILURE_EXIT)
    message(FATAL_ERROR "Memory check failed (${actual_exit}).\n${checker_stdout}\n${checker_stderr}")
endif()
