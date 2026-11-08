# SPDX-License-Identifier: Apache-2.0
#
# Writes a baseline, compares it with the one expected, then diffs the same scan against it,
# which must find nothing new.
# Inputs: PQSCAN, CASE_ARGS ("|"-separated), BASELINE (the file to write), EXPECTED_BASELINE.

string(REPLACE "|" ";" case_args "${CASE_ARGS}")
file(REMOVE "${BASELINE}")

function(run_pqscan expected_exit)
    execute_process(
        COMMAND "${PQSCAN}" ${ARGN} ${case_args}
        RESULT_VARIABLE actual_exit
        OUTPUT_VARIABLE actual_stdout
        ERROR_VARIABLE actual_stderr)
    if(NOT "${actual_exit}" STREQUAL "${expected_exit}")
        message(FATAL_ERROR "pqscan ${ARGN}: expected exit ${expected_exit}, got ${actual_exit}.\n"
            "${actual_stderr}")
    endif()
    set(last_stdout "${actual_stdout}" PARENT_SCOPE)
    set(last_stderr "${actual_stderr}" PARENT_SCOPE)
endfunction()

# Writing a baseline accepts what it finds, so the run is clean although it has findings.
run_pqscan(0 --write-baseline "${BASELINE}")
if(NOT "${last_stderr}" MATCHES "baseline of [0-9]+ findings written\n$")
    message(FATAL_ERROR "No word that the baseline was written:\n${last_stderr}")
endif()

file(READ "${BASELINE}" written)
file(READ "${EXPECTED_BASELINE}" expected)
if(NOT "${written}" STREQUAL "${expected}")
    message(FATAL_ERROR "The baseline differs.\n--- expected\n${expected}\n--- written\n${written}")
endif()

run_pqscan(0 --diff "${BASELINE}")
if(NOT "${last_stdout}" STREQUAL "" OR NOT "${last_stderr}" STREQUAL "")
    message(FATAL_ERROR "A diff against a fresh baseline found something.\n"
        "${last_stdout}\n${last_stderr}")
endif()
