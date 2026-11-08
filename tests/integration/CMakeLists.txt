# SPDX-License-Identifier: Apache-2.0
set(fixtures "${PROJECT_SOURCE_DIR}/tests/fixtures/scan")
set(expected "${CMAKE_CURRENT_SOURCE_DIR}/expected")

file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/version.txt" "pqscan ${PROJECT_VERSION}\n")

# Reports name the tool version, so what they are compared with is generated.
function(pqscan_expected_report name)
    configure_file("${expected}/${name}.in" "${CMAKE_CURRENT_BINARY_DIR}/${name}" @ONLY)
endfunction()

function(pqscan_add_memcheck_case name joined_args)
    list(JOIN PQSCAN_MEMCHECK_COMMAND "|" joined_memcheck)
    add_test(NAME cli_${name}_memcheck
        COMMAND "${CMAKE_COMMAND}"
            "-DPQSCAN=$<TARGET_FILE:pqscan>"
            "-DCASE_ARGS=${joined_args}"
            "-DMEMCHECK=${joined_memcheck}"
            "-DMEMCHECK_FAILURE_EXIT=${PQSCAN_MEMCHECK_FAILURE_EXIT}"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/run_memcheck_case.cmake"
        WORKING_DIRECTORY "${fixtures}")
    set_tests_properties(cli_${name}_memcheck PROPERTIES LABELS valgrind)
endfunction()

# Usage: pqscan_add_cli_test(name EXIT code [ARGS ...] [STDOUT file] [STDERR file] [STDOUT_SINK file])
function(pqscan_add_cli_test name)
    cmake_parse_arguments(PARSE_ARGV 1 CASE "" "EXIT;STDOUT;STDERR;STDOUT_SINK" "ARGS")
    list(JOIN CASE_ARGS "|" joined_args)
    add_test(NAME cli_${name}
        COMMAND "${CMAKE_COMMAND}"
            "-DPQSCAN=$<TARGET_FILE:pqscan>"
            "-DCASE_ARGS=${joined_args}"
            "-DEXPECTED_EXIT=${CASE_EXIT}"
            "-DEXPECTED_STDOUT=${CASE_STDOUT}"
            "-DEXPECTED_STDERR=${CASE_STDERR}"
            "-DSTDOUT_SINK=${CASE_STDOUT_SINK}"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/run_case.cmake"
        WORKING_DIRECTORY "${fixtures}")
    if(PQSCAN_ENABLE_MEMCHECK)
        pqscan_add_memcheck_case(${name} "${joined_args}")
    endif()
endfunction()

pqscan_add_cli_test(help EXIT 0 ARGS --help STDOUT "${expected}/help.txt")
pqscan_add_cli_test(help_short EXIT 0 ARGS -h STDOUT "${expected}/help.txt")
pqscan_add_cli_test(version EXIT 0 ARGS --version STDOUT "${CMAKE_CURRENT_BINARY_DIR}/version.txt")
pqscan_add_cli_test(version_short EXIT 0 ARGS -V STDOUT "${CMAKE_CURRENT_BINARY_DIR}/version.txt")

pqscan_add_cli_test(no_path EXIT 2 STDOUT "${expected}/empty.txt"
    STDERR "${expected}/missing_argument_stderr.txt")
pqscan_add_cli_test(unknown_option EXIT 2 ARGS --nope clean STDOUT "${expected}/empty.txt")
pqscan_add_cli_test(ignore_without_pattern EXIT 2 ARGS clean --ignore STDOUT "${expected}/empty.txt")
pqscan_add_cli_test(missing_path EXIT 2 ARGS no-such-path STDOUT "${expected}/empty.txt"
    STDERR "${expected}/missing_path_stderr.txt")
pqscan_add_cli_test(missing_path_prints_no_partial_report EXIT 2 ARGS findings no-such-path
    STDOUT "${expected}/empty.txt" STDERR "${expected}/missing_path_stderr.txt")

pqscan_add_cli_test(clean EXIT 0 ARGS clean STDOUT "${expected}/empty.txt" STDERR "${expected}/empty.txt")
pqscan_add_cli_test(findings EXIT 1 ARGS findings STDOUT "${expected}/findings.txt"
    STDERR "${expected}/empty.txt")
pqscan_add_cli_test(single_file EXIT 1 ARGS findings/rsa.c STDOUT "${expected}/single_file.txt")
pqscan_add_cli_test(several_paths EXIT 1 ARGS clean findings/rsa.c STDOUT "${expected}/single_file.txt")
pqscan_add_cli_test(ignore_directory EXIT 1 ARGS findings --ignore sub
    STDOUT "${expected}/findings_without_sub.txt")
pqscan_add_cli_test(ignore_glob EXIT 1 ARGS --ignore *.hpp findings
    STDOUT "${expected}/findings_without_sub.txt")
pqscan_add_cli_test(ignore_everything EXIT 0
    ARGS --ignore *.c --ignore *.h --ignore *.cpp --ignore *.hpp findings
    STDOUT "${expected}/empty.txt")
pqscan_add_cli_test(configs EXIT 1 ARGS configs STDOUT "${expected}/configs.txt"
    STDERR "${expected}/empty.txt")
pqscan_add_cli_test(edge_cases EXIT 1 ARGS edge STDOUT "${expected}/edge_stdout.txt"
    STDERR "${expected}/edge_stderr.txt")

pqscan_add_cli_test(unreadable_input_is_not_a_clean_result EXIT 4 ARGS edge/binary.c
    STDOUT "${expected}/empty.txt" STDERR "${expected}/incomplete_stderr.txt")
pqscan_add_cli_test(ignoring_an_unreadable_file_makes_the_scan_complete EXIT 1
    ARGS --ignore binary.c edge STDOUT "${expected}/edge_stdout.txt" STDERR "${expected}/empty.txt")
pqscan_add_cli_test(symlink_in_a_tree_is_skipped_by_design EXIT 0 ARGS links
    STDOUT "${expected}/empty.txt" STDERR "${expected}/symlink_in_tree_stderr.txt")
pqscan_add_cli_test(symlink_as_root_is_not_a_clean_result EXIT 4 ARGS links/to_clean
    STDOUT "${expected}/empty.txt" STDERR "${expected}/symlink_root_stderr.txt")

pqscan_add_cli_test(used_up_budget_is_not_a_clean_result EXIT 4 ARGS --max-time 0 findings/rsa.c
    STDOUT "${expected}/empty.txt" STDERR "${expected}/budget_stderr.txt")
pqscan_add_cli_test(budget_must_be_a_number EXIT 2 ARGS --max-time soon clean
    STDOUT "${expected}/empty.txt" STDERR "${expected}/bad_budget_stderr.txt")

pqscan_add_cli_test(a_finding_below_the_threshold_does_not_fail EXIT 0
    ARGS --fail-on CLASSICALLY_WEAK findings/rsa.c STDOUT "${expected}/single_file.txt")
pqscan_add_cli_test(a_finding_at_the_threshold_fails EXIT 1
    ARGS --fail-on QUANTUM_VULNERABLE findings/rsa.c STDOUT "${expected}/single_file.txt")
pqscan_add_cli_test(a_finding_above_the_threshold_fails EXIT 1
    ARGS --fail-on OK findings/rsa.c STDOUT "${expected}/single_file.txt")
pqscan_add_cli_test(below_the_threshold_and_incomplete_is_not_clean EXIT 4
    ARGS --fail-on CLASSICALLY_WEAK findings/rsa.c edge/binary.c
    STDOUT "${expected}/single_file.txt" STDERR "${expected}/incomplete_stderr.txt")
pqscan_add_cli_test(at_the_threshold_and_incomplete_reports_findings EXIT 1
    ARGS --fail-on QUANTUM_VULNERABLE findings/rsa.c edge/binary.c
    STDOUT "${expected}/single_file.txt" STDERR "${expected}/incomplete_stderr.txt")
pqscan_add_cli_test(unknown_threshold EXIT 2 ARGS --fail-on review clean
    STDOUT "${expected}/empty.txt" STDERR "${expected}/bad_threshold_stderr.txt")
pqscan_add_cli_test(unknown_format EXIT 2 ARGS --format xml clean
    STDOUT "${expected}/empty.txt" STDERR "${expected}/bad_format_stderr.txt")

foreach(extension IN ITEMS json cbom.json sarif)
    pqscan_expected_report(report_clean.${extension})
    pqscan_expected_report(report_incomplete.${extension})
endforeach()
pqscan_add_cli_test(json_report EXIT 1 ARGS --format json report edge/binary.c
    STDOUT "${CMAKE_CURRENT_BINARY_DIR}/report_incomplete.json")
pqscan_add_cli_test(json_report_of_a_clean_tree EXIT 0 ARGS -f json clean
    STDOUT "${CMAKE_CURRENT_BINARY_DIR}/report_clean.json" STDERR "${expected}/empty.txt")
pqscan_add_cli_test(cbom_report EXIT 1 ARGS --format cbom report edge/binary.c
    STDOUT "${CMAKE_CURRENT_BINARY_DIR}/report_incomplete.cbom.json")
pqscan_add_cli_test(cbom_report_of_a_clean_tree EXIT 0 ARGS -f cbom clean
    STDOUT "${CMAKE_CURRENT_BINARY_DIR}/report_clean.cbom.json" STDERR "${expected}/empty.txt")
pqscan_add_cli_test(sarif_report EXIT 1 ARGS --format sarif report edge/binary.c
    STDOUT "${CMAKE_CURRENT_BINARY_DIR}/report_incomplete.sarif")
pqscan_add_cli_test(sarif_report_of_a_clean_tree EXIT 0 ARGS -f sarif clean
    STDOUT "${CMAKE_CURRENT_BINARY_DIR}/report_clean.sarif" STDERR "${expected}/empty.txt")

pqscan_add_cli_test(custom_rules EXIT 1 ARGS --rules ../rules/custom.json custom
    STDOUT "${expected}/custom_rules.txt" STDERR "${expected}/empty.txt")
pqscan_add_cli_test(custom_rules_replace_the_built_in_ones EXIT 0
    ARGS --rules ../rules/custom.json findings STDOUT "${expected}/empty.txt")
pqscan_add_cli_test(malformed_rules EXIT 2 ARGS --rules ../rules/malformed.json findings
    STDOUT "${expected}/empty.txt" STDERR "${expected}/malformed_rules_stderr.txt")
pqscan_add_cli_test(invalid_rules EXIT 2 ARGS --rules ../rules/unknown_algorithm.json findings
    STDOUT "${expected}/empty.txt" STDERR "${expected}/unknown_algorithm_rules_stderr.txt")
pqscan_add_cli_test(missing_rules EXIT 2 ARGS --rules ../rules/no-such-file.json findings
    STDOUT "${expected}/empty.txt" STDERR "${expected}/missing_rules_stderr.txt")
pqscan_add_cli_test(rules_without_file EXIT 2 ARGS findings --rules STDOUT "${expected}/empty.txt")
pqscan_add_cli_test(rules_cannot_forge_a_diagnostic EXIT 2
    ARGS --rules ../rules/escape_in_field.json findings
    STDOUT "${expected}/empty.txt" STDERR "${expected}/escape_in_field_stderr.txt")

# /dev/full fails every write. macOS does not have it.
if(EXISTS /dev/full)
    pqscan_add_cli_test(unwritable_report EXIT 3 ARGS findings STDOUT_SINK /dev/full)
    pqscan_add_cli_test(unwritable_json_report EXIT 3 ARGS -f json findings
        STDOUT_SINK /dev/full)
    pqscan_add_cli_test(unwritable_cbom_report EXIT 3 ARGS -f cbom findings
        STDOUT_SINK /dev/full)
    pqscan_add_cli_test(unwritable_sarif_report EXIT 3 ARGS -f sarif findings
        STDOUT_SINK /dev/full)
endif()

if(PQSCAN_CHECK_REPORT_SCHEMAS)
    add_test(NAME report_schemas
        COMMAND "${PROJECT_SOURCE_DIR}/scripts/check-report-schemas.sh" $<TARGET_FILE:pqscan>
            "${cyclonedx_specification_SOURCE_DIR}/schema"
            "${sarif_schema_SOURCE_DIR}/sarif-schema-2.1.0.json")
    set_tests_properties(report_schemas PROPERTIES LABELS schema)
endif()
