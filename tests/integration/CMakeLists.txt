# SPDX-License-Identifier: Apache-2.0
set(fixtures "${PROJECT_SOURCE_DIR}/tests/fixtures/scan")
set(expected "${CMAKE_CURRENT_SOURCE_DIR}/expected")

file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/version.txt" "pqscan ${PROJECT_VERSION}\n")

# Reports name the tool version, so what they are compared with is generated.
function(pqscan_expected_report name)
    configure_file("${expected}/${name}.in" "${CMAKE_CURRENT_BINARY_DIR}/${name}" @ONLY)
endfunction()

# Priorities depend on the year, so every case scores for the same one. A case can still give
# its own --as-of, which comes later and wins.
set(pinned_year 2026)

function(pqscan_add_memcheck_case name joined_args directory)
    list(JOIN PQSCAN_MEMCHECK_COMMAND "|" joined_memcheck)
    add_test(NAME cli_${name}_memcheck
        COMMAND "${CMAKE_COMMAND}"
            "-DPQSCAN=$<TARGET_FILE:pqscan>"
            "-DCASE_ARGS=${joined_args}"
            "-DMEMCHECK=${joined_memcheck}"
            "-DMEMCHECK_FAILURE_EXIT=${PQSCAN_MEMCHECK_FAILURE_EXIT}"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/run_memcheck_case.cmake"
        WORKING_DIRECTORY "${directory}")
    set_tests_properties(cli_${name}_memcheck PROPERTIES LABELS valgrind)
endfunction()

# Usage: pqscan_add_cli_test(name EXIT code [ARGS ...] [STDOUT file] [STDERR file]
#                            [STDOUT_SINK file] [DIRECTORY dir])
# The case runs in DIRECTORY, by default the scan fixtures.
function(pqscan_add_cli_test name)
    cmake_parse_arguments(PARSE_ARGV 1 CASE "" "EXIT;STDOUT;STDERR;STDOUT_SINK;DIRECTORY" "ARGS")
    if(NOT CASE_DIRECTORY)
        set(CASE_DIRECTORY "${fixtures}")
    endif()
    list(JOIN CASE_ARGS "|" joined_args)
    set(joined_args "--as-of|${pinned_year}|${joined_args}")
    add_test(NAME cli_${name}
        COMMAND "${CMAKE_COMMAND}"
            "-DPQSCAN=$<TARGET_FILE:pqscan>"
            "-DCASE_ARGS=${joined_args}"
            "-DEXPECTED_EXIT=${CASE_EXIT}"
            "-DEXPECTED_STDOUT=${CASE_STDOUT}"
            "-DEXPECTED_STDERR=${CASE_STDERR}"
            "-DSTDOUT_SINK=${CASE_STDOUT_SINK}"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/run_case.cmake"
        WORKING_DIRECTORY "${CASE_DIRECTORY}")
    if(PQSCAN_ENABLE_MEMCHECK)
        pqscan_add_memcheck_case(${name} "${joined_args}" "${CASE_DIRECTORY}")
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
pqscan_add_cli_test(certificates EXIT 1 ARGS crypto/certs STDOUT "${expected}/crypto_certs.txt"
    STDERR "${expected}/empty.txt")
pqscan_add_cli_test(keys EXIT 1 ARGS crypto/keys STDOUT "${expected}/crypto_keys.txt"
    STDERR "${expected}/crypto_keys_stderr.txt")
pqscan_add_cli_test(broken_certificates_keep_the_findings_of_the_rest EXIT 1 ARGS crypto/broken
    STDOUT "${expected}/crypto_broken.txt" STDERR "${expected}/crypto_broken_stderr.txt")
pqscan_add_cli_test(a_truncated_certificate_is_not_a_clean_result EXIT 4
    ARGS crypto/broken/truncated.der
    STDOUT "${expected}/empty.txt" STDERR "${expected}/truncated_der_stderr.txt")
pqscan_add_cli_test(an_encrypted_key_is_not_a_clean_result EXIT 4
    ARGS crypto/keys/rsa-2048-encrypted.key
    STDOUT "${expected}/empty.txt" STDERR "${expected}/encrypted_key_stderr.txt")
pqscan_add_cli_test(elf_binaries EXIT 1 ARGS elf/bin STDOUT "${expected}/elf.txt"
    STDERR "${expected}/empty.txt")
pqscan_add_cli_test(unreadable_elf_files_are_not_a_clean_result EXIT 4 ARGS elf/broken
    STDOUT "${expected}/empty.txt" STDERR "${expected}/elf_broken_stderr.txt")
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
pqscan_expected_report(report_der_certificate.json)
pqscan_add_cli_test(json_report_of_a_der_certificate EXIT 1 ARGS -f json crypto/certs/ec-p256.der
    STDOUT "${CMAKE_CURRENT_BINARY_DIR}/report_der_certificate.json" STDERR "${expected}/empty.txt")
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

set(projects "${PROJECT_SOURCE_DIR}/tests/fixtures/projects")
pqscan_add_cli_test(without_a_project_equal_risks_go_by_path EXIT 1 ARGS priority
    STDOUT "${expected}/priority_without_project.txt" STDERR "${expected}/empty.txt")
pqscan_add_cli_test(a_project_ranks_long_lived_secrets_first EXIT 1
    ARGS --project ../projects/priority.json priority
    STDOUT "${expected}/priority_with_project.txt" STDERR "${expected}/empty.txt")
pqscan_add_cli_test(a_later_year_raises_quantum_priorities EXIT 1
    ARGS --project ../projects/priority.json --as-of 2036 priority
    STDOUT "${expected}/priority_in_2036.txt" STDERR "${expected}/empty.txt")
pqscan_add_cli_test(a_project_file_in_the_current_directory_is_read EXIT 1 ARGS .
    DIRECTORY "${projects}/discovered"
    STDOUT "${expected}/priority_discovered.txt" STDERR "${expected}/empty.txt")
pqscan_add_cli_test(a_broken_project_file_in_the_current_directory_is_an_error EXIT 2 ARGS .
    DIRECTORY "${projects}/broken_discovered"
    STDOUT "${expected}/empty.txt" STDERR "${expected}/broken_discovered_project_stderr.txt")
pqscan_add_cli_test(invalid_project EXIT 2 ARGS --project ../projects/unknown_field.json priority
    STDOUT "${expected}/empty.txt" STDERR "${expected}/unknown_field_project_stderr.txt")
pqscan_add_cli_test(missing_project EXIT 2 ARGS --project ../projects/no-such-file.json priority
    STDOUT "${expected}/empty.txt" STDERR "${expected}/missing_project_stderr.txt")
pqscan_add_cli_test(project_without_file EXIT 2 ARGS priority --project
    STDOUT "${expected}/empty.txt")
pqscan_add_cli_test(year_must_be_a_year EXIT 2 ARGS --as-of 26 priority
    STDOUT "${expected}/empty.txt" STDERR "${expected}/bad_year_stderr.txt")

set(baselines "${PROJECT_SOURCE_DIR}/tests/fixtures/baselines")
add_test(NAME cli_a_written_baseline_accepts_the_scan_it_came_from
    COMMAND "${CMAKE_COMMAND}"
        "-DPQSCAN=$<TARGET_FILE:pqscan>"
        "-DCASE_ARGS=--as-of|${pinned_year}|findings"
        "-DBASELINE=${CMAKE_CURRENT_BINARY_DIR}/written_baseline.json"
        "-DEXPECTED_BASELINE=${baselines}/findings.json"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/run_baseline_case.cmake"
    WORKING_DIRECTORY "${fixtures}")
if(PQSCAN_ENABLE_MEMCHECK)
    pqscan_add_memcheck_case(write_baseline
        "--write-baseline|${CMAKE_CURRENT_BINARY_DIR}/memcheck_baseline.json|findings"
        "${fixtures}")
endif()
pqscan_add_cli_test(diff_against_a_full_baseline_finds_nothing_new EXIT 0
    ARGS --diff ../baselines/findings.json findings
    STDOUT "${expected}/empty.txt" STDERR "${expected}/empty.txt")
pqscan_add_cli_test(diff_ignores_a_leading_current_directory EXIT 0
    ARGS --diff ../baselines/findings.json ./findings
    STDOUT "${expected}/empty.txt" STDERR "${expected}/empty.txt")
pqscan_add_cli_test(diff_reports_new_findings_and_stale_entries EXIT 1
    ARGS --diff ../baselines/partial.json findings
    STDOUT "${expected}/diff_new_findings.txt" STDERR "${expected}/diff_stale_stderr.txt")
pqscan_add_cli_test(diff_below_the_threshold_does_not_fail EXIT 0
    ARGS --fail-on CLASSICALLY_WEAK --diff ../baselines/partial.json findings
    STDOUT "${expected}/diff_new_findings.txt")
pqscan_add_cli_test(diff_of_an_incomplete_scan_is_not_clean EXIT 4
    ARGS --diff ../baselines/findings.json findings edge/binary.c
    STDOUT "${expected}/empty.txt" STDERR "${expected}/incomplete_stderr.txt")
pqscan_add_cli_test(invalid_baseline EXIT 2 ARGS --diff ../baselines/unknown_field.json findings
    STDOUT "${expected}/empty.txt" STDERR "${expected}/unknown_field_baseline_stderr.txt")
pqscan_add_cli_test(missing_baseline EXIT 2 ARGS --diff ../baselines/no-such-file.json findings
    STDOUT "${expected}/empty.txt" STDERR "${expected}/missing_baseline_stderr.txt")
pqscan_add_cli_test(diff_without_file EXIT 2 ARGS findings --diff STDOUT "${expected}/empty.txt")
pqscan_add_cli_test(diff_and_write_baseline_together EXIT 2
    ARGS --diff ../baselines/findings.json --write-baseline new.json findings
    STDOUT "${expected}/empty.txt" STDERR "${expected}/diff_and_write_baseline_stderr.txt")
pqscan_add_cli_test(uncreatable_baseline EXIT 2
    ARGS --write-baseline no-such-dir/baseline.json findings/rsa.c
    STDOUT "${expected}/empty.txt" STDERR "${expected}/uncreatable_baseline_stderr.txt")

# /dev/full fails every write. macOS does not have it.
if(EXISTS /dev/full)
    pqscan_add_cli_test(unwritable_report EXIT 3 ARGS findings STDOUT_SINK /dev/full)
    pqscan_add_cli_test(unwritable_json_report EXIT 3 ARGS -f json findings
        STDOUT_SINK /dev/full)
    pqscan_add_cli_test(unwritable_cbom_report EXIT 3 ARGS -f cbom findings
        STDOUT_SINK /dev/full)
    pqscan_add_cli_test(unwritable_sarif_report EXIT 3 ARGS -f sarif findings
        STDOUT_SINK /dev/full)
    pqscan_add_cli_test(unwritable_baseline EXIT 3 ARGS --write-baseline /dev/full findings)
endif()

if(PQSCAN_CHECK_REPORT_SCHEMAS)
    add_test(NAME report_schemas
        COMMAND "${PROJECT_SOURCE_DIR}/scripts/check-report-schemas.sh" $<TARGET_FILE:pqscan>
            "${cyclonedx_specification_SOURCE_DIR}/schema"
            "${sarif_schema_SOURCE_DIR}/sarif-schema-2.1.0.json")
    set_tests_properties(report_schemas PROPERTIES LABELS schema)
endif()
