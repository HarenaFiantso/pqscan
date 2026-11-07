# SPDX-License-Identifier: Apache-2.0
include(FetchContent)

FetchContent_Declare(unity
    URL https://github.com/ThrowTheSwitch/Unity/archive/refs/tags/v2.6.1.tar.gz
    URL_HASH SHA256=b41a66d45a6b99758fb3202ace6178177014d52fc524bf1f72687d93e9867292
    DOWNLOAD_DIR "${PQSCAN_DOWNLOAD_DIR}")
FetchContent_MakeAvailable(unity)

# Mark Unity's headers as system headers so our strict warnings skip them.
# FetchContent's SYSTEM option would do this but needs CMake 3.25.
get_target_property(unity_include_dirs unity INTERFACE_INCLUDE_DIRECTORIES)
set_target_properties(unity PROPERTIES
    INTERFACE_SYSTEM_INCLUDE_DIRECTORIES "${unity_include_dirs}")

add_library(pqscan_test_support STATIC support/scan_support.c support/temp_tree.c)
target_include_directories(pqscan_test_support PUBLIC support)
target_link_libraries(pqscan_test_support PUBLIC pqscan_core unity PRIVATE pqscan_posix pqscan_warnings)

function(pqscan_add_unit_test name source)
    add_executable(${name} ${source})
    target_link_libraries(${name} PRIVATE pqscan_core pqscan_posix pqscan_test_support pqscan_warnings)
    add_test(NAME ${name} COMMAND ${name})
    if(PQSCAN_ENABLE_MEMCHECK)
        add_test(NAME ${name}_memcheck COMMAND ${PQSCAN_MEMCHECK_COMMAND} $<TARGET_FILE:${name}>)
        set_tests_properties(${name}_memcheck PROPERTIES LABELS valgrind)
    endif()
endfunction()

pqscan_add_unit_test(test_call_arguments scan/test_call_arguments.c)
pqscan_add_unit_test(test_constant_eval flow/test_constant_eval.c)
pqscan_add_unit_test(test_constant_table flow/test_constant_table.c)
pqscan_add_unit_test(test_file_constants flow/test_file_constants.c)
pqscan_add_unit_test(test_function_mutations flow/test_function_mutations.c)
pqscan_add_unit_test(test_default_rules rules/test_default_rules.c)
pqscan_add_unit_test(test_file_reader scan/test_file_reader.c)
pqscan_add_unit_test(test_file_type walk/test_file_type.c)
pqscan_add_unit_test(test_finding core/test_finding.c)
pqscan_add_unit_test(test_ignore walk/test_ignore.c)
pqscan_add_unit_test(test_memory core/test_memory.c)
pqscan_add_unit_test(test_options cli/test_options.c)
pqscan_add_unit_test(test_posix core/test_posix.c)
pqscan_add_unit_test(test_primitive core/test_primitive.c)
pqscan_add_unit_test(test_risk risk/test_risk.c)
pqscan_add_unit_test(test_rule_loader rules/test_rule_loader.c)
pqscan_add_unit_test(test_rule_set rules/test_rule_set.c)
pqscan_add_unit_test(test_source_scanner scan/test_source_scanner.c)
pqscan_add_unit_test(test_status core/test_status.c)
pqscan_add_unit_test(test_string_list core/test_string_list.c)
pqscan_add_unit_test(test_syntax_parser scan/test_syntax_parser.c)
pqscan_add_unit_test(test_text_report report/test_text_report.c)
pqscan_add_unit_test(test_version core/test_version.c)
pqscan_add_unit_test(test_walker walk/test_walker.c)

add_subdirectory(integration)
target_compile_definitions(test_version PRIVATE PQSCAN_EXPECTED_VERSION="${PROJECT_VERSION}")
