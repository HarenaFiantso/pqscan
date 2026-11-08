# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 3.20...3.31)

project(pqscan
    VERSION 0.7.0
    DESCRIPTION "Find quantum-vulnerable cryptography in C/C++ source, configs, certificates and ELF binaries"
    LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(PQSCAN_ENABLE_LIBFUZZER "Build the libFuzzer targets, which needs a Clang with libFuzzer" OFF)

include(cmake/posix.cmake)
include(cmake/warnings.cmake)
include(cmake/memcheck.cmake)
include(cmake/dependencies.cmake)
include(cmake/openssl.cmake)
include(cmake/embed_rules.cmake)
include(cmake/report_schemas.cmake)

set(default_rules_c "${CMAKE_CURRENT_BINARY_DIR}/generated/default_rules.c")
pqscan_embed_rules("${PROJECT_SOURCE_DIR}/rules/default.json" "${default_rules_c}")

add_library(pqscan_core STATIC
    "${default_rules_c}"
    src/cli/diagnostic.c
    src/cli/options.c
    src/cli/rule_option.c
    src/cli/run.c
    src/core/clock.c
    src/core/finding.c
    src/core/json_fields.c
    src/core/key_size.c
    src/core/memory.c
    src/core/path_pattern.c
    src/core/primitive.c
    src/core/safe_text.c
    src/core/skip_list.c
    src/core/status.c
    src/core/string_list.c
    src/core/utc_time.c
    src/core/version.c
    src/flow/constant_eval.c
    src/flow/constant_flow.c
    src/flow/constant_table.c
    src/flow/declarations.c
    src/flow/file_constants.c
    src/flow/function_mutations.c
    src/report/cbom_report.c
    src/report/json_report.c
    src/report/json_writer.c
    src/report/report_format.c
    src/report/report_summary.c
    src/report/sarif_report.c
    src/report/sarif_uri.c
    src/report/text_report.c
    src/risk/priority.c
    src/risk/risk.c
    src/rules/rule_loader.c
    src/rules/rule_set.c
    src/scan/call_arguments.c
    src/scan/cert_scanner.c
    src/scan/config_lexer.c
    src/scan/config_list.c
    src/scan/config_scanner.c
    src/scan/crypto_object.c
    src/scan/elf_reader.c
    src/scan/elf_scanner.c
    src/scan/file_reader.c
    src/scan/pem_blocks.c
    src/scan/source_scanner.c
    src/scan/syntax_parser.c
    src/walk/file_type.c
    src/walk/walker.c)
target_include_directories(pqscan_core PUBLIC include)
target_compile_definitions(pqscan_core PRIVATE PQSCAN_VERSION_STRING="${PROJECT_VERSION}")
target_link_libraries(pqscan_core
    PUBLIC pqscan_tree_sitter
    PRIVATE pqscan_cjson pqscan_grammar_c pqscan_grammar_cpp pqscan_openssl pqscan_posix pqscan_warnings)

add_executable(pqscan src/cli/main.c)
target_link_libraries(pqscan PRIVATE pqscan_core pqscan_posix pqscan_warnings)

enable_testing()
add_subdirectory(tests)
add_subdirectory(fuzz)
