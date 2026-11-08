# SPDX-License-Identifier: Apache-2.0
#
# Each fuzz target is compiled from the sources it exercises instead of being linked with
# pqscan_core, so that a libFuzzer build instruments exactly that code.

# Usage: pqscan_add_fuzz_target(name SOURCES file... SEEDS file...)
function(pqscan_add_fuzz_target name)
    cmake_parse_arguments(PARSE_ARGV 1 FUZZ "" "" "SOURCES;SEEDS")
    add_executable(${name}_replay replay.c ${FUZZ_SOURCES})
    target_include_directories(${name}_replay PRIVATE "${PROJECT_SOURCE_DIR}/include" .)
    target_link_libraries(${name}_replay PRIVATE pqscan_posix pqscan_warnings)
    add_test(NAME ${name}_replay COMMAND ${name}_replay ${FUZZ_SEEDS})
    set_tests_properties(${name}_replay PROPERTIES LABELS fuzz)

    if(PQSCAN_ENABLE_LIBFUZZER)
        add_executable(${name} ${FUZZ_SOURCES})
        target_include_directories(${name} PRIVATE "${PROJECT_SOURCE_DIR}/include" .)
        target_compile_options(${name} PRIVATE -fsanitize=fuzzer)
        target_link_options(${name} PRIVATE -fsanitize=fuzzer)
        target_link_libraries(${name} PRIVATE pqscan_posix pqscan_warnings)
    endif()
endfunction()

set(elf_fixtures "${PROJECT_SOURCE_DIR}/tests/fixtures/scan/elf")
pqscan_add_fuzz_target(fuzz_elf_reader
    SOURCES
        fuzz_elf_reader.c
        "${PROJECT_SOURCE_DIR}/src/scan/elf_reader.c"
        "${PROJECT_SOURCE_DIR}/src/walk/file_type.c"
    SEEDS
        "${elf_fixtures}/bin/client.o"
        "${elf_fixtures}/bin/client-aarch64be"
        "${elf_fixtures}/broken/client-i386.o"
        "${elf_fixtures}/broken/truncated.o")
