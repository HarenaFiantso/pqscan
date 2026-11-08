# SPDX-License-Identifier: Apache-2.0
#
# Each fuzz target is compiled from the sources it exercises instead of being linked with
# pqscan_core, so that a libFuzzer build instruments exactly that code.

# Code that libFuzzer explores needs coverage instrumentation. pqscan_core gets it only in a
# libFuzzer build, and the third-party code it links does not, so that coverage measures ours.
if(PQSCAN_ENABLE_LIBFUZZER)
    target_compile_options(pqscan_core PRIVATE -fsanitize=fuzzer-no-link)
endif()

# Usage: pqscan_add_fuzz_target(name SOURCES file... [LIBRARIES target...] SEEDS file...)
# A small parser is compiled from its own sources, a scanner links pqscan_core.
function(pqscan_add_fuzz_target name)
    cmake_parse_arguments(PARSE_ARGV 1 FUZZ "" "" "SOURCES;LIBRARIES;SEEDS")
    add_executable(${name}_replay replay.c ${FUZZ_SOURCES})
    target_include_directories(${name}_replay PRIVATE "${PROJECT_SOURCE_DIR}/include" .)
    target_link_libraries(${name}_replay PRIVATE ${FUZZ_LIBRARIES} pqscan_posix pqscan_warnings)
    add_test(NAME ${name}_replay COMMAND ${name}_replay ${FUZZ_SEEDS})
    set_tests_properties(${name}_replay PROPERTIES LABELS fuzz)

    if(PQSCAN_ENABLE_LIBFUZZER)
        add_executable(${name} ${FUZZ_SOURCES})
        target_include_directories(${name} PRIVATE "${PROJECT_SOURCE_DIR}/include" .)
        target_compile_options(${name} PRIVATE -fsanitize=fuzzer)
        target_link_options(${name} PRIVATE -fsanitize=fuzzer)
        target_link_libraries(${name} PRIVATE ${FUZZ_LIBRARIES} pqscan_posix pqscan_warnings)
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

set(scan_fixtures "${PROJECT_SOURCE_DIR}/tests/fixtures/scan")
set(fixtures "${PROJECT_SOURCE_DIR}/tests/fixtures")

# The replay runs every seed cut at each length and edited 20000 times, so its seeds are small:
# one source file of 92 bytes already takes about 11 seconds under the sanitizers.
pqscan_add_fuzz_target(fuzz_config_lexer
    SOURCES fuzz_config_lexer.c "${PROJECT_SOURCE_DIR}/src/scan/config_lexer.c"
    SEEDS "${scan_fixtures}/configs/ssh/sshd_config" "${scan_fixtures}/configs/apache/ssl.conf")
pqscan_add_fuzz_target(fuzz_pem_blocks
    SOURCES fuzz_pem_blocks.c "${PROJECT_SOURCE_DIR}/src/scan/pem_blocks.c"
    SEEDS "${scan_fixtures}/crypto/keys/ec-p256.key" "${scan_fixtures}/crypto/certs/bundle.pem")
pqscan_add_fuzz_target(fuzz_source_scanner
    SOURCES fuzz_source_scanner.c scan_harness.c
    LIBRARIES pqscan_core
    SEEDS "${scan_fixtures}/findings/rsa.c")
pqscan_add_fuzz_target(fuzz_config_scanner
    SOURCES fuzz_config_scanner.c scan_harness.c
    LIBRARIES pqscan_core
    SEEDS "${scan_fixtures}/configs/openssl/openssl.cnf" "${scan_fixtures}/configs/ssh/sshd_config")
pqscan_add_fuzz_target(fuzz_cert_scanner
    SOURCES fuzz_cert_scanner.c scan_harness.c
    LIBRARIES pqscan_core
    SEEDS "${scan_fixtures}/crypto/keys/ec-p256.der" "${scan_fixtures}/crypto/keys/ed25519.key")
pqscan_add_fuzz_target(fuzz_rule_loader
    SOURCES fuzz_rule_loader.c
    LIBRARIES pqscan_core
    SEEDS "${fixtures}/rules/custom.json")
pqscan_add_fuzz_target(fuzz_project_file
    SOURCES fuzz_project_file.c
    LIBRARIES pqscan_core
    SEEDS "${fixtures}/projects/priority.json")
pqscan_add_fuzz_target(fuzz_baseline
    SOURCES fuzz_baseline.c
    LIBRARIES pqscan_core
    SEEDS "${fixtures}/baselines/unknown_field.json")
