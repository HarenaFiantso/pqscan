# SPDX-License-Identifier: Apache-2.0
include(FetchContent)

set(PQSCAN_DOWNLOAD_DIR "${CMAKE_BINARY_DIR}/.downloads" CACHE PATH
    "Where third-party archives are kept, so presets and CI can reuse them")

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

function(pqscan_add_unit_test name source)
    add_executable(${name} ${source})
    target_link_libraries(${name} PRIVATE pqscan_core pqscan_warnings unity)
    add_test(NAME ${name} COMMAND ${name})
    if(PQSCAN_ENABLE_MEMCHECK)
        add_test(NAME ${name}_memcheck COMMAND ${PQSCAN_MEMCHECK_COMMAND} $<TARGET_FILE:${name}>)
        set_tests_properties(${name}_memcheck PROPERTIES LABELS valgrind)
    endif()
endfunction()

pqscan_add_unit_test(test_version core/test_version.c)
target_compile_definitions(test_version PRIVATE PQSCAN_EXPECTED_VERSION="${PROJECT_VERSION}")
