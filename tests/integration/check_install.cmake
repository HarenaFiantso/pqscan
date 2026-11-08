# SPDX-License-Identifier: Apache-2.0
#
# Usage: cmake -DBUILD_DIR=dir -DPREFIX=dir -DEXPECTED=file -DVERSION=x.y.z -P check_install.cmake
# Installs the build into an empty PREFIX, then fails unless it holds exactly the files EXPECTED
# lists and the installed binary runs and names VERSION.

file(REMOVE_RECURSE "${PREFIX}")
execute_process(COMMAND "${CMAKE_COMMAND}" --install "${BUILD_DIR}" --prefix "${PREFIX}"
    RESULT_VARIABLE install_exit OUTPUT_QUIET)
if(NOT install_exit EQUAL 0)
    message(FATAL_ERROR "cmake --install exited ${install_exit}")
endif()

file(GLOB_RECURSE installed RELATIVE "${PREFIX}" "${PREFIX}/*")
list(SORT installed)
file(STRINGS "${EXPECTED}" expected)
list(SORT expected)
if(NOT installed STREQUAL expected)
    message(FATAL_ERROR "installed files differ\n  installed: ${installed}\n  expected:  ${expected}")
endif()

execute_process(COMMAND "${PREFIX}/bin/pqscan" --version
    OUTPUT_VARIABLE version_output RESULT_VARIABLE version_exit)
if(NOT version_exit EQUAL 0 OR NOT version_output STREQUAL "pqscan ${VERSION}\n")
    message(FATAL_ERROR "installed pqscan --version exited ${version_exit} and printed: ${version_output}")
endif()
