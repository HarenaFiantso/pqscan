# SPDX-License-Identifier: Apache-2.0

# Off where pqscan is only being installed, such as in the GitHub Action, so that a warning a
# newer compiler adds does not stop someone else's CI. Development and our CI keep it on.
option(PQSCAN_WARNINGS_AS_ERRORS "Turn compiler warnings into errors" ON)

# An interface target, not global flags, so third-party code is not built with -Werror.
add_library(pqscan_warnings INTERFACE)
target_compile_options(pqscan_warnings INTERFACE
    -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wstrict-prototypes)
if(PQSCAN_WARNINGS_AS_ERRORS)
    target_compile_options(pqscan_warnings INTERFACE -Werror)
endif()
