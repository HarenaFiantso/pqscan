# SPDX-License-Identifier: Apache-2.0

# An interface target, not global flags, so third-party code is not built with -Werror.
add_library(pqscan_warnings INTERFACE)
target_compile_options(pqscan_warnings INTERFACE
    -Wall -Wextra -Wpedantic -Werror -Wshadow -Wconversion -Wstrict-prototypes)
