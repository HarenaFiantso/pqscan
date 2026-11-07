# SPDX-License-Identifier: Apache-2.0

# -std=c11 makes glibc hide everything outside ISO C, so POSIX has to be requested. macOS shows
# it all by default, which is why a missing request would only surface on Linux. Requesting a
# POSIX level on macOS then hides names such as O_NOFOLLOW, which _DARWIN_C_SOURCE restores.
add_library(pqscan_posix INTERFACE)
target_compile_definitions(pqscan_posix INTERFACE
    _XOPEN_SOURCE=700
    $<$<PLATFORM_ID:Darwin>:_DARWIN_C_SOURCE>)
