#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Runs clang-tidy and cppcheck on project C files. Needs `cmake --preset debug` first,
# which writes the compile database both tools read.

set -eu

cd "$(git rev-parse --show-toplevel)"

compile_db_dir=build/debug
if [ ! -f "$compile_db_dir/compile_commands.json" ]; then
    echo "No compile database found. Run: cmake --preset debug" >&2
    exit 1
fi

# The PyPI clang-tidy is not Apple's compiler, so it cannot find the macOS SDK by itself.
sysroot_arg=""
if [ "$(uname -s)" = "Darwin" ]; then
    sysroot_arg="--extra-arg=-isysroot$(xcrun --show-sdk-path)"
fi

# shellcheck disable=SC2086 # sysroot_arg is empty or one word, and must vanish when empty.
git ls-files -- '*.c' ':(exclude)tests/fixtures/*' ':(exclude)third_party/*' |
    xargs clang-tidy --quiet -p "$compile_db_dir" $sysroot_arg

cppcheck --project="$compile_db_dir/compile_commands.json" \
    --enable=warning,style,performance,portability \
    --suppressions-list=.cppcheck-suppressions \
    --error-exitcode=1 --inline-suppr --quiet \
    -ibuild/
