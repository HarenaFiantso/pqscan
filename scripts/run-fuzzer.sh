#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Runs one libFuzzer target for a while, starting from its seeds. Needs a fuzz build, made
# with a Clang that ships libFuzzer: the distribution's clang on Linux, or Homebrew's llvm on
# macOS, since Apple's Clang has none.
#   CC=/opt/homebrew/opt/llvm/bin/clang cmake --preset fuzz    # just `cmake --preset fuzz` on Linux
#   cmake --build --preset fuzz --target fuzz_elf_reader
#   scripts/run-fuzzer.sh elf_reader [seconds]
# Inputs that reach new code are kept in build/fuzz-corpus/<target>/, and an input that crashes
# is written to build/fuzz-crashes/.

set -eu

cd "$(git rev-parse --show-toplevel)"

target=${1:?usage: scripts/run-fuzzer.sh TARGET [SECONDS]}
seconds=${2:-60}

case "$target" in
elf_reader) seeds="tests/fixtures/scan/elf/bin tests/fixtures/scan/elf/broken" ;;
*)
    echo "Unknown fuzz target: $target" >&2
    exit 2
    ;;
esac

corpus=build/fuzz-corpus/$target
mkdir -p "$corpus" build/fuzz-crashes

# shellcheck disable=SC2086 # seeds is a list of directories without spaces.
exec "build/fuzz/fuzz/fuzz_$target" -max_total_time="$seconds" \
    -artifact_prefix=build/fuzz-crashes/ "$corpus" $seeds
