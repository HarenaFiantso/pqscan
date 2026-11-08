#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Runs one libFuzzer target for a while, starting from its seeds. Needs a fuzz build, made
# with a Clang that ships libFuzzer: the distribution's clang on Linux, or Homebrew's llvm on
# macOS, since Apple's Clang has none.
#   CC=/opt/homebrew/opt/llvm/bin/clang cmake --preset fuzz    # just `cmake --preset fuzz` on Linux
#   cmake --build --preset fuzz --target fuzz_elf_reader
#   scripts/run-fuzzer.sh TARGET [seconds]    # TARGET is elf_reader, config_lexer, pem_blocks,
#                                             # source_scanner, config_scanner, cert_scanner,
#                                             # rule_loader, project_file or baseline
# Inputs that reach new code are kept in build/fuzz-corpus/<target>/, and an input that crashes
# is written to build/fuzz-crashes/.

set -eu

cd "$(git rev-parse --show-toplevel)"

target=${1:?usage: scripts/run-fuzzer.sh TARGET [SECONDS]}
seconds=${2:-60}

# Seeds are whole fixture directories. libFuzzer reads every file, and keeps what is new.
fixtures=tests/fixtures
case "$target" in
elf_reader) seeds="$fixtures/scan/elf/bin $fixtures/scan/elf/broken" dict="" ;;
config_lexer | config_scanner) seeds="$fixtures/scan/configs" dict=config ;;
pem_blocks | cert_scanner) seeds="$fixtures/scan/crypto" dict=crypto ;;
source_scanner) seeds="$fixtures/scan/findings $fixtures/scan/edge $fixtures/scan/priority" dict=source ;;
rule_loader) seeds="$fixtures/rules rules" dict=json ;;
project_file) seeds="$fixtures/projects" dict=json ;;
baseline) seeds="$fixtures/baselines" dict=json ;;
*)
    echo "Unknown fuzz target: $target" >&2
    exit 2
    ;;
esac

corpus=build/fuzz-corpus/$target
mkdir -p "$corpus" build/fuzz-crashes

dict_option=""
if [ -n "$dict" ]; then
    dict_option="-dict=fuzz/dict/$dict.dict"
fi

# shellcheck disable=SC2086 # seeds is a list of directories without spaces, and dict_option is
# empty or one word.
exec "build/fuzz/fuzz/fuzz_$target" -max_total_time="$seconds" -timeout=25 -rss_limit_mb=2048 \
    -artifact_prefix=build/fuzz-crashes/ $dict_option "$corpus" $seeds
