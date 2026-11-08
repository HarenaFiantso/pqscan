#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Regenerates the ELF fixtures from src/. The output is committed, so tests never need a
# cross compiler. Clang alone is enough: it writes ELF objects for any target it was built
# with, without a linker or a sysroot, so this runs on macOS as well as on Linux.
#   tests/fixtures/scan/elf/generate.sh [path/to/clang]

set -eu

clang=${1:-clang}
cd "$(dirname "$0")"
rm -rf bin broken
mkdir bin broken

compile() { # target, output
    "$clang" --target="$1" -O0 -fno-ident -fno-asynchronous-unwind-tables -c src/client.c -o "$2"
}

compile x86_64-linux-gnu bin/client.o
# No extension, as most executables have none: only its first bytes say it is ELF.
compile aarch64_be-linux-gnu bin/client-aarch64be
printf 'Not every file without an extension is a binary.\n' > bin/notes

compile i386-linux-gnu broken/client-i386.o
# The header survives, the section table does not.
head -c 256 bin/client.o > broken/truncated.o
