#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Checks every tracked C file against .clang-format. Used by CI and locally.

set -eu

cd "$(git rev-parse --show-toplevel)"

git ls-files -- '*.c' '*.h' ':(exclude)tests/fixtures/*' ':(exclude)third_party/*' |
    xargs clang-format --dry-run --Werror
