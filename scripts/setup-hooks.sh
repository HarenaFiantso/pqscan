#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Points git at the versioned hooks in .githooks/. Safe to run more than once.

set -eu

cd "$(git rev-parse --show-toplevel)"
git config core.hooksPath .githooks
echo "Git hooks enabled from .githooks/."

for tool in cmake ctest clang-format; do
    command -v "$tool" >/dev/null 2>&1 || echo "Warning: $tool not found; see CONTRIBUTING.md." >&2
done
