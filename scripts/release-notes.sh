#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Usage: scripts/release-notes.sh VERSION
# Prints the section of CHANGELOG.md for VERSION, without its heading, and fails if it has none.

set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 VERSION" >&2
    exit 2
fi
root=$(cd "$(dirname "$0")/.." && pwd)

# A section ends at the next heading of its level, or at the links at the bottom of the file.
if ! awk -v version="$1" '
    index($0, "## [" version "] - ") == 1 { found = 1; next }
    found && (/^## \[/ || /^\[[^]]*\]: /) { exit }
    found { print }
    END { exit found ? 0 : 1 }
' "$root/CHANGELOG.md"; then
    echo "CHANGELOG.md has no section for $1" >&2
    exit 1
fi
