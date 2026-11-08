#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Usage: scripts/package-release.sh INSTALL_DIR PLATFORM
# Checks the pqscan that `cmake --install` put in INSTALL_DIR, then archives it as
# pqscan-VERSION-PLATFORM.tar.gz in the current directory, and prints the archive's name.

set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 INSTALL_DIR PLATFORM" >&2
    exit 2
fi
install_dir=$1
platform=$2
root=$(cd "$(dirname "$0")/.." && pwd)
version=$(sed -n 's/^    VERSION \([0-9.]*\)$/\1/p' "$root/CMakeLists.txt")
pqscan="$install_dir/bin/pqscan"

if [ "$("$pqscan" --version)" != "pqscan $version" ]; then
    echo "$pqscan is not pqscan $version" >&2
    exit 1
fi
code=0
"$pqscan" "$root/tests/fixtures/scan/findings" > /dev/null || code=$?
if [ "$code" -ne 1 ]; then
    echo "$pqscan exited $code on the findings fixtures, not 1" >&2
    exit 1
fi
"$pqscan" "$root/tests/fixtures/scan/clean"

name="pqscan-$version-$platform"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
mkdir "$stage/$name"
cp -R "$install_dir/." "$stage/$name"
tar -czf "$name.tar.gz" -C "$stage" "$name"
echo "$name.tar.gz"
