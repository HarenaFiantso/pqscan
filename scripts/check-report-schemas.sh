#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Runs pqscan on trees with hostile file names and on the config and certificate fixtures,
# and checks every report against the official schemas. Unit tests decide what a report says.
# This decides whether other tools can read it.
#
# Usage: check-report-schemas.sh PQSCAN CYCLONEDX_SCHEMA_DIR SARIF_SCHEMA

set -eu

pqscan=$1
cyclonedx_dir=$2
sarif_schema=$3
fixtures=$(cd "$(dirname "$0")/../tests/fixtures/scan" && pwd)

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

source_line='void f(void) { RSA_new(); }'

# Not every file system takes every name: APFS refuses invalid UTF-8.
add_source() {
    { printf '%s\n' "$source_line" >"$work/$1/$2"; } 2>/dev/null || true
}

make_trees() {
    mkdir "$work/clean" "$work/hostile"
    printf 'int main(void) { return 0; }\n' >"$work/clean/plain.c"

    add_source hostile 'plain.c'
    add_source hostile 'with space.c'
    add_source hostile 'with"quote.c'
    add_source hostile 'back\slash.c'
    add_source hostile '100%.c'
    add_source hostile 'a:b.c'
    add_source hostile '#hash?.c'
    add_source hostile "$(printf 'line\nbreak.c')"
    add_source hostile "$(printf 'bad\377byte.c')"
    add_source hostile "$(printf 'caf\303\251.c')"
    printf 'a\000b' >"$work/hostile/binary.c"
}

# Exit codes 0, 1 and 4 all come with a report. Anything else is a failure of the run itself.
# Usage: write_report FORMAT OUTPUT PQSCAN_ARGUMENT...
write_report() {
    format=$1
    output=$2
    shift 2
    status=0
    "$pqscan" --format "$format" "$@" >"$output" 2>/dev/null || status=$?
    case "$status" in
    0 | 1 | 4) ;;
    *)
        echo "pqscan --format $format $* exited with $status" >&2
        exit 1
        ;;
    esac
}

# Usage: check_tree PQSCAN_ARGUMENT...
check_tree() {
    write_report cbom "$work/report.cbom.json" "$@"
    check-jsonschema --base-uri "file://$cyclonedx_dir/" \
        --schemafile "$cyclonedx_dir/bom-1.6.schema.json" "$work/report.cbom.json"

    write_report sarif "$work/report.sarif.json" "$@"
    check-jsonschema --schemafile "$sarif_schema" "$work/report.sarif.json"

    write_report json "$work/report.json" "$@"
    python3 -I -m json.tool "$work/report.json" >/dev/null
}

# The fixtures add findings of whole files and certificates that expire, and the project gives
# findings a component. Its patterns match paths relative to the fixtures.
make_trees
check_tree "$work/clean"
check_tree "$work/hostile"
check_tree "$fixtures/configs"
check_tree "$fixtures/crypto"
(cd "$fixtures" && check_tree --project ../projects/priority.json priority)
