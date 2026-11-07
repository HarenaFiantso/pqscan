#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Runs pqscan on trees with hostile file names, and checks every report against the official
# schemas. Unit tests decide what a report says. This decides whether other tools can read it.
#
# Usage: check-report-schemas.sh PQSCAN CYCLONEDX_SCHEMA_DIR SARIF_SCHEMA

set -eu

pqscan=$1
cyclonedx_dir=$2
sarif_schema=$3

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
write_report() {
    status=0
    "$pqscan" --format "$1" "$2" >"$3" 2>/dev/null || status=$?
    case "$status" in
    0 | 1 | 4) ;;
    *)
        echo "pqscan --format $1 $2 exited with $status" >&2
        exit 1
        ;;
    esac
}

check_tree() {
    tree=$work/$1

    write_report cbom "$tree" "$work/report.cbom.json"
    check-jsonschema --base-uri "file://$cyclonedx_dir/" \
        --schemafile "$cyclonedx_dir/bom-1.6.schema.json" "$work/report.cbom.json"

    write_report sarif "$tree" "$work/report.sarif.json"
    check-jsonschema --schemafile "$sarif_schema" "$work/report.sarif.json"

    write_report json "$tree" "$work/report.json"
    python3 -I -m json.tool "$work/report.json" >/dev/null
}

make_trees
check_tree clean
check_tree hostile
