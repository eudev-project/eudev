#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Runs dmi_memory_id -F on every dump in dmidecode-dumps/ and compares its output with the expected one in
# <dump>.txt, like the dmidecode_* tests of systemd (test/udev-dmi-memory-id-test.sh, one test per dump
# there). The dumps of real machines come from systemd's test/dmidecode-dumps/, the crafted ones from
# dmidecode-dumps/make-crafted-dumps.py.
#
# Environment:
#   TEST_DMI_MEMORY_ID  dmi_memory_id (default: ../src/dmi_memory_id/dmi_memory_id)
#
# Exit status: 0 on success, 1 if an output differs, 77 if dmi_memory_id is missing.

set -u

DMI_MEMORY_ID=${TEST_DMI_MEMORY_ID:-../src/dmi_memory_id/dmi_memory_id}
if [ ! -x "$DMI_MEMORY_ID" ]; then
        echo "$DMI_MEMORY_ID not found, skipping"
        exit 77
fi

DUMPS=$(dirname "$0")/dmidecode-dumps
T=$(mktemp -d) || exit 1
trap 'rm -rf "$T"' EXIT
fail=0
n=0

for input in "$DUMPS"/*.bin; do
        name=${input##*/}
        n=$((n + 1))
        if ! "$DMI_MEMORY_ID" -F "$input" > "$T/output" 2> "$T/stderr"; then
                echo "FAIL: $name: dmi_memory_id failed"
                sed 's/^/  /' "$T/stderr"
                fail=1
        elif ! diff -u "$input.txt" "$T/output" > "$T/diff"; then
                echo "FAIL: $name: the output differs from $name.txt"
                cat "$T/diff"
                fail=1
        else
                echo "ok: $name"
        fi
done

if [ "$n" -eq 0 ]; then
        echo "FAIL: no dumps in $DUMPS"
        fail=1
fi

exit $fail
