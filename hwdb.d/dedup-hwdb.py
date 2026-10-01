#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copies a hwdb file from stdin to stdout without the entries whose matches come again in a later entry
# that sets the same properties, so that each match is left once, with the values that win in hwdb.bin,
# where a later entry overrides an earlier one. Each dropped entry is reported on stderr.
#
# eudev uses it for 20-acpi-vendor.hwdb: 20-acpi-vendor.hwdb.patch adds some ids that the registries
# already have, after their registry entries, and the entries of the patch win.

import sys


def blocks(lines):
    """Splits the lines into runs of non-empty lines, each with the empty lines in front of it."""
    block, before = [], []
    for line in lines:
        if line.strip():
            block.append(line)
            continue
        if block:
            yield before, block
            block, before = [], []
        before.append(line)
    if block or before:
        yield before, block


def matches(block):
    return tuple(line for line in block if not line[0].isspace() and not line.startswith('#'))


def properties(block):
    return {line.strip().partition('=')[0] for line in block if line[0].isspace() and '=' in line}


def main():
    all_blocks = list(blocks(sys.stdin.read().splitlines(keepends=True)))
    last = {}
    for i, (_, block) in enumerate(all_blocks):
        m = matches(block)
        if m:
            last[m] = i

    out = []
    for i, (before, block) in enumerate(all_blocks):
        m = matches(block)
        if m and last[m] != i:
            later = all_blocks[last[m]][1]
            if not properties(block) <= properties(later):
                sys.exit(f'A later entry of {" ".join(line.strip() for line in m)} '
                         'does not override all properties of an earlier one')
            print(f'Dropping {" ".join(line.strip() for line in block)}, '
                  f'overridden by {" ".join(line.strip() for line in later if line[0].isspace())}',
                  file=sys.stderr)
            continue
        out += before + block

    sys.stdout.write(''.join(out))


if __name__ == '__main__':
    main()
