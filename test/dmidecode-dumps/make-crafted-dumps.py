#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Writes the crafted dumps crafted-*.bin of this directory: minimal SMBIOS 3.3 tables in the layout of
# "dmidecode --dump-bin" (the 64-bit entry point at offset 0, the table at offset 0x20), which
# "dmi_memory_id -F" reads, each with a Memory Device (Type 17) entry per case below and the End-of-Table
# entry (Type 127). They test values that the dumps of real machines do not contain; the expected output
# of each is in <dump>.txt, see dmi-memory-id-test.sh.
#
#   crafted-voltages.bin       minimum, maximum and configured voltage (7.18.x, offsets 0x22, 0x24, 0x26)
#                              in mV: whole tenths of a volt (DDR, DDR2, DDR3, DDR4, DDR5), DDR3L's 1.35 V,
#                              whole volts, and 0 (unknown)
#   crafted-64-bit-sizes.bin   the 64-bit sizes of SMBIOS 3.2 (7.18.12, 7.18.13, offsets 0x34-0x53),
#                              which take 64 bits also on 32-bit systems: multiples of 4 GiB, values
#                              whose low 32 bits are all ones, 0 (none) and all ones (unknown)
#
# usage: make-crafted-dumps.py [DIRECTORY]

import os
import struct
import sys

GIB = 1 << 30
MIB = 1 << 20


def type17(handle, locator, length=0x28, volts=(1200, 1200, 1200), size_mb=8192, extended_size=None,
           sizes64=None):
    d = bytearray(length)
    d[0] = 17
    d[1] = length
    struct.pack_into('<H', d, 0x02, handle)
    struct.pack_into('<H', d, 0x04, 0x1000)                 # physical memory array handle
    struct.pack_into('<H', d, 0x06, 0xFFFE)                 # no error information
    struct.pack_into('<H', d, 0x08, 64)                     # total width
    struct.pack_into('<H', d, 0x0A, 64)                     # data width
    if extended_size is None:
        struct.pack_into('<H', d, 0x0C, size_mb)            # size in MB
    else:
        struct.pack_into('<H', d, 0x0C, 0x7FFF)             # see Extended Size
        struct.pack_into('<I', d, 0x1C, extended_size)
    d[0x0E] = 0x09                                          # form factor: DIMM
    d[0x10] = 1                                             # locator: string 1
    d[0x12] = 0x1A                                          # type: DDR4
    struct.pack_into('<H', d, 0x13, 0x0080)                 # type detail: synchronous
    struct.pack_into('<H', d, 0x15, 2666)                   # speed
    d[0x1B] = 1                                             # rank
    struct.pack_into('<H', d, 0x20, 2666)                   # configured speed
    for offset, mv in zip((0x22, 0x24, 0x26), volts):
        struct.pack_into('<H', d, offset, mv)
    if sizes64 is not None:
        d[0x28] = 0x03                                      # memory technology: DRAM
        struct.pack_into('<H', d, 0x29, 0x0008)             # operating mode capability: volatile memory
        for offset, size in zip((0x34, 0x3C, 0x44, 0x4C), sizes64):
            struct.pack_into('<Q', d, offset, size)
    return bytes(d) + locator.encode() + b'\0\0'


def write_dump(path, entries):
    table = b''.join(type17(0x1100 + i, **e) for i, e in enumerate(entries))
    table += bytes([127, 4, 0xFF, 0xFF, 0, 0])              # End-of-Table
    ep = bytearray(0x18)
    ep[0:5] = b'_SM3_'
    ep[6] = 0x18                                            # entry point length
    ep[7], ep[8] = 3, 3                                     # SMBIOS 3.3
    ep[0x0A] = 1                                            # entry point revision
    struct.pack_into('<I', ep, 0x0C, len(table))            # table maximum size
    struct.pack_into('<Q', ep, 0x10, 0x20)                  # table address: offset in the dump
    ep[5] = (-sum(ep)) & 0xFF                               # checksum
    with open(path, 'wb') as f:
        f.write(bytes(ep) + bytes(0x20 - len(ep)) + table)


def main():
    directory = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))

    write_dump(os.path.join(directory, 'crafted-voltages.bin'), [
        dict(locator='DDR4', volts=(1200, 1200, 1200)),
        dict(locator='DDR3', volts=(1500, 1500, 1500)),
        dict(locator='DDR3L', volts=(1350, 1500, 1350)),
        dict(locator='DDR5', volts=(1100, 1100, 1100)),
        dict(locator='DDR2', volts=(1800, 1800, 1800)),
        dict(locator='DDR', volts=(2500, 2600, 2500)),
        dict(locator='whole volts', volts=(1000, 2000, 1000)),
        dict(locator='unknown', volts=(0, 0, 0)),
    ])

    # (non-volatile, volatile, cache, logical)
    write_dump(os.path.join(directory, 'crafted-64-bit-sizes.bin'), [
        dict(locator='DIMM A', length=0x54, extended_size=16 * GIB // MIB,
             sizes64=(0, 16 * GIB, 0, 0xFFFFFFFFFFFFFFFF)),
        dict(locator='DIMM B', length=0x54, extended_size=4 * GIB // MIB,
             sizes64=(0x200000000, 4 * GIB, 0x1FFFFFFFF, 0)),
        dict(locator='DIMM C', length=0x54, extended_size=4 * GIB // MIB,
             sizes64=(0xFFFFFFFF, 0x100000001, 0, 0x400000000)),
    ])


if __name__ == '__main__':
    main()
