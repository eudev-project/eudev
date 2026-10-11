# eudev Licensing

This directory contains the full texts of the licenses used by the files of
the eudev source tree, named by their SPDX identifiers (https://spdx.org/).
The license notice at the top of a file, either an SPDX-License-Identifier
line or the full notice, says which license applies to it. This file lists
those notices, by license. COPYING in the top directory is the text of the GPL
version 2, the same as GPL-2.0-or-later.txt.

Most of eudev comes from udev of systemd, whose files carry the same licenses.

## Main licenses

Unless otherwise noted, the eudev sources are licensed under the terms and
conditions of **LGPL-2.1-or-later** (**GNU Lesser General Public License v2.1
or later**), like the systemd sources. This also applies to the files that
have no license notice of their own (see the end).

The license notices of the files name these two licenses:

 * **GPL-2.0-or-later** (GNU General Public License v2.0 or later,
   GPL-2.0-or-later.txt):
   - the udev daemon and udevadm: most of src/udev/, e.g. udevd.c, udev.h,
     udev-event.c, udev-node.c, udev-rules.c, udev-rules-check.c,
     udev-watch.c, udev-dump.c, the udevadm-*.c files of the udevadm
     commands except udevadm-hwdb.c, and the builtins blkid, factory_reset,
     input_id, kmod, path_id, tpm2_id and usb_id
   - the udev helper programs: src/ata_id/, src/cdrom_id/, src/collect/,
     src/dmi_memory_id/, src/mtd_probe/, src/scsi_id/ (see below for
     scsi.h) and src/v4l_id/
   - rule_generator/rule_generator.functions and
     rule_generator/write_net_rules.in
   - test/test-collect.c, which includes src/collect/collect.c, and
     test/test-scsi_id.c, which includes src/scsi_id/scsi_id.c
   - test/rule-syntax-check.py, test/hwdb-test.sh, hwdb.d/dedup-hwdb.py and
     tools/gen-net-naming-rules.py

 * **LGPL-2.1-or-later** (GNU Lesser General Public License v2.1 or later,
   LGPL-2.1-or-later.txt):
   - libudev: src/libudev/
   - most of the shared code in src/shared/ (see below for the exceptions)
   - the other files of src/udev/, e.g. udev-builtin.c, udev-ctrl.c,
     hwdb-util.c, systemd-hwdb.c, udevadm-hwdb.c, netif-naming-scheme.c,
     blockdev-util.c, reread-partition-table.c, udev-netlink.c and the
     builtins btrfs, hwdb, keyboard, net_driver and net_id
   - src/fido_id/ and src/include/glibc/
   - the other test programs test/test-*.c, and test/udev-devlink-test.sh
   - the man page sources man/hwdb.xml, man/systemd-hwdb.xml,
     man/udev.conf.xml and man/custom-man.xsl
   - the shell completions in shell-completion/
   - hwdb.d/ids_parser.py, hwdb.d/acpi-update.py and
     hwdb.d/60-autosuspend-fingerprint-reader.hwdb

Hence the programs udevd and udevadm and the helper programs, which include
sources under GPL-2.0-or-later, are effectively distributed under
GPL-2.0-or-later (scsi_id under GPL-2.0-only, see below), and libudev, which is
built from sources under LGPL-2.1-or-later and the more permissive licenses
below, under LGPL-2.1-or-later.

## Other licenses

 * **GPL-2.0-only** (the text is GPL-2.0-or-later.txt): src/scsi_id/scsi.h,
   whose notice names version 2 of the license without "or any later
   version". Hence the helper program scsi_id, which is built with it, is
   effectively distributed under GPL-2.0-only. eudev keeps the notice as it
   is; systemd marks its copy as GPL-2.0-or-later.
 * **GPL-2.0-only WITH Linux-syscall-note** (GPL-2.0-or-later.txt and
   Linux-syscall-note.txt): src/include/uapi/linux/input.h and
   src/include/uapi/linux/input-event-codes.h, headers of the user space API
   of Linux, copied verbatim from the same directory of systemd, which copies
   them from Linux (the notice of input.h says "GPL-2.0", the older SPDX
   identifier of GPL-2.0-only). They are used within the scope of the
   exception of the syscall note.
 * **LGPL-2.0-or-later** (GNU Library General Public License v2.0 or later,
   LGPL-2.0-or-later.txt): the parts of src/shared/utf8.c that are based on
   gutf8.c of GLib, as the original notice in the file says; the file as a
   whole is under LGPL-2.1-or-later.
 * **MIT** (MIT.txt): src/shared/sparse-endian.h and hwdb.d/parse_hwdb.py.
 * **CC0-1.0** (Creative Commons Zero v1.0 Universal, CC0-1.0.txt):
   src/shared/siphash24.c and src/shared/siphash24.h.
 * **Public domain** (murmurhash2-public-domain.txt):
   src/shared/MurmurHash2.c and src/shared/MurmurHash2.h.
 * **BSD-3-Clause** (BSD-3-Clause.txt): hwdb.d/60-autosuspend-chromiumos.hwdb,
   which is generated from gen_autosuspend_rules.py of Chromium OS.
 * hwdb.d/pci.ids may be distributed under the GNU General Public License
   version 2 or later, or under the 3-clause BSD license, as its header says.

## Files without a license notice

The other files have no license notice of their own: the udev rules in rules/
and rule_generator/, the hwdb files in hwdb.d/ except the ones named above, the
other man page sources and the generated man pages, the build system files,
the configuration file src/udev/udev.conf, the documentation, the test scripts
test/udev-test.pl and test/rules-test.sh, and the test data. Like the files of
systemd without a license notice, they are licensed under
**LGPL-2.1-or-later** (see "Main licenses"), with one exception, as in
systemd: the test data without an explicit license, the sysfs tree in
test/sys.tar.xz, is assumed to be non-copyrightable.

The data files from which some of the hwdb files are generated (see
hwdb.d/README) come from public registries and lists: hwdb.d/usb.ids
(linux-usb.org), hwdb.d/sdio.ids (systemd), hwdb.d/ma-*.txt (the IEEE
registration authority), hwdb.d/acpi_id_registry.csv and
hwdb.d/pnp_id_registry.csv (UEFI), and the Bluetooth SIG list of
20-bluetooth-vendor-product.hwdb; apart from pci.ids, they do not state a
license of their own.
