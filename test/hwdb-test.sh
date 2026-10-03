#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Tests how "udevadm hwdb --update" handles directories and files of hwdb files that cannot be read:
# the update fails with exit status 1 and keeps the existing hwdb.bin, for a directory that cannot be
# opened, e.g. one that is a regular file (ENOTDIR) or not readable (EACCES), and for a hwdb file that
# cannot be read. A missing directory, and a dangling symlink to one, are skipped. A relative directory
# is relative to the root directory. Without any hwdb file, hwdb.bin is removed.
#
# The directories are given in $UDEV_HWDB_PATH, below a temporary root directory, where the system
# directories of hwdb files do not exist.
#
# Environment:
#   TEST_UDEVADM  udevadm (default: ../src/udev/udevadm)
#
# Exit status: 0 on success, 1 if a check failed, 77 if udevadm is missing.

set -u

UDEVADM=${TEST_UDEVADM:-../src/udev/udevadm}
if [ ! -x "$UDEVADM" ]; then
        echo "$UDEVADM not found, skipping"
        exit 77
fi

T=$(mktemp -d) || exit 1
trap 'chmod -R u+rwx "$T"; rm -rf "$T"' EXIT
R=$T/root
BIN=$R/hwdb.bin
fail=0

mkdir -p "$R/hw" "$R/hw2" "$R/unreadable" "$R/hw3"
printf 'usb:v1234p5678*\n KEY_A=1\n' > "$R/hw/a.hwdb"
printf 'usb:v1234p5679*\n KEY_B=1\n' > "$R/hw2/b.hwdb"
printf 'usb:v1234p567A*\n KEY_C=1\n' > "$R/unreadable/c.hwdb"
printf 'usb:v1234p567B*\n KEY_D=1\n' > "$R/hw3/d.hwdb"
echo "not a directory" > "$R/file"
ln -s /missing "$R/dangling"

# update EXPECTED_STATUS UDEV_HWDB_PATH DESCRIPTION
update() {
        UDEV_HWDB_PATH=$2 "$UDEVADM" hwdb --update --root="$R" --output=/hwdb.bin > "$T/log" 2>&1
        rc=$?
        if [ "$rc" = "$1" ]; then
                echo "ok: $3 (exit status $rc)"
                return 0
        fi
        echo "FAIL: $3: exit status $rc, expected $1"
        sed 's/^/  /' "$T/log"
        fail=1
        return 1
}

# kept DESCRIPTION: hwdb.bin is still the file of the last successful update
kept() {
        if [ "$(ls -i "$BIN" 2>/dev/null)" = "$INODE" ] && cmp -s "$BIN" "$T/hwdb.bin.good"; then
                echo "ok: $1, hwdb.bin is kept"
        else
                echo "FAIL: $1, hwdb.bin was changed or removed"
                fail=1
        fi
}

# good: remembers hwdb.bin of a successful update (hwdb.bin is read-only, and so is the copy)
good() {
        INODE=$(ls -i "$BIN" 2>/dev/null)
        rm -f "$T/hwdb.bin.good"
        cp "$BIN" "$T/hwdb.bin.good"
}

if update 0 /hw:/hw2 "two directories"; then
        good
        cp "$BIN" "$T/hwdb.bin.first"
fi

update 1 /hw:/hw2:/file "a directory that is a regular file"
kept "a directory that is a regular file"

update 1 /hw:/hw2:/file/sub "a directory below a regular file"
kept "a directory below a regular file"

if [ "$(id -u)" != 0 ]; then
        chmod 000 "$R/unreadable"
        update 1 /hw:/hw2:/unreadable "a directory that cannot be read"
        kept "a directory that cannot be read"
        chmod 755 "$R/unreadable"

        chmod 000 "$R/unreadable/c.hwdb"
        update 1 /hw:/hw2:/unreadable "a hwdb file that cannot be read"
        kept "a hwdb file that cannot be read"
        chmod 644 "$R/unreadable/c.hwdb"
else
        echo "skipped as root: a directory and a file that cannot be read"
fi

update 0 /hw:/hw2:/hw3 "three directories" && good
update 1 /hw:/hw2:/hw3:/file "a directory that is a regular file, after another update"
kept "a directory that is a regular file, after another update"

update 0 /hw:/missing:/hw2:/dangling "a missing directory and a dangling symlink"
if cmp -s "$BIN" "$T/hwdb.bin.first"; then
        echo "ok: a missing directory and a dangling symlink are skipped"
else
        echo "FAIL: a missing directory and a dangling symlink: hwdb.bin differs from the one of /hw:/hw2"
        fail=1
fi

update 0 hw:./hw2 "relative directories"
if cmp -s "$BIN" "$T/hwdb.bin.first"; then
        echo "ok: relative directories are relative to the root directory"
else
        echo "FAIL: relative directories: hwdb.bin differs from the one of /hw:/hw2"
        fail=1
fi

update 0 /missing "no hwdb files"
if [ -e "$BIN" ]; then
        echo "FAIL: no hwdb files: hwdb.bin is not removed"
        fail=1
else
        echo "ok: no hwdb files, hwdb.bin is removed"
fi

exit $fail
