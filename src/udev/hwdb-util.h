/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

struct udev;

/* Compiles the hwdb files, below root if not NULL, into hwdb_bin, which is below root, too.
 * The format of hwdb.bin is configured with hwdb_format= in udev.conf. With strict, parsing
 * errors make it return an error, after the database is written. Shared by 'udevadm hwdb'
 * and systemd-hwdb, like systemd's hwdb-util.c. */
int hwdb_update(struct udev *udev, const char *root, const char *hwdb_bin, bool strict);

/* Prints the properties of modalias from the installed hwdb.bin, below root if not NULL.
 * Returns -ENOENT if there is no hwdb.bin. */
int hwdb_query(struct udev *udev, const char *modalias, const char *root);
