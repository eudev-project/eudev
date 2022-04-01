/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

#include "libudev.h"

/* Block device helpers, after src/shared/blockdev-util.c and src/shared/btrfs-util.c of systemd. */

int block_device_is_whole_disk(struct udev_device *dev);
int blockdev_partscan_enabled(struct udev_device *dev);

int block_get_whole_disk(dev_t d, dev_t *ret);
int block_get_originating(dev_t dt, dev_t *ret);

/* The block device of a btrfs file system on a single device: 1 and the device, 0 and 0 for a
 * multi-device file system, -ENOTTY if fd is not on btrfs. */
int btrfs_get_block_device_fd(int fd, dev_t *ret);
int get_block_device_harder(const char *path, dev_t *ret);

int blockdev_get_root(int level, dev_t *ret);
