/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>
#include <sys/types.h>

#include "libudev.h"

/* Block device helpers, after src/shared/blockdev-util.c and src/shared/btrfs-util.c of systemd. */

int block_device_is_whole_disk(struct udev_device *dev);
/* The device itself if it is a whole disk, or its parent device if it is a partition: -ENOTBLK if the device
 * is not a block device, -ENODEV if the parent device does not exist (anymore), -ENXIO if it is not a whole
 * disk. The returned device is not referenced. */
int block_device_get_whole_disk(struct udev_device *dev, struct udev_device **ret);
int blockdev_partscan_enabled(struct udev_device *dev);

/* BLKPG: add, remove or resize the partition nr of the whole disk opened as fd; start and size in bytes */
int block_device_add_partition(int fd, int nr, uint64_t start, uint64_t size);
int block_device_remove_partition(int fd, int nr);
int block_device_resize_partition(int fd, int nr, uint64_t start, uint64_t size);
/* The partitions of a whole disk, -ENXIO if dev is a partition */
int partition_enumerator_new(struct udev_device *dev, struct udev_enumerate **ret);
/* The device node of the partition nr of the whole disk with the device node node, e.g. /dev/sda1 or
 * /dev/nvme0n1p1 */
int partition_node_of(const char *node, unsigned nr, char **ret);

int block_get_whole_disk(dev_t d, dev_t *ret);
int block_get_originating(dev_t dt, dev_t *ret);

/* The block device of a btrfs file system on a single device: 1 and the device, 0 and 0 for a
 * multi-device file system, -ENOTTY if fd is not on btrfs. */
int btrfs_get_block_device_fd(int fd, dev_t *ret);
int get_block_device_harder(const char *path, dev_t *ret);

int blockdev_get_root(int level, dev_t *ret);
