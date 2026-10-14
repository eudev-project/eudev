/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "libudev.h"

typedef enum RereadPartitionTableFlags {
        REREADPT_FORCE_UEVENT = 1 << 0, /* Force a "change" uevent out on partitions we didn't resize/remove/add */
        REREADPT_BSD_LOCK     = 1 << 1, /* Take a BSD lock on the device around the rescan operation */
} RereadPartitionTableFlags;

/* args: the caller arguments of the triggered uevents (KEY VALUE pairs, without timestamps, see
 * device_trigger_with_timestamp()), or NULL for the ones of device_build_default_trigger_args(); locked: when not
 * NULL, called with userdata right before the partition table is read, after the BSD lock was taken with
 * REREADPT_BSD_LOCK; not called when it is not read, e.g. when another process holds the lock */
int reread_partition_table(struct udev_device *dev, RereadPartitionTableFlags flags, char * const *args,
                           void (*locked)(void *userdata), void *userdata);
