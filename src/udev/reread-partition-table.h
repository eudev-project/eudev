/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "libudev.h"

typedef enum RereadPartitionTableFlags {
        REREADPT_FORCE_UEVENT = 1 << 0, /* Force a "change" uevent out on partitions we didn't resize/remove/add */
        REREADPT_BSD_LOCK     = 1 << 1, /* Take a BSD lock on the device around the rescan operation */
} RereadPartitionTableFlags;

/* args: the caller arguments of the triggered uevents (KEY VALUE pairs, without timestamps, see
 * device_trigger_with_timestamp()), or NULL for the ones of device_build_default_trigger_args() */
int reread_partition_table(struct udev_device *dev, RereadPartitionTableFlags flags, char * const *args);
