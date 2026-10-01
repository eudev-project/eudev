/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef HAVE_BLKID
#include <blkid/blkid.h>
#endif

#include "blockdev-util.h"
#include "libudev-private.h"
#include "log.h"
#include "reread-partition-table.h"
#include "set.h"
#include "udev-util.h"
#include "util.h"

/* After RET_GATHER() of systemd: keeps the first error. */
#define RET_GATHER(ret, err)                    \
        ({                                      \
                int _err = (err);               \
                if ((ret) >= 0 && _err < 0)     \
                        (ret) = _err;           \
                (ret);                          \
        })

#define ERRNO_IS_DEVICE_ABSENT(r) IN_SET(abs(r), ENODEV, ENXIO, ENOENT)

#define log_device_debug(d, fmt, ...) \
        log_debug("%s: " fmt, strna(udev_device_get_sysname(d)), ##__VA_ARGS__)
#define log_device_debug_errno(d, error, fmt, ...) \
        log_debug_errno(error, "%s: " fmt, strna(udev_device_get_sysname(d)), ##__VA_ARGS__)

/* Like sd_device_open() of systemd: opens the device node of the block device, and checks that it is the
 * block device node with the device number of the device. */
static int device_open(struct udev_device *dev, int flags) {
        _cleanup_close_ int fd = -1;
        const char *node;
        struct stat st;

        node = udev_device_get_devnode(dev);
        if (!node)
                return -ENOENT;

        fd = open(node, flags);
        if (fd < 0)
                return -errno;

        if (fstat(fd, &st) < 0)
                return -errno;

        if (!S_ISBLK(st.st_mode) || st.st_rdev != udev_device_get_devnum(dev))
                return -ENXIO;

        return TAKE_FD(fd);
}

static int trigger_partitions(struct udev_device *dev, bool blkrrpart_success) {
        _cleanup_udev_enumerate_unref_ struct udev_enumerate *e = NULL;
        struct udev_list_entry *item;
        int ret = 0, r;

        assert(dev);

        /* search for partitions */
        r = partition_enumerator_new(dev, &e);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to initialize partition enumerator: %m");

        /* We have partitions and re-read the table, the kernel already sent out a "change"
         * event for the disk, and "remove/add" for all partitions. */
        if (blkrrpart_success && udev_enumerate_get_list_entry(e))
                return 0;

        /* We have partitions but re-reading the partition table did not work, synthesize
         * "change" for the disk and all partitions. */
        r = device_trigger(dev, "change", NULL);
        if (r < 0)
                RET_GATHER(ret, log_device_debug_errno(dev, r, "Failed to trigger 'change' uevent, proceeding: %m"));

        udev_list_entry_foreach(item, udev_enumerate_get_list_entry(e)) {
                _cleanup_udev_device_unref_ struct udev_device *d = NULL;

                d = udev_device_new_from_syspath(udev_device_get_udev(dev), udev_list_entry_get_name(item));
                if (!d)
                        continue;

                r = device_trigger(d, "change", NULL);
                if (r < 0)
                        RET_GATHER(ret, log_device_debug_errno(d, r, "Failed to trigger 'change' uevent, proceeding: %m"));
        }

        return ret;
}

static int fallback_ioctl(struct udev_device *d, int fd, RereadPartitionTableFlags flags) {
        int r;

        assert(d);
        assert(fd >= 0);

        r = ioctl(fd, BLKRRPART, 0) < 0 ? -errno : 0;
        if (r < 0)
                log_device_debug_errno(d, r, "Failed to reread partition table via BLKRRPART: %m");
        else
                log_device_debug(d, "Successfully reread partition table via BLKRRPART.");

        if (FLAGS_SET(flags, REREADPT_FORCE_UEVENT))
                RET_GATHER(r, trigger_partitions(d, r >= 0));

        return r;
}

#ifdef HAVE_BLKID
/* Symbolic names for the return values of blkid_do_safeprobe(), as in blkid-util.h of systemd */
enum {
        _BLKID_SAFEPROBE_FOUND     =  0,
        _BLKID_SAFEPROBE_NOT_FOUND =  1,
        _BLKID_SAFEPROBE_AMBIGUOUS = -2,
        _BLKID_SAFEPROBE_ERROR     = -1,
};

DEFINE_TRIVIAL_CLEANUP_FUNC(blkid_probe, blkid_free_probe);

/* Like sd_device_new_from_devname() of systemd for a block device node, -ENODEV if it does not exist. */
static int device_new_from_devname(struct udev *udev, const char *devname, struct udev_device **ret) {
        struct udev_device *dev;
        struct stat st;

        if (stat(devname, &st) < 0)
                return ERRNO_IS_DEVICE_ABSENT(errno) ? -ENODEV : -errno;

        if (!S_ISBLK(st.st_mode))
                return -ENOTBLK;

        dev = udev_device_new_from_devnum(udev, 'b', st.st_rdev);
        if (!dev)
                return -ENODEV;

        *ret = dev;
        return 0;
}

static int process_partition(
                struct udev_device *d,
                int fd,
                blkid_partition pp,
                Set **partnos,
                RereadPartitionTableFlags flags,
                bool *changed) {

        _cleanup_udev_device_unref_ struct udev_device *partition = NULL;
        _cleanup_free_ char *subnode = NULL;
        blkid_loff_t start, size;
        const char *node;
        int nr, r;

        assert(d);
        assert(fd >= 0);
        assert(pp);
        assert(partnos);
        assert(changed);

        node = udev_device_get_devnode(d);
        if (!node)
                return log_device_debug_errno(d, ENOENT, "Failed to acquire device node path: %m");

        errno = 0;
        nr = blkid_partition_get_partno(pp);
        if (nr < 0)
                return log_debug_errno(errno_or_else(EIO), "Failed to read partition number of partition: %m");

        log_device_debug(d, "Processing partition %i...", nr);

        errno = 0;
        start = blkid_partition_get_start(pp);
        if (start < 0)
                return log_debug_errno(errno_or_else(EIO), "Failed to read partition start offset of partition %i: %m", nr);
        assert((uint64_t) start < UINT64_MAX / 512U);

        errno = 0;
        size = blkid_partition_get_size(pp);
        if (size < 0)
                return log_debug_errno(errno_or_else(EIO), "Failed to read partition size of partition %i: %m", nr);
        assert((uint64_t) size < UINT64_MAX / 512U);

        r = set_ensure_allocated(partnos, NULL);
        if (r >= 0)
                r = set_put(*partnos, UINT_TO_PTR(nr));
        if (r < 0)
                return log_oom_debug();

        r = partition_node_of(node, nr, &subnode);
        if (r < 0)
                return log_device_debug_errno(d, r, "Failed to determine partition node %i for '%s': %m", nr, node);

        r = device_new_from_devname(udev_device_get_udev(d), subnode, &partition);
        if (r < 0) {
                if (r != -ENODEV)
                        return log_device_debug_errno(d, r, "Failed to acquire device '%s': %m", subnode);
        } else {
                uint64_t start_kernel, size_kernel;

                r = device_get_sysattr_u64(partition, "start", &start_kernel);
                if (r < 0)
                        return log_device_debug_errno(partition, r, "Failed to get start of kernel partition device '%s': %m", subnode);

                r = device_get_sysattr_u64(partition, "size", &size_kernel);
                if (r < 0)
                        return log_device_debug_errno(partition, r, "Failed to get size of kernel partition device '%s': %m", subnode);

                if (start_kernel == (uint64_t) start && size_kernel == (uint64_t) size) {
                        log_device_debug(partition, "Kernel partition device '%s' already matches partition table, not modifying.", subnode);

                        if (FLAGS_SET(flags, REREADPT_FORCE_UEVENT)) {
                                if (!*changed) {
                                        /* Make sure to synthesize a change event on the main device, before we issue the first one on a partition device */
                                        r = device_trigger(d, "change", NULL);
                                        if (r < 0)
                                                return log_device_debug_errno(d, r, "Failed to issue 'change' uevent on device '%s': %m", node);

                                        log_device_debug(d, "Successfully issued 'change' uevent on device '%s'.", node);
                                        *changed = true;
                                }

                                r = device_trigger(partition, "change", NULL);
                                if (r < 0)
                                        return log_device_debug_errno(partition, r, "Failed to issue 'change' uevent on partition '%s': %m", subnode);

                                log_device_debug(partition, "Successfully issued 'change' uevent on partition '%s'.", subnode);
                        }

                        return 0;
                }

                if (start_kernel == (uint64_t) start) {
                        /* If the start offsize doesn't change we can just resize the partition */
                        log_device_debug(partition, "Resizing partition %i...", nr);

                        r = block_device_resize_partition(fd, nr, (uint64_t) start * 512U, (uint64_t) size * 512U);
                        if (r < 0)
                                return log_device_debug_errno(partition, r, "Failed to resize kernel partition device '%s' to partition table values: %m", subnode);

                        log_device_debug(partition, "Successfully resized kernel partition device '%s' to match partition table.", subnode);
                        *changed = true;
                        return 1;
                }

                /* If the start offset changed we need to remove and recreate the partition */
                log_device_debug(partition, "Removing and recreating partition %i...", nr);

                /* NB: when logging below we use the parent device now, after all the partition device ceased
                 * existing by now, most likely. Let's explicitly get rid of the obsolete device object now,
                 * just to make a point. */
                partition = udev_device_unref(partition);

                r = block_device_remove_partition(fd, nr);
                if (r < 0)
                        return log_device_debug_errno(d, r, "Failed to remove kernel partition device '%s' in order to recreate it: %m", subnode);

                /* And now add it the partition anew */
                log_device_debug(d, "Successfully removed kernel partition device '%s' in order to recreate it.", subnode);
        }

        log_device_debug(d, "Adding partition %i...", nr);

        r = block_device_add_partition(fd, nr, (uint64_t) start * 512U, (uint64_t) size * 512U);
        if (r < 0)
                return log_device_debug_errno(d, r, "Failed to add kernel partition device %i to partition table values: %m", nr);

        log_device_debug(d, "Successfully added kernel partition device %i to match partition table.", nr);
        *changed = true;
        return 1;
}

static int remove_partitions(struct udev_device *d, int fd, struct udev_enumerate *e, Set *partnos, bool *changed) {
        struct udev_list_entry *item;
        int ret = 0, r;

        assert(d);
        assert(fd >= 0);
        assert(e);
        assert(changed);

        /* Removes all partitions of the specified device that we didn't find in the partition table (as
         * listed in the specified Set object) */

        udev_list_entry_foreach(item, udev_enumerate_get_list_entry(e)) {
                _cleanup_udev_device_unref_ struct udev_device *partition = NULL;
                const char *devname, *s;
                unsigned nr;

                partition = udev_device_new_from_syspath(udev_device_get_udev(d), udev_list_entry_get_name(item));
                if (!partition) {
                        log_device_debug(d, "Kernel partition device '%s' disappeared, ignoring.", udev_list_entry_get_name(item));
                        continue;
                }

                devname = udev_device_get_devnode(partition);
                if (!devname)
                        return log_device_debug_errno(partition, ENOENT, "Failed to get name of partition: %m");

                s = udev_device_get_property_value(partition, "PARTN");
                r = s ? safe_atou(s, &nr) : -ENOENT;
                if (r < 0)
                        return log_device_debug_errno(partition, r, "Failed to read partition number property: %m");
                if (set_contains(partnos, UINT_TO_PTR(nr))) {
                        log_device_debug(partition, "Found kernel partition device %u in partition table, leaving around.", nr);
                        continue;
                }

                log_device_debug(partition, "Kernel knows partition %u which we didn't find, removing.", nr);

                r = block_device_remove_partition(fd, (int) nr);
                if (r < 0) /* NB: when logging we use the parent device below, after all the partition device ceased existing by now, most likely */
                        RET_GATHER(ret, log_device_debug_errno(d, r, "Failed to remove kernel partition device '%s' that vanished from partition table: %m", devname));
                else  {
                        log_device_debug(d, "Removed partition %u from kernel.", nr);
                        *changed = true;
                }
        }

        return ret;
}
#endif

/* *ret_triggered is set when uevents for the disk and its partitions were triggered, or the kernel sent them,
 * also when an error is returned. */
static int reread_partition_table_full(struct udev_device *dev, int fd, RereadPartitionTableFlags flags,
                                       bool *ret_triggered) {
        _cleanup_close_ int lock_fd = -1;
        const char *p;
        int r;

        assert(dev);
        assert(fd >= 0);
        assert(ret_triggered);

        p = udev_device_get_devnode(dev);
        if (!p)
                return log_device_debug_errno(dev, ENOENT, "Failed to get block device name: %m");

        if (FLAGS_SET(flags, REREADPT_BSD_LOCK)) {
                lock_fd = device_open(dev, O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (lock_fd < 0)
                        return log_device_debug_errno(dev, lock_fd, "Failed to open lock fd for block device '%s': %m", p);

                if (flock(lock_fd, LOCK_EX|LOCK_NB) < 0) {
                        r = log_device_debug_errno(dev, errno, "Failed to take BSD lock on block device '%s': %m", p);

                        if (r == -EAGAIN && FLAGS_SET(flags, REREADPT_FORCE_UEVENT)) {
                                log_device_debug(dev, "Giving up rereading partition table of '%s'. Triggering change events for the device and its partitions.", p);
                                (void) trigger_partitions(dev, /* blkrrpart_success= */ false);
                                *ret_triggered = true;
                        }

                        return r;
                }
        }

        r = blockdev_partscan_enabled(dev);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to test if block device '%s' knows partition scanning: %m", p);
        if (r == 0) {
                /* No partition scanning? Generate a uevent at least, if that's requested */
                if (FLAGS_SET(flags, REREADPT_FORCE_UEVENT)) {
                        *ret_triggered = true;
                        r = device_trigger(dev, "change", NULL);
                        if (r < 0)
                                return log_device_debug_errno(dev, r, "Failed to trigger 'change' uevent, proceeding: %m");

                        return 0;
                }

                return log_device_debug_errno(dev, ENOTTY, "Block device '%s' does not support partition scanning.", p);
        }

#ifdef HAVE_BLKID
        _cleanup_(blkid_free_probep) blkid_probe b = NULL;
        _cleanup_udev_enumerate_unref_ struct udev_enumerate *e = NULL;
        _cleanup_set_free_ Set *found_partnos = NULL;
        const char *pttype = NULL;
        blkid_partlist pl;
        bool changed = false;
        int n_partitions, ret = 0;

        b = blkid_new_probe();
        if (!b)
                return log_oom_debug();

        errno = 0;
        r = blkid_probe_set_device(b, fd, /* off= */ 0, /* size= */ 0);
        if (r != 0)
                return log_device_debug_errno(dev, errno_or_else(ENOMEM), "Failed to open block device '%s': %m", p);

        (void) blkid_probe_enable_partitions(b, 1);
        (void) blkid_probe_set_partitions_flags(b, BLKID_PARTS_ENTRY_DETAILS);

        errno = 0;
        r = blkid_do_safeprobe(b);
        if (r == _BLKID_SAFEPROBE_ERROR)
                return log_device_debug_errno(dev, errno_or_else(EIO), "Unable to probe for partition table of '%s': %m", p);
        if (IN_SET(r, _BLKID_SAFEPROBE_AMBIGUOUS, _BLKID_SAFEPROBE_NOT_FOUND)) {
                log_device_debug(dev, "Didn't find partition table on block device '%s', falling back to BLKRRPART.", p);
                *ret_triggered = true;
                return fallback_ioctl(dev, fd, flags);
        }

        assert(r == _BLKID_SAFEPROBE_FOUND);

        (void) blkid_probe_lookup_value(b, "PTTYPE", &pttype, NULL);
        if (!streq_ptr(pttype, "gpt")) {
                log_device_debug(dev, "Didn't find a GPT partition table on '%s', falling back to BLKRRPART.", p);
                *ret_triggered = true;
                return fallback_ioctl(dev, fd, flags);
        }

        errno = 0;
        pl = blkid_probe_get_partitions(b);
        if (!pl)
                return log_device_debug_errno(dev, errno_or_else(EIO), "Unable to read partition table of '%s': %m", p);

        errno = 0;
        n_partitions = blkid_partlist_numof_partitions(pl);
        if (n_partitions < 0)
                return log_device_debug_errno(dev, errno_or_else(EIO), "Unable to acquire number of entries in partition table of '%s': %m", p);

        r = partition_enumerator_new(dev, &e);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to enumerate kernel partition devices: %m");

        log_device_debug(dev, "Updating/adding kernel partition devices...");

        for (int i = 0; i < n_partitions; i++) {
                blkid_partition pp;

                errno = 0;
                pp = blkid_partlist_get_partition(pl, i);
                if (!pp)
                        return log_device_debug_errno(dev, errno_or_else(EIO), "Unable to get partition data of partition %i of partition table of '%s': %m", i, p);

                RET_GATHER(ret, process_partition(dev, fd, pp, &found_partnos, flags, &changed));
        }

        /* Only delete unrecognized partitions if everything else worked */
        if (ret < 0)
                return ret;

        log_device_debug(dev, "Removing old kernel partition devices...");

        r = remove_partitions(dev, fd, e, found_partnos, &changed);
        if (r < 0)
                return r;

        if (changed)
                return 1;

        if (FLAGS_SET(flags, REREADPT_FORCE_UEVENT)) {
                /* No change? Then trigger an event manually if we were told to */
                *ret_triggered = true;
                r = device_trigger(dev, "change", NULL);
                if (r < 0)
                        return log_device_debug_errno(dev, r, "Failed to issue 'change' uevent on device '%s': %m", p);
        }

        return 0;
#else
        log_device_debug(dev, "We don't have libblkid, falling back to BLKRRPART on '%s'.", p);
        *ret_triggered = true;
        return fallback_ioctl(dev, fd, flags);
#endif
}

int reread_partition_table(struct udev_device *dev, RereadPartitionTableFlags flags) {
        _cleanup_close_ int fd = -1;
        bool triggered = false;
        int r;

        assert(dev);

        fd = device_open(dev, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (fd < 0)
                r = log_debug_errno(fd, "Failed to open block device: %m");
        else
                r = reread_partition_table_full(dev, fd, flags, &triggered);

        /* eudev: when the partition table could not be re-read or the kernel's partitions could not be
         * updated, e.g. as a partition that is in use cannot be moved, or the disk cannot be opened or
         * probed, systemd a446e8ff2c triggers no uevent at all and logs the failure at debug level only.
         * Like udevd did before it re-read GPT partition tables in userspace, trigger a change event for
         * the disk and all its partitions then, so that listeners learn that they may have changed, and
         * warn. When the kernel sent the events, or they were triggered already, e.g. when another process
         * holds the lock of the disk, or BLKRRPART failed, do not trigger them again. Do not warn when the
         * disk or its medium is gone. */
        if (r < 0 && !triggered && FLAGS_SET(flags, REREADPT_FORCE_UEVENT)) {
                log_full_errno(ERRNO_IS_DEVICE_ABSENT(r) || r == -ENOMEDIUM ? LOG_DEBUG : LOG_WARNING, r,
                               "%s: Failed to re-read the partition table, triggering 'change' events for the disk and its partitions instead: %m",
                               strna(udev_device_get_sysname(dev)));
                (void) trigger_partitions(dev, /* blkrrpart_success= */ false);
        }

        return r;
}
