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
#include "strv.h"
#include "udev-util.h"
#include "util.h"

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

/* eudev: the uevents that were sent for the disk and its partitions while the partition table was re-read, so
 * that reread_partition_table() does not trigger them again after a failure: all of them, when the kernel sent
 * them or they were triggered; otherwise whether a change event for the disk was triggered, and the numbers of
 * the partitions that got a uevent: a triggered change event, or the add event of the kernel for a partition
 * added with BLKPG. A resized partition gets no uevent from the kernel. */
struct uevents_sent {
        bool all;
        bool disk;
        Set *partnos;
};

#ifdef HAVE_BLKID
/* When out of memory, the partition may get a second uevent after a failure, as before. */
static void uevents_sent_add_partition(struct uevents_sent *sent, int nr) {
        if (set_ensure_allocated(&sent->partnos, NULL) < 0 || set_put(sent->partnos, UINT_TO_PTR(nr)) < 0)
                (void) log_oom_debug();
}
#endif

/* eudev: the number of a partition device, from its attribute "partition", which the kernel gives every partition,
 * and no disk, with the number that PARTN= of its uevent file has, which old kernels do not add; or else, e.g. in a
 * directory used as sysfs for tests, from that property. The attribute first, so that the uevent file is not read:
 * on some kernels, a read of it waits while a driver probes or releases the device, see udev_watch_lookup(), and
 * udevd re-reads the partition table in its main process when it cannot fork, or cannot allocate the struct reread
 * of the re-read. */
static int partition_get_number(struct udev_device *partition, unsigned *ret) {
        const char *s;

        s = udev_device_get_sysattr_value(partition, "partition");
        if (!s)
                s = udev_device_get_property_value(partition, "PARTN");
        if (!s)
                return -ENOENT;

        return safe_atou(s, ret);
}

static bool uevents_sent_has_partition(const struct uevents_sent *sent, struct udev_device *partition) {
        unsigned nr;

        if (!sent || partition_get_number(partition, &nr) < 0)
                return false;

        return set_contains(sent->partnos, UINT_TO_PTR(nr));
}

/* appends ", " and name to *list, or only name when *list is NULL */
static int list_append(char **list, const char *name) {
        char *n;

        n = *list ? strjoin(*list, ", ", name, NULL) : strdup(name);
        if (!n)
                return -ENOMEM;

        free(*list);
        *list = n;
        return 0;
}

/* eudev: logs that the partition table could not be re-read (error), and for which of the disk and its partitions
 * (listed by e) 'change' events are triggered instead, see reread_partition_table(): all of them, unless some got
 * a uevent already (sent), which are named then, like the ones that get a 'change' event. Not a warning when the
 * disk or its medium is gone. */
static void log_reread_failed(struct udev_device *dev, struct udev_enumerate *e, const struct uevents_sent *sent,
                              int error) {
        _cleanup_free_ char *lesc1 = NULL, *lesc2 = NULL;
        _cleanup_free_ char *triggered = NULL, *skipped = NULL;
        int level = ERRNO_IS_DEVICE_ABSENT_OR_EMPTY(error) ? LOG_DEBUG : LOG_WARNING;
        struct udev_list_entry *item;
        const char *name;

        name = udev_device_get_sysname(dev);
        if (list_append(sent && sent->disk ? &skipped : &triggered, strna(name)) < 0)
                goto generic;

        udev_list_entry_foreach(item, udev_enumerate_get_list_entry(e)) {
                _cleanup_udev_device_unref_ struct udev_device *d = NULL;

                d = udev_device_new_from_syspath(udev_device_get_udev(dev), udev_list_entry_get_name(item));
                if (!d)
                        continue;

                name = udev_device_get_sysname(d);
                if (list_append(uevents_sent_has_partition(sent, d) ? &skipped : &triggered, strna(name)) < 0)
                        goto generic;
        }

        if (!skipped)
                goto generic;

        if (!triggered) {
                log_device_full_errno(dev, level, error, "Failed to re-read the partition table, %s got a uevent already: %m",
                                      utf8_escape_for_log(skipped, &lesc1));
                return;
        }

        log_device_full_errno(dev, level, error,
                              "Failed to re-read the partition table, triggering 'change' events for %s instead, %s got a uevent already: %m",
                              utf8_escape_for_log(triggered, &lesc1), utf8_escape_for_log(skipped, &lesc2));
        return;

generic:
        log_device_full_errno(dev, level, error,
                              "Failed to re-read the partition table, triggering 'change' events for the disk and its partitions instead: %m");
}

/* sent: the uevents that were sent already and are not triggered again, or NULL; error: when the uevents are
 * triggered as the partition table could not be re-read, its error, which is logged, see log_reread_failed(),
 * otherwise 0 */
static int trigger_partitions(struct udev_device *dev, char * const *args, bool blkrrpart_success,
                              const struct uevents_sent *sent, int error) {
        _cleanup_udev_enumerate_unref_ struct udev_enumerate *e = NULL;
        struct udev_list_entry *item;
        int ret = 0, r;

        assert(dev);

        /* search for partitions */
        r = partition_enumerator_new(dev, &e);
        if (r < 0) {
                if (error < 0)
                        log_device_full_errno(dev, ERRNO_IS_DEVICE_ABSENT_OR_EMPTY(error) ? LOG_DEBUG : LOG_WARNING, error,
                                              "Failed to re-read the partition table, triggering 'change' events for the disk and its partitions instead: %m");
                return log_device_debug_errno(dev, r, "Failed to initialize partition enumerator: %m");
        }

        /* We have partitions and re-read the table, the kernel already sent out a "change"
         * event for the disk, and "remove/add" for all partitions. */
        if (blkrrpart_success && udev_enumerate_get_list_entry(e))
                return 0;

        if (error < 0)
                log_reread_failed(dev, e, sent, error);

        /* We have partitions but re-reading the partition table did not work, synthesize
         * "change" for the disk and all partitions. eudev: except for those that got a uevent already. */
        if (sent && sent->disk)
                log_device_debug(dev, "A 'change' uevent was triggered for the disk already, not triggering it again.");
        else {
                r = device_trigger_with_timestamp(dev, "change", args, /* ret_uuid= */ NULL);
                if (r < 0)
                        RET_GATHER(ret, log_device_debug_errno(dev, r, "Failed to trigger 'change' uevent, proceeding: %m"));
        }

        udev_list_entry_foreach(item, udev_enumerate_get_list_entry(e)) {
                _cleanup_udev_device_unref_ struct udev_device *d = NULL;

                d = udev_device_new_from_syspath(udev_device_get_udev(dev), udev_list_entry_get_name(item));
                if (!d)
                        continue;

                if (uevents_sent_has_partition(sent, d)) {
                        log_device_debug(d, "The partition got a uevent already, not triggering 'change'.");
                        continue;
                }

                r = device_trigger_with_timestamp(d, "change", args, /* ret_uuid= */ NULL);
                if (r < 0)
                        RET_GATHER(ret, log_device_debug_errno(d, r, "Failed to trigger 'change' uevent, proceeding: %m"));
        }

        return ret;
}

static int fallback_ioctl(struct udev_device *d, int fd, RereadPartitionTableFlags flags, char * const *args) {
        int r;

        assert(d);
        assert(fd >= 0);

        r = ioctl(fd, BLKRRPART, 0) < 0 ? -errno : 0;
        if (r < 0)
                log_device_debug_errno(d, r, "Failed to reread partition table via BLKRRPART: %m");
        else
                log_device_debug(d, "Successfully reread partition table via BLKRRPART.");

        if (FLAGS_SET(flags, REREADPT_FORCE_UEVENT))
                RET_GATHER(r, trigger_partitions(d, args, r >= 0, /* sent= */ NULL, /* error= */ 0));

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

/* eudev: *changed is set when a kernel partition device was resized, removed or added, and sent->disk when a
 * change event for the disk was triggered, while systemd uses *changed for both. With REREADPT_FORCE_UEVENT, the
 * syspaths of the resized partitions are added to *resized, see reread_partition_table_full(), and the numbers
 * of the partitions that got a uevent to sent->partnos. */
static int process_partition(
                struct udev_device *d,
                int fd,
                blkid_partition pp,
                Set **partnos,
                RereadPartitionTableFlags flags,
                char * const *args,
                bool *changed,
                struct uevents_sent *sent,
                char ***resized) {
        _cleanup_free_ char *lesc1 = NULL;

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
        assert(sent);
        assert(resized);

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
                return log_device_debug_errno(d, r, "Failed to determine partition node %i for '%s': %m",
                                              nr, utf8_escape_for_log(node, &lesc1));

        r = device_new_from_devname(udev_device_get_udev(d), subnode, &partition);
        if (r < 0) {
                if (r != -ENODEV)
                        return log_device_debug_errno(d, r, "Failed to acquire device '%s': %m",
                                                      utf8_escape_for_log(subnode, &lesc1));
        } else {
                uint64_t start_kernel, size_kernel;

                r = device_get_sysattr_u64(partition, "start", &start_kernel);
                if (r < 0)
                        return log_device_debug_errno(partition, r,
                                                      "Failed to get start of kernel partition device '%s': %m",
                                                      utf8_escape_for_log(subnode, &lesc1));

                r = device_get_sysattr_u64(partition, "size", &size_kernel);
                if (r < 0)
                        return log_device_debug_errno(partition, r,
                                                      "Failed to get size of kernel partition device '%s': %m",
                                                      utf8_escape_for_log(subnode, &lesc1));

                if (start_kernel == (uint64_t) start && size_kernel == (uint64_t) size) {
                        log_device_debug(partition,
                                         "Kernel partition device '%s' already matches partition table, not modifying.",
                                         utf8_escape_for_log(subnode, &lesc1));

                        if (FLAGS_SET(flags, REREADPT_FORCE_UEVENT)) {
                                if (!sent->disk) {
                                        /* Make sure to synthesize a change event on the main device, before we issue the first one on a partition device */
                                        r = device_trigger_with_timestamp(d, "change", args, /* ret_uuid= */ NULL);
                                        if (r < 0)
                                                return log_device_debug_errno(d, r,
                                                                              "Failed to issue 'change' uevent on device '%s': %m",
                                                                              utf8_escape_for_log(node, &lesc1));

                                        log_device_debug(d, "Successfully issued 'change' uevent on device '%s'.",
                                                         utf8_escape_for_log(node, &lesc1));
                                        sent->disk = true;
                                }

                                r = device_trigger_with_timestamp(partition, "change", args, /* ret_uuid= */ NULL);
                                if (r < 0)
                                        return log_device_debug_errno(partition, r,
                                                                      "Failed to issue 'change' uevent on partition '%s': %m",
                                                                      utf8_escape_for_log(subnode, &lesc1));

                                log_device_debug(partition, "Successfully issued 'change' uevent on partition '%s'.",
                                                 utf8_escape_for_log(subnode, &lesc1));
                                uevents_sent_add_partition(sent, nr);
                        }

                        return 0;
                }

                if (start_kernel == (uint64_t) start) {
                        /* If the start offsize doesn't change we can just resize the partition */
                        log_device_debug(partition, "Resizing partition %i...", nr);

                        r = block_device_resize_partition(fd, nr, (uint64_t) start * 512U, (uint64_t) size * 512U);
                        if (r < 0)
                                return log_device_debug_errno(partition, r,
                                                              "Failed to resize kernel partition device '%s' to partition table values: %m",
                                                              utf8_escape_for_log(subnode, &lesc1));

                        log_device_debug(partition,
                                         "Successfully resized kernel partition device '%s' to match partition table.",
                                         utf8_escape_for_log(subnode, &lesc1));
                        *changed = true;

                        /* eudev: the kernel sends no uevent for a resized partition, see
                         * reread_partition_table_full() */
                        if (FLAGS_SET(flags, REREADPT_FORCE_UEVENT) &&
                            strv_extend(resized, udev_device_get_syspath(partition)) < 0)
                                return log_oom_debug();

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
                        return log_device_debug_errno(d, r,
                                                      "Failed to remove kernel partition device '%s' in order to recreate it: %m",
                                                      utf8_escape_for_log(subnode, &lesc1));

                /* And now add it the partition anew */
                log_device_debug(d, "Successfully removed kernel partition device '%s' in order to recreate it.",
                                 utf8_escape_for_log(subnode, &lesc1));
        }

        log_device_debug(d, "Adding partition %i...", nr);

        r = block_device_add_partition(fd, nr, (uint64_t) start * 512U, (uint64_t) size * 512U);
        if (r < 0)
                return log_device_debug_errno(d, r, "Failed to add kernel partition device %i to partition table values: %m", nr);

        log_device_debug(d, "Successfully added kernel partition device %i to match partition table.", nr);
        *changed = true;

        /* eudev: the kernel sent an add event for it */
        if (FLAGS_SET(flags, REREADPT_FORCE_UEVENT))
                uevents_sent_add_partition(sent, nr);
        return 1;
}

static int remove_partitions(struct udev_device *d, int fd, struct udev_enumerate *e, Set *partnos, bool *changed) {
        _cleanup_free_ char *lesc1 = NULL;
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
                unsigned nr;

                partition = udev_device_new_from_syspath(udev_device_get_udev(d), udev_list_entry_get_name(item));
                if (!partition) {
                        log_device_debug(d, "Kernel partition device '%s' disappeared, ignoring.",
                                         utf8_escape_for_log(udev_list_entry_get_name(item), &lesc1));
                        continue;
                }

                /* eudev: the number of the partition from its attribute, see partition_get_number(), and its
                 * device node, which only its uevent file tells, only for the message when it cannot be removed,
                 * rather than the property PARTN and the device node first, like systemd */
                r = partition_get_number(partition, &nr);
                if (r < 0)
                        return log_device_debug_errno(partition, r, "Failed to read partition number: %m");
                if (set_contains(partnos, UINT_TO_PTR(nr))) {
                        log_device_debug(partition, "Found kernel partition device %u in partition table, leaving around.", nr);
                        continue;
                }

                log_device_debug(partition, "Kernel knows partition %u which we didn't find, removing.", nr);

                r = block_device_remove_partition(fd, (int) nr);
                if (r < 0) /* NB: when logging we use the parent device below, after all the partition device ceased existing by now, most likely */
                        RET_GATHER(ret, log_device_debug_errno(d, r,
                                                               "Failed to remove kernel partition device '%s' that vanished from partition table: %m",
                                                               utf8_escape_for_log(
                                                                       strna(udev_device_get_devnode(partition)),
                                                                       &lesc1)));
                else  {
                        log_device_debug(d, "Removed partition %u from kernel.", nr);
                        *changed = true;
                }
        }

        return ret;
}
#endif

/* sent tells which uevents for the disk and its partitions were triggered, or the kernel sent, also when an error
 * is returned. */
static int reread_partition_table_full(struct udev_device *dev, int fd, RereadPartitionTableFlags flags,
                                       char * const *args, void (*locked)(void *userdata), void *userdata,
                                       struct uevents_sent *sent) {
        _cleanup_free_ char *lesc1 = NULL;
        _cleanup_close_ int lock_fd = -1;
        const char *p;
        int r;

        assert(dev);
        assert(fd >= 0);
        assert(sent);

        p = udev_device_get_devnode(dev);
        if (!p)
                return log_device_debug_errno(dev, ENOENT, "Failed to get block device name: %m");

        if (FLAGS_SET(flags, REREADPT_BSD_LOCK)) {
                lock_fd = device_open(dev, O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (lock_fd < 0)
                        return log_device_debug_errno(dev, lock_fd, "Failed to open lock fd for block device '%s': %m",
                                                      utf8_escape_for_log(p, &lesc1));

                if (flock(lock_fd, LOCK_EX|LOCK_NB) < 0) {
                        r = log_device_debug_errno(dev, errno, "Failed to take BSD lock on block device '%s': %m",
                                                   utf8_escape_for_log(p, &lesc1));

                        if (r == -EAGAIN && FLAGS_SET(flags, REREADPT_FORCE_UEVENT)) {
                                log_device_debug(dev,
                                                 "Giving up rereading partition table of '%s'. Triggering change events for the device and its partitions.",
                                                 utf8_escape_for_log(p, &lesc1));
                                (void) trigger_partitions(dev, args, /* blkrrpart_success= */ false, /* sent= */ NULL, /* error= */ 0);
                                sent->all = true;
                        }

                        return r;
                }
        }

        if (locked)
                locked(userdata);

        r = blockdev_partscan_enabled(dev);
        if (r < 0)
                return log_device_debug_errno(dev, r,
                                              "Failed to test if block device '%s' knows partition scanning: %m",
                                              utf8_escape_for_log(p, &lesc1));
        if (r == 0) {
                /* No partition scanning? Generate a uevent at least, if that's requested */
                if (FLAGS_SET(flags, REREADPT_FORCE_UEVENT)) {
                        sent->all = true;
                        r = device_trigger_with_timestamp(dev, "change", args, /* ret_uuid= */ NULL);
                        if (r < 0)
                                return log_device_debug_errno(dev, r, "Failed to trigger 'change' uevent, proceeding: %m");

                        return 0;
                }

                return log_device_debug_errno(dev, ENOTTY, "Block device '%s' does not support partition scanning.",
                                              utf8_escape_for_log(p, &lesc1));
        }

#ifdef HAVE_BLKID
        _cleanup_(blkid_free_probep) blkid_probe b = NULL;
        _cleanup_udev_enumerate_unref_ struct udev_enumerate *e = NULL;
        _cleanup_set_free_ Set *found_partnos = NULL;
        _cleanup_strv_free_ char **resized = NULL;
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
                return log_device_debug_errno(dev, errno_or_else(ENOMEM), "Failed to open block device '%s': %m",
                                              utf8_escape_for_log(p, &lesc1));

        (void) blkid_probe_enable_partitions(b, 1);
        (void) blkid_probe_set_partitions_flags(b, BLKID_PARTS_ENTRY_DETAILS);

        errno = 0;
        r = blkid_do_safeprobe(b);
        if (r == _BLKID_SAFEPROBE_ERROR)
                return log_device_debug_errno(dev, errno_or_else(EIO),
                                              "Unable to probe for partition table of '%s': %m",
                                              utf8_escape_for_log(p, &lesc1));
        if (IN_SET(r, _BLKID_SAFEPROBE_AMBIGUOUS, _BLKID_SAFEPROBE_NOT_FOUND)) {
                log_device_debug(dev, "Didn't find partition table on block device '%s', falling back to BLKRRPART.",
                                 utf8_escape_for_log(p, &lesc1));
                sent->all = true;
                return fallback_ioctl(dev, fd, flags, args);
        }

        assert(r == _BLKID_SAFEPROBE_FOUND);

        (void) blkid_probe_lookup_value(b, "PTTYPE", &pttype, NULL);
        if (!streq_ptr(pttype, "gpt")) {
                log_device_debug(dev, "Didn't find a GPT partition table on '%s', falling back to BLKRRPART.",
                                 utf8_escape_for_log(p, &lesc1));
                sent->all = true;
                return fallback_ioctl(dev, fd, flags, args);
        }

        errno = 0;
        pl = blkid_probe_get_partitions(b);
        if (!pl)
                return log_device_debug_errno(dev, errno_or_else(EIO), "Unable to read partition table of '%s': %m",
                                              utf8_escape_for_log(p, &lesc1));

        errno = 0;
        n_partitions = blkid_partlist_numof_partitions(pl);
        if (n_partitions < 0)
                return log_device_debug_errno(dev, errno_or_else(EIO),
                                              "Unable to acquire number of entries in partition table of '%s': %m",
                                              utf8_escape_for_log(p, &lesc1));

        r = partition_enumerator_new(dev, &e);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to enumerate kernel partition devices: %m");

        log_device_debug(dev, "Updating/adding kernel partition devices...");

        for (int i = 0; i < n_partitions; i++) {
                blkid_partition pp;

                errno = 0;
                pp = blkid_partlist_get_partition(pl, i);
                if (!pp)
                        return log_device_debug_errno(dev, errno_or_else(EIO),
                                                      "Unable to get partition data of partition %i of partition table of '%s': %m",
                                                      i, utf8_escape_for_log(p, &lesc1));

                RET_GATHER(ret, process_partition(dev, fd, pp, &found_partnos, flags, args, &changed, sent, &resized));
        }

        /* Only delete unrecognized partitions if everything else worked */
        if (ret < 0)
                return ret;

        log_device_debug(dev, "Removing old kernel partition devices...");

        r = remove_partitions(dev, fd, e, found_partnos, &changed);
        if (r < 0)
                return r;

        if (FLAGS_SET(flags, REREADPT_FORCE_UEVENT)) {
                char **path;

                sent->all = true;

                /* No change? Then trigger an event manually if we were told to.
                 *
                 * eudev: also after the kernel partition devices were updated with BLKPG. Unlike BLKRRPART,
                 * which sends a change event for the disk, and removes and adds all partitions, BLKPG sends
                 * only remove and add events for the partitions that are removed or added, and no event for
                 * a resized partition, so listeners would not learn that the partition table and the size
                 * of a partition changed. systemd a446e8ff2c sends none of these change events (when the
                 * first partition was updated, it does not even send the change event for the disk before
                 * the change event of an unchanged partition). */
                if (!sent->disk) {
                        r = device_trigger_with_timestamp(dev, "change", args, /* ret_uuid= */ NULL);
                        if (r < 0)
                                return log_device_debug_errno(dev, r,
                                                              "Failed to issue 'change' uevent on device '%s': %m",
                                                              utf8_escape_for_log(p, &lesc1));
                }

                STRV_FOREACH(path, resized) {
                        _cleanup_udev_device_unref_ struct udev_device *partition = NULL;

                        partition = udev_device_new_from_syspath(udev_device_get_udev(dev), *path);
                        if (!partition) {
                                log_device_debug(dev, "Resized kernel partition device '%s' disappeared, ignoring.",
                                                 utf8_escape_for_log(*path, &lesc1));
                                continue;
                        }

                        r = device_trigger_with_timestamp(partition, "change", args, /* ret_uuid= */ NULL);
                        if (r < 0)
                                RET_GATHER(ret, log_device_debug_errno(partition, r, "Failed to issue 'change' uevent on resized partition: %m"));
                        else
                                log_device_debug(partition, "Successfully issued 'change' uevent on resized partition.");
                }

                if (ret < 0)
                        return ret;
        }

        return changed;
#else
        log_device_debug(dev, "We don't have libblkid, falling back to BLKRRPART on '%s'.",
                         utf8_escape_for_log(p, &lesc1));
        sent->all = true;
        return fallback_ioctl(dev, fd, flags, args);
#endif
}

int reread_partition_table(struct udev_device *dev, RereadPartitionTableFlags flags, char * const *args,
                           void (*locked)(void *userdata), void *userdata) {
        _cleanup_strv_free_ char **args_free = NULL;
        _cleanup_close_ int fd = -1;
        struct uevents_sent sent = {};
        int r;

        assert(dev);

        if (!args) {
                r = device_build_default_trigger_args(/* with_timestamp= */ false, &args_free);
                if (r < 0)
                        return r;

                args = args_free;
        }

        fd = device_open(dev, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (fd < 0)
                r = log_debug_errno(fd, "Failed to open block device: %m");
        else
                r = reread_partition_table_full(dev, fd, flags, args, locked, userdata, &sent);

        /* eudev: when the partition table could not be re-read or the kernel's partitions could not be
         * updated, e.g. as a partition that is in use cannot be moved, or the disk cannot be opened or
         * probed, systemd a446e8ff2c triggers no uevent at all and logs the failure at debug level only.
         * Like udevd did before it re-read GPT partition tables in userspace, trigger a change event for
         * the disk and all its partitions then, so that listeners learn that they may have changed, and
         * warn. When the kernel sent the events, or they were triggered already, e.g. when another process
         * holds the lock of the disk, or BLKRRPART failed, do not trigger them again; and only for the
         * disk and the partitions that got no uevent yet, when updating the kernel's partitions failed
         * after some of them got one, e.g. the unchanged partitions, see struct uevents_sent; the warning
         * names them then. Do not warn when the disk or its medium is gone. A partition is told by its
         * number, see partition_get_number(). */
        if (r < 0 && !sent.all && FLAGS_SET(flags, REREADPT_FORCE_UEVENT))
                (void) trigger_partitions(dev, args, /* blkrrpart_success= */ false, &sent, r);

        set_free(sent.partnos);
        return r;
}
