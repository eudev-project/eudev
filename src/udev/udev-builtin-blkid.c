/*
 * probe disks for filesystems and partitions
 *
 * Copyright (C) 2011 Kay Sievers <kay@vrfy.org>
 * Copyright (C) 2011 Karel Zak <kzak@redhat.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/loop.h>
#include <blkid/blkid.h>

#include "blockdev-util.h"
#include "efivars.h"
#include "gpt.h"
#include "id128-util.h"
#include "udev.h"
#include "utf8.h"

DEFINE_TRIVIAL_CLEANUP_FUNC(blkid_probe, blkid_free_probe);
#define _cleanup_blkid_free_probe_ _cleanup_(blkid_free_probep)

static void print_property(struct udev_device *dev, enum udev_event_mode mode, const char *name, const char *value) {
        char s[256];

        s[0] = '\0';

        if (streq(name, "TYPE")) {
                udev_builtin_add_property(dev, mode, "ID_FS_TYPE", value);

        } else if (streq(name, "USAGE")) {
                udev_builtin_add_property(dev, mode, "ID_FS_USAGE", value);

        } else if (streq(name, "VERSION")) {
                udev_builtin_add_property(dev, mode, "ID_FS_VERSION", value);

        } else if (streq(name, "UUID")) {
                blkid_safe_string(value, s, sizeof(s));
                udev_builtin_add_property(dev, mode, "ID_FS_UUID", s);
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(dev, mode, "ID_FS_UUID_ENC", s);

        } else if (streq(name, "UUID_SUB")) {
                blkid_safe_string(value, s, sizeof(s));
                udev_builtin_add_property(dev, mode, "ID_FS_UUID_SUB", s);
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(dev, mode, "ID_FS_UUID_SUB_ENC", s);

        } else if (streq(name, "LABEL")) {
                blkid_safe_string(value, s, sizeof(s));
                udev_builtin_add_property(dev, mode, "ID_FS_LABEL", s);
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(dev, mode, "ID_FS_LABEL_ENC", s);

        } else if (streq(name, "FSSIZE") || streq(name, "FSLASTBLOCK") || streq(name, "FSBLOCKSIZE")) {
                strscpyl(s, sizeof(s), "ID_FS_", name + 2, NULL);
                udev_builtin_add_property(dev, mode, s, value);

        } else if (streq(name, "PTTYPE")) {
                udev_builtin_add_property(dev, mode, "ID_PART_TABLE_TYPE", value);

        } else if (streq(name, "PTUUID")) {
                udev_builtin_add_property(dev, mode, "ID_PART_TABLE_UUID", value);

        } else if (streq(name, "PART_ENTRY_NAME")) {
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(dev, mode, "ID_PART_ENTRY_NAME", s);

        } else if (streq(name, "PART_ENTRY_TYPE")) {
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(dev, mode, "ID_PART_ENTRY_TYPE", s);

        } else if (startswith(name, "PART_ENTRY_")) {
                strscpyl(s, sizeof(s), "ID_", name, NULL);
                udev_builtin_add_property(dev, mode, s, value);

        } else if (streq(name, "SYSTEM_ID")) {
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(dev, mode, "ID_FS_SYSTEM_ID", s);

        } else if (streq(name, "PUBLISHER_ID")) {
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(dev, mode, "ID_FS_PUBLISHER_ID", s);

        } else if (streq(name, "APPLICATION_ID")) {
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(dev, mode, "ID_FS_APPLICATION_ID", s);

        } else if (streq(name, "BOOT_SYSTEM_ID")) {
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(dev, mode, "ID_FS_BOOT_SYSTEM_ID", s);

        } else if (streq(name, "VOLUME_ID")) {
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(dev, mode, "ID_FS_VOLUME_ID", s);

        } else if (streq(name, "LOGICAL_VOLUME_ID")) {
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(dev, mode, "ID_FS_LOGICAL_VOLUME_ID", s);

        } else if (streq(name, "VOLUME_SET_ID")) {
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(dev, mode, "ID_FS_VOLUME_SET_ID", s);

        } else if (streq(name, "DATA_PREPARER_ID")) {
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(dev, mode, "ID_FS_DATA_PREPARER_ID", s);
        }
}

#ifdef GPT_ROOT_NATIVE
static int blkid_partition_get_uuid_id128(blkid_partition p, id128_t *ret) {
        const char *s;

        assert(p);

        s = blkid_partition_get_uuid(p);
        if (isempty(s))
                return -ENXIO;

        return id128_from_string(s, ret);
}

static int blkid_partition_get_type_id128(blkid_partition p, id128_t *ret) {
        const char *s;

        assert(p);

        s = blkid_partition_get_type_string(p);
        if (isempty(s))
                return -ENXIO;

        return id128_from_string(s, ret);
}
#endif

static int find_gpt_root(struct udev_device *dev, blkid_probe pr, const char *loop_backing_fname, enum udev_event_mode mode) {

#ifdef GPT_ROOT_NATIVE
        _cleanup_free_ char *root_label = NULL;
        id128_t esp_or_xbootldr = ID128_NULL, root_id = ID128_NULL;
        bool need_esp_or_xbootldr, found_esp_or_xbootldr = false;
        dev_t root_devno = 0;
        const char *devnode;
        blkid_partlist pl;
        int r;

        assert(dev);
        assert(pr);

        /* In the initrd: Iterate through the partitions on this disk, and see if the UEFI ESP or XBOOTLDR
         * partition we booted from is on it. If so, find the newest root partition, and add a property
         * indicating its partition UUID. We also do this if we are dealing with a loopback block device
         * whose "backing filename" field is set to the string "root". In the latter case we do not search
         * for ESP or XBOOTLDR.
         *
         * After the initrd→host transition: look at the current block device mounted at / and set the same
         * properties to its whole block device. */

        devnode = udev_device_get_devnode(dev);
        if (!devnode)
                return log_debug_errno(ENODEV, "%s: Failed to get device node.", udev_device_get_sysname(dev));

        r = block_device_is_whole_disk(dev);
        if (r < 0)
                return log_debug_errno(r, "Unable to determine if device '%s' is a whole-block device: %m", devnode);
        if (r == 0) {
                log_debug("Invoked on device '%s' which is not a whole-disk block device, ignoring.", devnode);
                return 0;
        }

        r = blockdev_partscan_enabled(dev);
        if (r < 0)
                return log_debug_errno(r, "Failed to determine if block device '%s' supports partitions: %m", devnode);
        if (r == 0) {
                log_debug("Invoked on block device '%s' that lacks partition scanning, ignoring.", devnode);
                return 0;
        }

        if (in_initrd()) {
                /* In the initrd look at the boot loader provided data (and loopback backing fname) to find
                 * our *future* root */

                r = efi_loader_get_device_part_uuid(&esp_or_xbootldr);
                if (r < 0) {
                        if (r != -ENOENT && !IN_SET(r, -EOPNOTSUPP, -ENOTTY, -ENOSYS))
                                return log_debug_errno(r, "Unable to determine loader partition UUID: %m");

                        log_debug("No loader partition UUID EFI variable set, not using partition data to search for default root block device.");

                        /* NB: if an ESP/xbootldr field is set, we always use that. We do this in order to guarantee
                         * systematic behaviour. */
                        if (!streq_ptr(loop_backing_fname, "rootdisk") && !streq_ptr(loop_backing_fname, "rootdisk.raw")) {
                                log_debug("Device is not a loopback block device with reference string 'root', not considering block device as default root block device.");
                                return 0;
                        }

                        /* OK, we have now sufficiently identified this device as the right root "whole" device,
                         * hence no need to bother with searching for ESP/XBOOTLDR */
                        need_esp_or_xbootldr = false;
                } else
                        /* We now know the ESP/xbootldr UUID, but we cannot be sure yet it's on this block
                         * device, hence look for it among partitions now */
                        need_esp_or_xbootldr = true;
        } else {
                dev_t whole_devno;

                /* On the main system look at the *current* root instead */

                r = blockdev_get_root(LOG_DEBUG, &root_devno);
                if (r < 0) {
                        log_debug_errno(r, "Unable to determine current root block device, skipping gpt-auto probing: %m");
                        return 0;
                }
                if (r == 0) {
                        log_debug("Root block device not backed by a (single) whole block device, skipping gpt-auto probing.");
                        return 0;
                }

                r = block_get_whole_disk(root_devno, &whole_devno);
                if (r < 0)
                        return log_debug_errno(r, "Failed to find whole block device for root block device: %m");

                if (whole_devno != udev_device_get_devnum(dev)) {
                        log_debug("This device is not the current root block device.");
                        return 0;
                }

                /* We don't need to check ESP/XBOOTLDR UUID, we *know* what our root disk is */
                need_esp_or_xbootldr = false;
        }

        errno = 0;
        pl = blkid_probe_get_partitions(pr);
        if (!pl)
                return log_debug_errno(errno_or_else(ENOMEM), "Failed to probe partitions: %m");

        if (root_devno != 0) {
                blkid_partition root_partition;

                /* If we already know the root partition, let's verify its type ID and then directly query
                 * its ID */

                root_partition = blkid_partlist_devno_to_partition(pl, root_devno);
                if (root_partition) {
                        id128_t type;

                        r = blkid_partition_get_type_id128(root_partition, &type);
                        if (r < 0)
                                log_debug_errno(r, "Failed to get root partition type UUID, ignoring: %m");
                        else if (id128_equal(type, GPT_ROOT_NATIVE)) {
                                r = blkid_partition_get_uuid_id128(root_partition, &root_id);
                                if (r < 0)
                                        log_debug_errno(r, "Failed to get partition UUID, ignoring: %m");
                        }
                }
        } else {
                int i, nvals;

                /* We do not know the root partition, let's search for it. */

                nvals = blkid_partlist_numof_partitions(pl);
                for (i = 0; i < nvals; i++) {
                        blkid_partition pp;
                        const char *label;
                        id128_t type, id;

                        pp = blkid_partlist_get_partition(pl, i);
                        if (!pp)
                                continue;

                        r = blkid_partition_get_uuid_id128(pp, &id);
                        if (r < 0) {
                                log_debug_errno(r, "Failed to get partition UUID, ignoring: %m");
                                continue;
                        }

                        r = blkid_partition_get_type_id128(pp, &type);
                        if (r < 0) {
                                log_debug_errno(r, "Failed to get partition type UUID, ignoring: %m");
                                continue;
                        }

                        label = blkid_partition_get_name(pp); /* returns NULL if empty */

                        if (need_esp_or_xbootldr && id128_in_set(type, GPT_ESP, GPT_XBOOTLDR)) {

                                /* We found an ESP or XBOOTLDR, let's see if it matches the ESP/XBOOTLDR we booted from. */
                                if (id128_equal(id, esp_or_xbootldr))
                                        found_esp_or_xbootldr = true;

                        } else if (id128_equal(type, GPT_ROOT_NATIVE)) {
                                unsigned long long flags;

                                flags = blkid_partition_get_flags(pp);
                                if (flags & GPT_FLAG_NO_AUTO)
                                        continue;

                                /* systemd-sysupdate expects empty partitions to be marked with an "_empty" label, hence ignore them here. */
                                if (streq_ptr(label, "_empty"))
                                        continue;

                                /* We found a suitable root partition, let's remember the first one, or the one with
                                 * the newest version, as determined by comparing the partition labels. */

                                if (id128_is_null(root_id) || strverscmp_improved(label, root_label) > 0) {
                                        root_id = id;

                                        free(root_label);
                                        root_label = NULL;
                                        if (label) {
                                                root_label = strdup(label);
                                                if (!root_label)
                                                        return log_oom();
                                        }
                                }
                        }
                }
        }

        if (!need_esp_or_xbootldr || found_esp_or_xbootldr) {
                /* We found the ESP/XBOOTLDR on this disk (or we didn't need it) */
                udev_builtin_add_property(dev, mode, "ID_PART_GPT_AUTO_ROOT_DISK", "1");

                /* We found a root partition, nice! Let's export its UUID. */
                if (!id128_is_null(root_id)) {
                        char s[ID128_UUID_STRING_MAX];

                        udev_builtin_add_property(dev, mode, "ID_PART_GPT_AUTO_ROOT_UUID", id128_to_uuid_string(root_id, s));
                }
        }
#endif

        return 0;
}

static int probe_superblocks(blkid_probe pr) {
        struct stat st;
        int rc;

        if (fstat(blkid_probe_get_fd(pr), &st))
                return -errno;

        blkid_probe_enable_partitions(pr, 1);

        if (!S_ISCHR(st.st_mode) &&
            blkid_probe_get_size(pr) <= 1024 * 1440 &&
            blkid_probe_is_wholedisk(pr)) {
                /*
                 * check if the small disk is partitioned, if yes then
                 * don't probe for filesystems.
                 */
                blkid_probe_enable_superblocks(pr, 0);

                errno = 0;
                rc = blkid_do_fullprobe(pr);
                if (rc < 0)
                        return errno_or_else(EIO);

                if (blkid_probe_lookup_value(pr, "PTTYPE", NULL, NULL) == 0)
                        return 0;        /* partition table detected */
        }

        blkid_probe_set_partitions_flags(pr, BLKID_PARTS_ENTRY_DETAILS);
        blkid_probe_enable_superblocks(pr, 1);

        errno = 0;
        rc = blkid_do_safeprobe(pr);
        if (rc < 0)
                return errno_or_else(EIO);

        return rc; /* 0 = success, 1 = nothing found */
}

static int read_loopback_backing_inode(
                struct udev_device *dev,
                int fd,
                dev_t *ret_devno,
                ino_t *ret_inode,
                char **ret_fname) {

        _cleanup_free_ char *fn = NULL;
        struct loop_info64 info;
        const char *name;

        assert(dev);
        assert(fd >= 0);
        assert(ret_devno);
        assert(ret_inode);
        assert(ret_fname);

        /* Retrieves various fields of the current loopback device backing file, so that we can ultimately
         * use it to create stable symlinks to loopback block devices, based on what they are backed by. We
         * pick up inode/device as well as file name field. Note that we pick up the "lo_file_name" field
         * here, which is an arbitrary free-form string provided by userspace. We do not return the sysfs
         * attribute loop/backing_file here, because that is directly accessible from udev rules anyway. And
         * sometimes, depending on context, it's a good thing to return the string userspace can freely pick
         * over the string automatically generated by the kernel. */

        name = udev_device_get_sysname(dev);
        if (!name)
                return -ENODEV;

        if (!startswith(name, "loop"))
                goto notloop;

        if (ioctl(fd, LOOP_GET_STATUS64, &info) < 0) {
                if (IN_SET(errno, ENOTTY, EOPNOTSUPP, ENOSYS))
                        goto notloop;

                return -errno;
        }

        if (isempty((char*) info.lo_file_name) ||
            strnlen((char*) info.lo_file_name, sizeof(info.lo_file_name)-1) == sizeof(info.lo_file_name)-1)
                /* Don't pick up file name if it is unset or possibly truncated. (Note: the kernel silently
                 * truncates the string passed from userspace by LOOP_SET_STATUS64 ioctl. See
                 * loop_set_status_from_info() in drivers/block/loop.c. Hence, we can't really know the file
                 * name is truncated if it uses sizeof(info.lo_file_name)-1 as length; it could also mean the
                 * string is just that long and wasn't truncated — but the fact is simply that we cannot know
                 * in that case if it was truncated or not. Thus, we assume the worst and suppress — at least
                 * for now. For shorter strings we know for sure it wasn't truncated, hence that's always
                 * safe.) */
                fn = NULL;
        else {
                fn = strndup((char*) info.lo_file_name, sizeof(info.lo_file_name));
                if (!fn)
                        return -ENOMEM;
        }

        *ret_inode = info.lo_inode;
        *ret_devno = info.lo_device;
        *ret_fname = TAKE_PTR(fn);
        return 1;

notloop:
        *ret_devno = 0;
        *ret_inode = 0;
        *ret_fname = NULL;
        return 0;
}

static int builtin_blkid(struct udev_device *dev, int argc, char *argv[], enum udev_event_mode mode) {
        int64_t offset = 0;
        bool noraid = false;
        _cleanup_close_ int fd = -1;
        _cleanup_blkid_free_probe_ blkid_probe pr = NULL;
        const char *data;
        const char *name;
        const char *devnode;
        const char *root_partition;
        bool is_gpt = false;
        int nvals;
        int i;
        int err = 0;
        int r;
        _cleanup_free_ char *backing_fname = NULL;
        ino_t backing_inode = 0;
        dev_t backing_devno = 0;

        static const struct option options[] = {
                { "offset", required_argument, NULL, 'o' },
                { "hint",   required_argument, NULL, 'H' },
                { "noraid", no_argument, NULL, 'R' },
                {}
        };

        pr = blkid_new_probe();
        if (!pr)
                return EXIT_FAILURE;

        for (;;) {
                int option;

                option = getopt_long(argc, argv, "o:H:R", options, NULL);
                if (option == -1)
                        break;

                switch (option) {
                case 'H':
#ifdef HAVE_BLKID_PROBE_SET_HINT
                        if (blkid_probe_set_hint(pr, optarg, 0) < 0) {
                                log_error("Failed to use '%s' probing hint", optarg);
                                return EXIT_FAILURE;
                        }
                        break;
#else
                        /* Use the hint <name>=<offset> as probing offset for old versions */
                        optarg = strchr(optarg, '=');
                        if (!optarg)
                                /* no value means 0, do nothing for old versions */
                                break;
                        ++optarg;
                        /* fall through */
#endif
                case 'o':
                        r = safe_atoi64(optarg, &offset);
                        if (r < 0) {
                                log_error_errno(r, "Failed to parse '%s' as an integer: %m", optarg);
                                return EXIT_FAILURE;
                        }
                        if (offset < 0) {
                                log_error("Invalid offset %"PRIi64".", offset);
                                return EXIT_FAILURE;
                        }
                        break;
                case 'R':
                        noraid = true;
                        break;
                }
        }

        blkid_probe_set_superblocks_flags(pr,
                BLKID_SUBLKS_LABEL | BLKID_SUBLKS_UUID |
                BLKID_SUBLKS_TYPE | BLKID_SUBLKS_SECTYPE |
#ifdef BLKID_SUBLKS_FSINFO
                BLKID_SUBLKS_FSINFO |
#endif
                BLKID_SUBLKS_USAGE | BLKID_SUBLKS_VERSION);

        if (noraid)
                blkid_probe_filter_superblocks_usage(pr, BLKID_FLTR_NOTIN, BLKID_USAGE_RAID);

        devnode = udev_device_get_devnode(dev);
        if (!devnode) {
                log_debug("%s: Failed to get device name.", udev_device_get_sysname(dev));
                return EXIT_FAILURE;
        }

        fd = open(devnode, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (fd < 0) {
                bool ignore = errno == ENOENT;

                log_debug_errno(errno, "Failed to open block device %s%s: %m",
                                devnode, ignore ? ", ignoring" : "");
                return ignore ? EXIT_SUCCESS : EXIT_FAILURE;
        }

        err = blkid_probe_set_device(pr, fd, offset, 0);
        if (err < 0)
                goto out;

        log_debug("probe %s %sraid offset=%"PRIi64,
                  devnode,
                  noraid ? "no" : "", offset);

        err = probe_superblocks(pr);
        if (err < 0) {
                log_debug_errno(err, "Failed to probe superblocks of %s: %m", devnode);
                goto out;
        }

        /* If the device is a partition then its parent passed the root partition UUID to the device */
        root_partition = udev_device_get_property_value(dev, "ID_PART_GPT_AUTO_ROOT_UUID");

        nvals = blkid_probe_numof_values(pr);
        for (i = 0; i < nvals; i++) {
                if (blkid_probe_get_value(pr, i, &name, &data, NULL))
                        continue;

                print_property(dev, mode, name, data);

                /* Is this a disk with GPT partition table? */
                if (streq(name, "PTTYPE") && streq(data, "gpt"))
                        is_gpt = true;

                /* Is this a partition that matches the root partition
                 * property inherited from the parent? */
                if (root_partition && streq(name, "PART_ENTRY_UUID") && streq(data, root_partition))
                        udev_builtin_add_property(dev, mode, "ID_PART_GPT_AUTO_ROOT", "1");
        }

        r = read_loopback_backing_inode(
                        dev,
                        fd,
                        &backing_devno,
                        &backing_inode,
                        &backing_fname);
        if (r < 0)
                log_debug_errno(r, "Failed to read loopback backing inode, ignoring: %m");
        else if (r > 0) {
                char buf[DECIMAL_STR_MAX(uint64_t)*2 + 2];

                xsprintf(buf, "%u:%u", major(backing_devno), minor(backing_devno));
                udev_builtin_add_property(dev, mode, "ID_LOOP_BACKING_DEVICE", buf);
                xsprintf(buf, "%" PRIu64, (uint64_t) backing_inode);
                udev_builtin_add_property(dev, mode, "ID_LOOP_BACKING_INODE", buf);

                if (backing_fname) {
                        /* In the worst case blkid_encode_string() will blow up to 4x the string
                         * length. Hence size the buffer to 4x of the longest string
                         * read_loopback_backing_inode() might return */
                        char encoded[LO_NAME_SIZE * 4 + 1];

                        assert(strlen(backing_fname) < ELEMENTSOF(encoded) / 4);
                        blkid_encode_string(backing_fname, encoded, ELEMENTSOF(encoded));

                        /* lo_file_name is an arbitrary string picked by userspace, do not store it
                         * unencoded if it contains control characters or invalid UTF-8 */
                        if (utf8_is_valid(backing_fname) && !string_has_cc(backing_fname, /* ok= */ NULL))
                                udev_builtin_add_property(dev, mode, "ID_LOOP_BACKING_FILENAME", backing_fname);
                        udev_builtin_add_property(dev, mode, "ID_LOOP_BACKING_FILENAME_ENC", encoded);
                }
        }

        if (is_gpt)
                find_gpt_root(dev, pr, backing_fname, mode);

out:
        if (err < 0)
                return EXIT_FAILURE;

        return EXIT_SUCCESS;
}

const struct udev_builtin udev_builtin_blkid = {
        .name = "blkid",
        .cmd = builtin_blkid,
        .help = "Filesystem and partition probing",
        .run_once = true,
};
