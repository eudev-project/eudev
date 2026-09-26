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

#include "udev.h"
#include "utf8.h"

static void print_property(struct udev_device *dev, bool test, const char *name, const char *value) {
        char s[256];

        s[0] = '\0';

        if (streq(name, "TYPE")) {
                udev_builtin_add_property(dev, test, "ID_FS_TYPE", value);

        } else if (streq(name, "USAGE")) {
                udev_builtin_add_property(dev, test, "ID_FS_USAGE", value);

        } else if (streq(name, "VERSION")) {
                udev_builtin_add_property(dev, test, "ID_FS_VERSION", value);

        } else if (streq(name, "UUID")) {
                blkid_safe_string(value, s, sizeof(s));
                udev_builtin_add_property(dev, test, "ID_FS_UUID", s);
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(dev, test, "ID_FS_UUID_ENC", s);

        } else if (streq(name, "UUID_SUB")) {
                blkid_safe_string(value, s, sizeof(s));
                udev_builtin_add_property(dev, test, "ID_FS_UUID_SUB", s);
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(dev, test, "ID_FS_UUID_SUB_ENC", s);

        } else if (streq(name, "LABEL")) {
                blkid_safe_string(value, s, sizeof(s));
                udev_builtin_add_property(dev, test, "ID_FS_LABEL", s);
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(dev, test, "ID_FS_LABEL_ENC", s);

        } else if (streq(name, "FSSIZE") || streq(name, "FSLASTBLOCK") || streq(name, "FSBLOCKSIZE")) {
                strscpyl(s, sizeof(s), "ID_FS_", name + 2, NULL);
                udev_builtin_add_property(dev, test, s, value);

        } else if (streq(name, "PTTYPE")) {
                udev_builtin_add_property(dev, test, "ID_PART_TABLE_TYPE", value);

        } else if (streq(name, "PTUUID")) {
                udev_builtin_add_property(dev, test, "ID_PART_TABLE_UUID", value);

        } else if (streq(name, "PART_ENTRY_NAME")) {
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(dev, test, "ID_PART_ENTRY_NAME", s);

        } else if (streq(name, "PART_ENTRY_TYPE")) {
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(dev, test, "ID_PART_ENTRY_TYPE", s);

        } else if (startswith(name, "PART_ENTRY_")) {
                strscpyl(s, sizeof(s), "ID_", name, NULL);
                udev_builtin_add_property(dev, test, s, value);

        } else if (streq(name, "SYSTEM_ID")) {
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(dev, test, "ID_FS_SYSTEM_ID", s);

        } else if (streq(name, "PUBLISHER_ID")) {
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(dev, test, "ID_FS_PUBLISHER_ID", s);

        } else if (streq(name, "APPLICATION_ID")) {
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(dev, test, "ID_FS_APPLICATION_ID", s);

        } else if (streq(name, "BOOT_SYSTEM_ID")) {
                blkid_encode_string(value, s, sizeof(s));
                udev_builtin_add_property(dev, test, "ID_FS_BOOT_SYSTEM_ID", s);
        }
}

static int probe_superblocks(blkid_probe pr) {
        struct stat st;
        int rc;

        if (fstat(blkid_probe_get_fd(pr), &st))
                return -1;

        blkid_probe_enable_partitions(pr, 1);

        if (!S_ISCHR(st.st_mode) &&
            blkid_probe_get_size(pr) <= 1024 * 1440 &&
            blkid_probe_is_wholedisk(pr)) {
                /*
                 * check if the small disk is partitioned, if yes then
                 * don't probe for filesystems.
                 */
                blkid_probe_enable_superblocks(pr, 0);

                rc = blkid_do_fullprobe(pr);
                if (rc < 0)
                        return rc;        /* -1 = error, 1 = nothing, 0 = success */

                if (blkid_probe_lookup_value(pr, "PTTYPE", NULL, NULL) == 0)
                        return 0;        /* partition table detected */
        }

        blkid_probe_set_partitions_flags(pr, BLKID_PARTS_ENTRY_DETAILS);
        blkid_probe_enable_superblocks(pr, 1);

        return blkid_do_safeprobe(pr);
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

static int builtin_blkid(struct udev_device *dev, int argc, char *argv[], bool test) {
        int64_t offset = 0;
        bool noraid = false;
        _cleanup_close_ int fd = -1;
        blkid_probe pr;
        const char *data;
        const char *name;
        const char *prtype = NULL;
        int nvals;
        int i;
        int err = 0;
        int r;
        _cleanup_free_ char *backing_fname = NULL;
        ino_t backing_inode = 0;
        dev_t backing_devno = 0;

        static const struct option options[] = {
                { "offset", optional_argument, NULL, 'o' },
                { "hint",   required_argument, NULL, 'H' },
                { "noraid", no_argument, NULL, 'R' },
                {}
        };

        pr = blkid_new_probe();
        if (!pr)
                return EXIT_FAILURE;

        for (;;) {
                int option;

                option = getopt_long(argc, argv, "oH:R", options, NULL);
                if (option == -1)
                        break;

                switch (option) {
                case 'H':
#ifdef HAVE_BLKID_PROBE_SET_HINT
                        if (blkid_probe_set_hint(pr, optarg, 0) < 0) {
                                log_error("Failed to use '%s' probing hint", optarg);
                                blkid_free_probe(pr);
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
                        offset = strtoull(optarg, NULL, 0);
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
                BLKID_SUBLKS_USAGE | BLKID_SUBLKS_VERSION |
                BLKID_SUBLKS_BADCSUM);

        if (noraid)
                blkid_probe_filter_superblocks_usage(pr, BLKID_FLTR_NOTIN, BLKID_USAGE_RAID);

        fd = open(udev_device_get_devnode(dev), O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0) {
                err = log_debug_errno(errno, "Failure opening block device %s: %m", udev_device_get_devnode(dev));
                goto out;
        }

        err = blkid_probe_set_device(pr, fd, offset, 0);
        if (err < 0)
                goto out;

        log_debug("probe %s %sraid offset=%"PRIi64,
                  udev_device_get_devnode(dev),
                  noraid ? "no" : "", offset);

        err = probe_superblocks(pr);
        if (err < 0)
                goto out;
        if (blkid_probe_has_value(pr, "SBBADCSUM")) {
                if (!blkid_probe_lookup_value(pr, "TYPE", &prtype, NULL))
                        log_warning("incorrect %s checksum on %s",
                                    prtype, udev_device_get_devnode(dev));
                else
                        log_warning("incorrect checksum on %s",
                                    udev_device_get_devnode(dev));
                goto out;
        }

        nvals = blkid_probe_numof_values(pr);
        for (i = 0; i < nvals; i++) {
                if (blkid_probe_get_value(pr, i, &name, &data, NULL))
                        continue;

                print_property(dev, test, name, data);
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
                udev_builtin_add_property(dev, test, "ID_LOOP_BACKING_DEVICE", buf);
                xsprintf(buf, "%" PRIu64, (uint64_t) backing_inode);
                udev_builtin_add_property(dev, test, "ID_LOOP_BACKING_INODE", buf);

                if (backing_fname) {
                        /* In the worst case blkid_encode_string() will blow up to 4x the string
                         * length. Hence size the buffer to 4x of the longest string
                         * read_loopback_backing_inode() might return */
                        char encoded[LO_NAME_SIZE * 4 + 1];

                        assert(strlen(backing_fname) < ELEMENTSOF(encoded) / 4);
                        blkid_encode_string(backing_fname, encoded, ELEMENTSOF(encoded));

                        /* lo_file_name is an arbitrary string picked by userspace, do not store it
                         * unencoded if it contains control characters or invalid UTF-8 */
                        if (utf8_is_printable_newline(backing_fname, strlen(backing_fname), false))
                                udev_builtin_add_property(dev, test, "ID_LOOP_BACKING_FILENAME", backing_fname);
                        udev_builtin_add_property(dev, test, "ID_LOOP_BACKING_FILENAME_ENC", encoded);
                }
        }

        blkid_free_probe(pr);
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
