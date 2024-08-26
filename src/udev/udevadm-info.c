/*
 * Copyright (C) 2004-2009 Kay Sievers <kay@vrfy.org>
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <ctype.h>
#include <stdarg.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysmacros.h>

#include "path-util.h"
#include "strv.h"
#include "udev.h"
#include "udev-util.h"
#include "udevadm-util.h"

/* Put a limit on --tree descent level to not exhaust our stack */
#define TREE_DEPTH_MAX 64

static JsonFormatFlags arg_json_format_flags = JSON_FORMAT_OFF;

static bool skip_attribute(const char *name) {
        static const char* const skip[] = {
                "uevent",
                "dev",
                "modalias",
                "resource",
                "driver",
                "subsystem",
                "module",
        };
        unsigned int i;

        for (i = 0; i < ELEMENTSOF(skip); i++)
                if (streq(name, skip[i]))
                        return true;
        return false;
}

typedef struct SysAttr {
        const char *name;
        const char *value;
} SysAttr;

static int sysattr_compare(const void *a, const void *b) {
        const SysAttr *x = a, *y = b;

        return strcmp(x->name, y->name);
}

static int collect_attributes(struct udev_device *device, SysAttr **ret, size_t *ret_n) {
        _cleanup_free_ SysAttr *sysattrs = NULL;
        size_t n_items = 0, n_allocated = 0;
        struct udev_list_entry *sysattr;

        assert(device);
        assert(ret);
        assert(ret_n);

        udev_list_entry_foreach(sysattr, udev_device_get_sysattr_list_entry(device)) {
                const char *name, *value;
                size_t len;

                name = udev_list_entry_get_name(sysattr);
                if (skip_attribute(name))
                        continue;

                value = udev_device_get_sysattr_value(device, name);
                if (value == NULL)
                        continue;

                /* skip any values that look like a path */
                if (value[0] == '/')
                        continue;

                /* skip nonprintable attributes */
                len = strlen(value);
                while (len > 0 && isprint((unsigned char) value[len-1]))
                        len--;
                if (len > 0)
                        continue;

                if (!GREEDY_REALLOC(sysattrs, n_allocated, n_items + 1))
                        return log_oom();

                sysattrs[n_items] = (SysAttr) {
                        .name = name,
                        .value = value,
                };
                n_items++;
        }

        qsort_safe(sysattrs, n_items, sizeof(SysAttr), sysattr_compare);

        *ret = sysattrs;
        sysattrs = NULL;
        *ret_n = n_items;
        return 0;
}

static int print_all_attributes(struct udev_device *device, bool is_parent) {
        _cleanup_free_ SysAttr *sysattrs = NULL;
        size_t n_items = 0, i;
        const char *value;
        int r;

        assert(device);

        if (is_parent)
                puts("");

        value = udev_device_get_devpath(device);
        printf("  looking at %sdevice '%s':\n", is_parent ? "parent " : "", value ?: "");

        value = udev_device_get_sysname(device);
        printf("    %s==\"%s\"\n", is_parent ? "KERNELS" : "KERNEL", value ?: "");

        value = udev_device_get_subsystem(device);
        printf("    %s==\"%s\"\n", is_parent ? "SUBSYSTEMS" : "SUBSYSTEM", value ?: "");

        value = udev_device_get_driver(device);
        printf("    %s==\"%s\"\n", is_parent ? "DRIVERS" : "DRIVER", value ?: "");

        r = collect_attributes(device, &sysattrs, &n_items);
        if (r < 0)
                return r;

        for (i = 0; i < n_items; i++)
                printf("    %s{%s}==\"%s\"\n", is_parent ? "ATTRS" : "ATTR", sysattrs[i].name, sysattrs[i].value);

        return 0;
}

static int print_device_chain(struct udev_device *device) {
        struct udev_device *child, *parent;
        int r;

        printf("\n"
               "Udevadm info starts with the device specified by the devpath and then\n"
               "walks up the chain of parent devices. It prints for every device\n"
               "found, all possible attributes in the udev rules key format.\n"
               "A rule to match, can be composed by the attributes of the device\n"
               "and the attributes from one single parent device.\n"
               "\n");

        r = print_all_attributes(device, /* is_parent = */ false);
        if (r < 0)
                return r;

        for (child = device; (parent = udev_device_get_parent(child)); child = parent) {
                r = print_all_attributes(parent, /* is_parent = */ true);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int print_all_attributes_in_json(struct udev_device *device, bool is_parent) {
        _cleanup_free_ SysAttr *sysattrs = NULL;
        size_t n_items = 0, i;
        JsonWriter w;
        int r;

        assert(device);

        r = collect_attributes(device, &sysattrs, &n_items);
        if (r < 0)
                return r;

        json_writer_init(&w, stdout, arg_json_format_flags);

        /* Like sd_json_variant_set_field_string() with a NULL string, a missing value is shown as null,
         * which json_writer_string() does. */
        json_writer_object_begin(&w);

        json_writer_key(&w, "DEVPATH");
        json_writer_string(&w, udev_device_get_devpath(device));

        json_writer_key(&w, is_parent ? "KERNELS" : "KERNEL");
        json_writer_string(&w, udev_device_get_sysname(device));

        json_writer_key(&w, is_parent ? "SUBSYSTEMS" : "SUBSYSTEM");
        json_writer_string(&w, udev_device_get_subsystem(device));

        json_writer_key(&w, is_parent ? "DRIVERS" : "DRIVER");
        json_writer_string(&w, udev_device_get_driver(device));

        json_writer_key(&w, is_parent ? "ATTRS" : "ATTR");
        if (n_items == 0)
                /* sd_json_variant_set_field() with a NULL object, as systemd does without attributes. */
                json_writer_null(&w);
        else {
                json_writer_object_begin(&w);
                for (i = 0; i < n_items; i++) {
                        json_writer_key(&w, sysattrs[i].name);
                        json_writer_string(&w, sysattrs[i].value);
                }
                json_writer_object_end(&w);
        }

        json_writer_object_end(&w);

        return json_writer_finish(&w);
}

static int print_device_chain_in_json(struct udev_device *device) {
        struct udev_device *child, *parent;
        int r;

        assert(device);

        arg_json_format_flags |= JSON_FORMAT_SEQ;

        r = print_all_attributes_in_json(device, /* is_parent = */ false);
        if (r < 0)
                return r;

        for (child = device; (parent = udev_device_get_parent(child)); child = parent) {
                r = print_all_attributes_in_json(parent, /* is_parent = */ true);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int device_get_diskseq(struct udev_device *device, uint64_t *ret) {
        const char *s;
        uint64_t q;

        /* Like sd_device_get_diskseq(): the kernel passes the sequence number of block devices in
         * the DISKSEQ uevent property. */
        s = udev_device_get_property_value(device, "DISKSEQ");
        if (!s)
                return -ENOENT;

        if (safe_atou64(s, &q) < 0)
                return -EINVAL;

        *ret = q;
        return 0;
}

/* Like sd_device_get_driver_subsystem(): for the devices of the "drivers" pseudo-subsystem, i.e.
 * /sys/bus/SUBSYSTEM/drivers/DRIVER, the subsystem of the driver. */
static int device_get_driver_subsystem(struct udev_device *device, char *buf, size_t size) {
        const char *devpath, *drivers, *p;

        assert(device);
        assert(buf);

        if (!streq_ptr(udev_device_get_subsystem(device), "drivers"))
                return -ENOENT;

        devpath = udev_device_get_devpath(device);
        drivers = strstr(devpath, "/drivers/");
        if (!drivers)
                drivers = endswith(devpath, "/drivers");
        if (!drivers)
                return -EINVAL;

        /* Find the path component immediately before the "/drivers/" string */
        for (p = drivers; p > devpath && p[-1] != '/'; p--)
                ;
        if (p == drivers)
                return -EINVAL;
        if ((size_t) (drivers - p) >= size)
                return -ENAMETOOLONG;

        memcpy(buf, p, drivers - p);
        buf[drivers - p] = '\0';
        return 0;
}

static void print_record(struct udev_device *device, const char *prefix) {
        char driver_subsystem[UTIL_NAME_SIZE];
        const char *str, *subsys;
        dev_t devnum;
        uint64_t q;
        int ifi;
        struct udev_list_entry *list_entry;

        /* We don't show syspath here, because it's identical to devpath (modulo the "/sys" prefix).
         *
         * We don't show action/seqnum here because that only makes sense for records synthesized from
         * uevents, not for those synthesized from database entries.
         *
         * We don't show sysattrs here, because they can be expensive and potentially issue expensive driver
         * IO.
         *
         * Coloring: let's be conservative with coloring. Let's use it to group related fields. Right now:
         *
         *     • highlight fields that give the device a name
         *     • green for fields that categorize the device into subsystem/devtype and similar
         *     • cyan for fields about associated device nodes/symlinks/network interfaces and such
         *     • magenta for block device diskseq
         *     • yellow for driver info
         *     • no color for regular properties */

        if (!prefix)
                prefix = "";

        printf("%sP: %s%s%s\n", prefix, ansi_highlight(), udev_device_get_devpath(device), ansi_normal());

        str = udev_device_get_sysname(device);
        if (str)
                printf("%sM: %s%s%s\n", prefix, ansi_highlight(), str, ansi_normal());

        str = udev_device_get_sysnum(device);
        if (str)
                printf("%sR: %s%s%s\n", prefix, ansi_highlight(), str, ansi_normal());

        /* The ID of the device in the udev database, as udevd names the files in /run/udev/data. */
        str = udev_device_get_id_filename(device);
        if (str)
                printf("%sJ: %s%s%s\n", prefix, ansi_highlight(), str, ansi_normal());

        subsys = udev_device_get_subsystem(device);
        if (subsys)
                printf("%sU: %s%s%s\n", prefix, ansi_highlight_green(), subsys, ansi_normal());

        if (device_get_driver_subsystem(device, driver_subsystem, sizeof(driver_subsystem)) >= 0)
                printf("%sB: %s%s%s\n", prefix, ansi_highlight_green(), driver_subsystem, ansi_normal());

        str = udev_device_get_devtype(device);
        if (str)
                printf("%sT: %s%s%s\n", prefix, ansi_highlight_green(), str, ansi_normal());

        devnum = udev_device_get_devnum(device);
        if (major(devnum) > 0)
                printf("%sD: %s%c %u:%u%s\n",
                       prefix,
                       ansi_highlight_cyan(),
                       streq_ptr(subsys, "block") ? 'b' : 'c', major(devnum), minor(devnum),
                       ansi_normal());

        ifi = udev_device_get_ifindex(device);
        if (ifi > 0)
                printf("%sI: %s%i%s\n", prefix, ansi_highlight_cyan(), ifi, ansi_normal());

        str = udev_device_get_devnode(device);
        if (str != NULL) {
                printf("%sN: %s%s%s\n", prefix, ansi_highlight_cyan(), str + strlen("/dev/"), ansi_normal());

                printf("%sL: %s%i%s\n", prefix, ansi_highlight_cyan(), udev_device_get_devlink_priority(device), ansi_normal());

                udev_list_entry_foreach(list_entry, udev_device_get_devlinks_list_entry(device))
                        printf("%sS: %s%s%s\n", prefix, ansi_highlight_cyan(),
                               udev_list_entry_get_name(list_entry) + strlen("/dev/"), ansi_normal());
        }

        if (device_get_diskseq(device, &q) >= 0)
                printf("%sQ: %s%" PRIu64 "%s\n", prefix, ansi_highlight_magenta(), q, ansi_normal());

        str = udev_device_get_driver(device);
        if (str)
                printf("%sV: %s%s%s\n", prefix, ansi_highlight_yellow(), str, ansi_normal());

        udev_list_entry_foreach(list_entry, udev_device_get_properties_list_entry(device))
                printf("%sE: %s=%s\n",
                       prefix,
                       udev_list_entry_get_name(list_entry),
                       udev_list_entry_get_value(list_entry));

        if (isempty(prefix))
                printf("\n");
}

static int record_to_json(struct udev_device *device) {
        char driver_subsystem[UTIL_NAME_SIZE];
        struct udev_list_entry *list_entry;
        JsonWriter w;
        const char *str;

        assert(device);

        /* We don't show any shorthand fields here as done in print_record() except for SYSNAME, SYSNUM,
         * DRIVER_SUBSYSTEM, and DEVICE_ID, as all the other ones have a matching property which will already
         * be included. */

        json_writer_init(&w, stdout, arg_json_format_flags);

        json_writer_object_begin(&w);

        str = udev_device_get_sysname(device);
        if (str) {
                json_writer_key(&w, "SYSNAME");
                json_writer_string(&w, str);
        }

        str = udev_device_get_sysnum(device);
        if (str) {
                json_writer_key(&w, "SYSNUM");
                json_writer_string(&w, str);
        }

        if (device_get_driver_subsystem(device, driver_subsystem, sizeof(driver_subsystem)) >= 0) {
                json_writer_key(&w, "DRIVER_SUBSYSTEM");
                json_writer_string(&w, driver_subsystem);
        }

        str = udev_device_get_id_filename(device);
        if (str) {
                json_writer_key(&w, "DEVICE_ID");
                json_writer_string(&w, str);
        }

        udev_list_entry_foreach(list_entry, udev_device_get_properties_list_entry(device)) {
                json_writer_key(&w, udev_list_entry_get_name(list_entry));
                json_writer_string(&w, udev_list_entry_get_value(list_entry));
        }

        json_writer_object_end(&w);

        return json_writer_finish(&w);
}

static int stat_device(const char *name, bool export, const char *prefix) {
        struct stat statbuf;

        if (stat(name, &statbuf) != 0)
                return -1;

        if (export) {
                if (prefix == NULL)
                        prefix = "INFO_";
                printf("%sMAJOR=%u\n"
                       "%sMINOR=%u\n",
                       prefix, major(statbuf.st_dev),
                       prefix, minor(statbuf.st_dev));
        } else
                printf("%u:%u\n", major(statbuf.st_dev), minor(statbuf.st_dev));
        return 0;
}

static int export_devices(struct udev *udev) {
        struct udev_enumerate *udev_enumerate;
        struct udev_list_entry *list_entry;

        udev_enumerate = udev_enumerate_new(udev);
        if (udev_enumerate == NULL)
                return -1;
        udev_enumerate_scan_devices(udev_enumerate);
        udev_list_entry_foreach(list_entry, udev_enumerate_get_list_entry(udev_enumerate)) {
                struct udev_device *device;

                device = udev_device_new_from_syspath(udev, udev_list_entry_get_name(list_entry));
                if (device != NULL) {
                        if (!json_format_enabled(arg_json_format_flags))
                                print_record(device, NULL);
                        else
                                (void) record_to_json(device);
                        udev_device_unref(device);
                }
        }
        udev_enumerate_unref(udev_enumerate);
        return 0;
}

static void cleanup_dir(DIR *dir, mode_t mask, int depth) {
        struct dirent *dent;
        int dfd;

        if (depth <= 0)
                return;

        dfd = dirfd(dir);
        if (dfd < 0)
                return;

        for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
                struct stat stats;

                if (dent->d_name[0] == '.')
                        continue;
                if (fstatat(dfd, dent->d_name, &stats, AT_SYMLINK_NOFOLLOW) != 0)
                        continue;
                if ((stats.st_mode & mask) != 0)
                        continue;
                if (S_ISDIR(stats.st_mode)) {
                        _cleanup_closedir_ DIR *subdir = NULL;

                        subdir = xopendirat(dfd, dent->d_name, O_NOFOLLOW);
                        if (!subdir)
                                log_debug_errno(errno, "Failed to open subdirectory '%s', ignoring: %m", dent->d_name);
                        else
                                cleanup_dir(subdir, mask, depth-1);

                        (void) unlinkat(dfd, dent->d_name, AT_REMOVEDIR);
                } else
                        (void) unlinkat(dfd, dent->d_name, 0);
        }
}

/*
 * Assume that dir is a directory with file names matching udev data base
 * entries for devices in /run/udev/data (such as "b8:16"), and removes
 * all files except those that haven't been deleted in /run/udev/data
 * (i.e. they were skipped during db cleanup because of the db_persist flag).
 * Returns true if the directory is empty after cleanup.
 */
static bool cleanup_dir_after_db_cleanup(DIR *dir, DIR *datadir) {
        unsigned int kept = 0;
        struct dirent *dent;
        int dfd, data_dfd;

        assert(dir && datadir);

        dfd = dirfd(dir);
        data_dfd = dirfd(datadir);
        if (dfd < 0 || data_dfd < 0)
                return false;

        for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
                struct stat data_stats, link_stats;

                if (streq(dent->d_name, ".") || streq(dent->d_name, ".."))
                        continue;
                if (fstatat(dfd, dent->d_name, &link_stats, AT_SYMLINK_NOFOLLOW) < 0) {
                        if (errno != ENOENT)
                                kept++;
                        continue;
                }

                if (fstatat(data_dfd, dent->d_name, &data_stats, 0) < 0)
                        (void) unlinkat(dfd, dent->d_name,
                                        S_ISDIR(link_stats.st_mode) ? AT_REMOVEDIR : 0);
                else
                        /* The entry still exists under /run/udev/data */
                        kept++;
        }

        return kept == 0;
}

static void cleanup_dirs_after_db_cleanup(DIR *dir, DIR *datadir) {
        struct dirent *dent;
        int dfd;

        assert(dir && datadir);

        dfd = dirfd(dir);
        if (dfd < 0)
                return;

        for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
                struct stat stats;

                if (streq(dent->d_name, ".") || streq(dent->d_name, ".."))
                        continue;
                if (fstatat(dfd, dent->d_name, &stats, AT_SYMLINK_NOFOLLOW) < 0)
                        continue;
                if (S_ISDIR(stats.st_mode)) {
                        _cleanup_closedir_ DIR *subdir = NULL;

                        subdir = xopendirat(dfd, dent->d_name, O_NOFOLLOW);
                        if (!subdir)
                                log_debug_errno(errno, "Failed to open subdirectory '%s', ignoring: %m", dent->d_name);
                        else if (cleanup_dir_after_db_cleanup(subdir, datadir))
                                (void) unlinkat(dfd, dent->d_name, AT_REMOVEDIR);
                } else
                        (void) unlinkat(dfd, dent->d_name, 0);
        }
}

/*
 * Removes the lock files of the stack directories in /run/udev/links.lock. A worker removes the lock
 * file of a devlink when it is done with it, so they are only left behind when a worker was killed
 * while it held one. A lock file that is held right now is kept. Removing one while holding it
 * exclusively is safe: a worker waiting for it notices that it was removed after getting the lock,
 * and creates a new one, see make_lock_file().
 */
static void cleanup_lock_dir(DIR *dir) {
        struct dirent *dent;
        int dfd;

        dfd = dirfd(dir);
        if (dfd < 0)
                return;

        for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
                _cleanup_close_ int fd = -1;

                if (dent->d_name[0] == '.')
                        continue;

                fd = openat(dfd, dent->d_name, O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NOCTTY|O_NONBLOCK);
                if (fd < 0)
                        continue;

                if (flock(fd, LOCK_EX|LOCK_NB) < 0) {
                        log_debug_errno(errno, "Lock file '%s' is in use, keeping it: %m", dent->d_name);
                        continue;
                }

                (void) unlinkat(dfd, dent->d_name, 0);
        }
}

static void cleanup_db(struct udev *udev __attribute__((unused))) {
        _cleanup_closedir_ DIR *dir1 = NULL, *dir2 = NULL, *dir3 = NULL, *dir4 = NULL, *dir5 = NULL;

        unlink(UDEV_ROOT_RUN "/udev/queue.bin");

        dir1 = opendir(UDEV_ROOT_RUN "/udev/data");
        if (dir1 != NULL)
                cleanup_dir(dir1, S_ISVTX, 1);

        /* Devices with the db_persist property are not deleted from the database, keep
         * their links and tags too, so that udevd has the same information about them
         * after it is restarted. */
        dir2 = opendir(UDEV_ROOT_RUN "/udev/links");
        if (dir2 != NULL) {
                if (dir1 != NULL)
                        cleanup_dirs_after_db_cleanup(dir2, dir1);
                else
                        cleanup_dir(dir2, 0, 2);
        }

        dir3 = opendir(UDEV_ROOT_RUN "/udev/tags");
        if (dir3 != NULL) {
                if (dir1 != NULL)
                        cleanup_dirs_after_db_cleanup(dir3, dir1);
                else
                        cleanup_dir(dir3, 0, 2);
        }

        dir4 = opendir(UDEV_ROOT_RUN "/udev/static_node-tags");
        if (dir4 != NULL)
                cleanup_dir(dir4, 0, 2);

        dir5 = opendir(UDEV_ROOT_RUN "/udev/links.lock");
        if (dir5 != NULL)
                cleanup_lock_dir(dir5);

        /* Do not remove /run/udev/watch. It will be handled by udevd well on restart.
         * And should not be removed by external program when udevd is running. */
}

static int wait_for_initialization(struct udev_device **device, usec_t timeout_usec) {
        struct udev_device *d;
        int r;

        if (timeout_usec == 0)
                return 0;

        r = device_wait_for_initialization(*device, timeout_usec, &d);
        if (r < 0)
                return r;

        udev_device_unref(*device);
        *device = d;
        return 0;
}

static int draw_tree(
                struct udev_device *parent,
                struct udev_device *const array[], size_t n,
                const char *prefix,
                unsigned level);

static int output_tree_device(
                struct udev_device *device,
                const char *str,
                const char *prefix,
                bool more,
                struct udev_device *const array[], size_t n,
                unsigned level) {

        _cleanup_free_ char *subprefix = NULL, *subsubprefix = NULL;

        assert(device);
        assert(str);

        if (!prefix)
                prefix = "";

        printf("%s%s%s\n", prefix, glyph(more ? GLYPH_TREE_BRANCH : GLYPH_TREE_RIGHT), str);

        subprefix = strjoin(prefix, glyph(more ? GLYPH_TREE_VERTICAL : GLYPH_TREE_SPACE), NULL);
        if (!subprefix)
                return log_oom();

        subsubprefix = strjoin(subprefix, glyph(GLYPH_VERTICAL_DOTTED), " ", NULL);
        if (!subsubprefix)
                return log_oom();

        print_record(device, subsubprefix);

        return draw_tree(device, array, n, subprefix, level + 1);
}

static int draw_tree(
                struct udev_device *parent,
                struct udev_device *const array[], size_t n,
                const char *prefix,
                unsigned level) {

        const char *parent_path;
        size_t i = 0;
        int r;

        if (n == 0)
                return 0;

        assert(array);

        parent_path = parent ? udev_device_get_devpath(parent) : NULL;

        if (level > TREE_DEPTH_MAX) {
                log_warning("Eliding tree below '%s', too deep.", parent_path ?: "n/a");
                return 0;
        }

        while (i < n) {
                struct udev_device *device = array[i];
                const char *device_path, *str;
                bool more = false;
                size_t j;

                device_path = udev_device_get_devpath(device);

                /* Scan through the subsequent devices looking children of the device we are looking at. */
                for (j = i + 1; j < n; j++) {
                        const char *next_path = udev_device_get_devpath(array[j]);

                        if (!path_startswith(next_path, device_path)) {
                                more = !parent_path || path_startswith(next_path, parent_path);
                                break;
                        }
                }

                /* Determine the string to display for this node. If we are at the top of the tree, the full
                 * device path so far, otherwise just the part suffixing the parent's device path. */
                str = parent ? path_startswith(device_path, parent_path) : device_path;
                assert(str);

                r = output_tree_device(device, str, prefix, more, array + i + 1, j - i - 1, level);
                if (r < 0)
                        return r;

                i = j;
        }

        return 0;
}

static int print_tree(struct udev *udev, struct udev_device *below) {
        _cleanup_udev_enumerate_unref_ struct udev_enumerate *e = NULL;
        struct udev_list_entry *entry;
        struct udev_device **array = NULL;
        size_t n = 0, n_allocated = 0, i;
        int r;

        e = udev_enumerate_new(udev);
        if (!e)
                return log_error_errno(ENOMEM, "Failed to allocate device enumerator: %m");

        if (below) {
                r = udev_enumerate_add_match_parent(e, below);
                if (r < 0)
                        return log_error_errno(r, "Failed to install parent enumerator match: %m");
        }

        r = udev_enumerate_scan_devices(e);
        if (r >= 0)
                r = udev_enumerate_scan_subsystems(e);
        if (r < 0)
                return log_error_errno(r, "Failed to scan for devices and subsystems: %m");

        if (below) {
                struct udev_device *parent;

                /* This must be called after the scan. Like sd-device's enumerator, skip devices without
                 * a subsystem, which a subsystem match never matches. */
                for (parent = udev_device_get_parent(below); parent; parent = udev_device_get_parent(parent)) {
                        if (!udev_device_get_subsystem(parent))
                                continue;

                        r = udev_enumerate_add_syspath(e, udev_device_get_syspath(parent));
                        if (r < 0)
                                return log_error_errno(r, "Failed to add parent devices: %m");
                }
        }

        udev_list_entry_foreach(entry, udev_enumerate_get_list_entry(e)) {
                struct udev_device *d;

                /* Devices that are gone meanwhile are skipped. */
                d = udev_device_new_from_syspath(udev, udev_list_entry_get_name(entry));
                if (!d)
                        continue;

                if (!GREEDY_REALLOC(array, n_allocated, n + 1)) {
                        udev_device_unref(d);
                        r = log_oom();
                        goto finish;
                }

                array[n++] = d;
        }

        if (n == 0) {
                log_info("No items.");
                r = 0;
                goto finish;
        }

        r = draw_tree(NULL, array, n, NULL, 0);
        if (r < 0)
                goto finish;

        printf("\n%zu items shown.\n", n);
        r = 0;

finish:
        for (i = 0; i < n; i++)
                udev_device_unref(array[i]);
        free(array);
        return r;
}

static void help(void) {

        printf("%s info [OPTIONS] [DEVPATH|FILE]\n\n"
               "Query sysfs or the udev database.\n\n"
               "  -h --help                   Print this message\n"
               "     --version                Print version of the program\n"
               "  -q --query=TYPE             Query device information:\n"
               "       name                     Name of device node\n"
               "       symlink                  Pointing to node\n"
               "       path                     sysfs device path\n"
               "       property                 The device properties\n"
               "       all                      All values\n"
               "     --property=NAME          Show only properties by this name\n"
               "     --value                  Print only values\n"
               "  -p --path=SYSPATH           sysfs device path used for query or attribute walk\n"
               "  -n --name=NAME              Node or symlink name used for query or attribute walk\n"
               "  -r --root                   Prepend dev directory to path names\n"
               "  -a --attribute-walk         Print all key matches walking along the chain\n"
               "                              of parent devices\n"
               "  -t --tree                   Show tree of devices\n"
               "  -d --device-id-of-file=FILE Print major:minor of device containing this file\n"
               "  -x --export                 Export key/value pairs\n"
               "  -P --export-prefix          Export the key name with a prefix\n"
               "  -e --export-db              Export the content of the udev database\n"
               "  -c --cleanup-db             Clean up the udev database\n"
               "  -w --wait-for-initialization[=SECONDS]\n"
               "                              Wait for device to be initialized\n"
               "     --json=pretty|short|off  Generate JSON output\n"
               , program_invocation_short_name);
}

static int uinfo(struct udev *udev, int argc, char *argv[]) {
        _cleanup_udev_device_unref_ struct udev_device *device = NULL;
        _cleanup_strv_free_ char **properties = NULL;
        bool root = 0;
        bool export = 0;
        bool value = false;
        const char *export_prefix = NULL;
        char name[UTIL_PATH_SIZE];
        struct udev_list_entry *list_entry;
        usec_t wait_for_initialization_timeout = 0;
        int c, r;

        enum {
                ARG_PROPERTY = 0x100,
                ARG_VALUE,
                ARG_JSON,
        };

        static const struct option options[] = {
                { "name",              required_argument, NULL, 'n' },
                { "path",              required_argument, NULL, 'p' },
                { "query",             required_argument, NULL, 'q' },
                { "attribute-walk",    no_argument,       NULL, 'a' },
                { "tree",              no_argument,       NULL, 't' },
                { "cleanup-db",        no_argument,       NULL, 'c' },
                { "export-db",         no_argument,       NULL, 'e' },
                { "root",              no_argument,       NULL, 'r' },
                { "device-id-of-file", required_argument, NULL, 'd' },
                { "export",            no_argument,       NULL, 'x' },
                { "export-prefix",     required_argument, NULL, 'P' },
                { "property",          required_argument, NULL, ARG_PROPERTY },
                { "value",             no_argument,       NULL, ARG_VALUE },
                { "json",              required_argument, NULL, ARG_JSON },
                { "wait-for-initialization", optional_argument, NULL, 'w' },
                { "version",           no_argument,       NULL, 'V' },
                { "help",              no_argument,       NULL, 'h' },
                {}
        };

        enum action_type {
                ACTION_QUERY,
                ACTION_ATTRIBUTE_WALK,
                ACTION_DEVICE_ID_FILE,
                ACTION_TREE,
                ACTION_EXPORT,
        } action = ACTION_QUERY;

        enum query_type {
                QUERY_NAME,
                QUERY_PATH,
                QUERY_SYMLINK,
                QUERY_PROPERTY,
                QUERY_ALL,
        } query = QUERY_ALL;

        while ((c = getopt_long(argc, argv, "atced:n:p:q:rxP:w::Vh", options, NULL)) >= 0)
                switch (c) {
                case ARG_PROPERTY:
                        /* Make sure that if the empty property list was specified, we won't show any
                           properties. */
                        if (isempty(optarg) && !properties) {
                                properties = new0(char*, 1);
                                if (!properties) {
                                        log_oom();
                                        return 1;
                                }
                        } else {
                                r = strv_split_and_extend(&properties, optarg, ",", true);
                                if (r < 0) {
                                        log_oom();
                                        return 1;
                                }
                        }
                        break;
                case ARG_VALUE:
                        value = true;
                        break;
                case ARG_JSON:
                        r = parse_json_argument(optarg, &arg_json_format_flags);
                        if (r <= 0)
                                return r < 0 ? 1 : 0;
                        break;
                case 'n': {
                        if (device != NULL) {
                                fprintf(stderr, "device already specified\n");
                                return 2;
                        }

                        device = find_device(udev, optarg, "/dev/");
                        if (device == NULL) {
                                fprintf(stderr, "device node not found\n");
                                return 2;
                        }
                        break;
                }
                case 'p':
                        if (device != NULL) {
                                fprintf(stderr, "device already specified\n");
                                return 2;
                        }

                        device = find_device(udev, optarg, "/sys");
                        if (device == NULL) {
                                fprintf(stderr, "syspath not found\n");
                                return 2;
                        }
                        break;
                case 'q':
                        action = ACTION_QUERY;
                        if (streq(optarg, "property") || streq(optarg, "env"))
                                query = QUERY_PROPERTY;
                        else if (streq(optarg, "name"))
                                query = QUERY_NAME;
                        else if (streq(optarg, "symlink"))
                                query = QUERY_SYMLINK;
                        else if (streq(optarg, "path"))
                                query = QUERY_PATH;
                        else if (streq(optarg, "all"))
                                query = QUERY_ALL;
                        else {
                                fprintf(stderr, "unknown query type\n");
                                return 3;
                        }
                        break;
                case 'r':
                        root = true;
                        break;
                case 'd':
                        action = ACTION_DEVICE_ID_FILE;
                        strscpy(name, sizeof(name), optarg);
                        break;
                case 'a':
                        action = ACTION_ATTRIBUTE_WALK;
                        break;
                case 't':
                        action = ACTION_TREE;
                        break;
                case 'e':
                        action = ACTION_EXPORT;
                        break;
                case 'c':
                        cleanup_db(udev);
                        return 0;
                case 'x':
                        export = true;
                        break;
                case 'P':
                        export = true;
                        export_prefix = optarg;
                        break;
                case 'w':
                        if (optarg) {
                                r = parse_sec(optarg, &wait_for_initialization_timeout);
                                if (r < 0) {
                                        log_error_errno(r, "Failed to parse timeout value: %m");
                                        return 1;
                                }
                        } else
                                wait_for_initialization_timeout = USEC_INFINITY;
                        break;
                case 'V':
                        printf("%s\n", UDEV_VERSION);
                        return 0;
                case 'h':
                        help();
                        return 0;
                default:
                        return 1;
                }

        if (export && value) {
                log_error("-x/--export or -P/--export-prefix cannot be used with --value");
                return 1;
        }

        switch (action) {
        case ACTION_EXPORT:
                export_devices(udev);
                break;
        case ACTION_QUERY:
                if (!device) {
                        if (!argv[optind]) {
                                help();
                                return 2;
                        }
                        device = find_device(udev, argv[optind], NULL);
                        if (!device) {
                                fprintf(stderr, "Unknown device, --name=, --path=, or absolute path in /dev/ or /sys expected.\n");
                                return 4;
                        }
                }

                if (wait_for_initialization(&device, wait_for_initialization_timeout) < 0)
                        return 1;

                switch(query) {
                case QUERY_NAME: {
                        const char *node = udev_device_get_devnode(device);

                        if (node == NULL) {
                                fprintf(stderr, "no device node found\n");
                                return 5;
                        }

                        if (root)
                                printf("%s\n", udev_device_get_devnode(device));
                        else
                                printf("%s\n", udev_device_get_devnode(device) + strlen("/dev/"));
                        break;
                }
                case QUERY_SYMLINK:
                        list_entry = udev_device_get_devlinks_list_entry(device);
                        while (list_entry != NULL) {
                                const char *devlink = udev_list_entry_get_name(list_entry);

                                if (!root)
                                        devlink += strlen("/dev/");

                                list_entry = udev_list_entry_get_next(list_entry);

                                if (value)
                                        printf("%s\n", devlink);
                                else
                                        printf("%s%s", devlink, list_entry != NULL ? " " : "");
                        }
                        printf("\n");
                        break;
                case QUERY_PATH:
                        printf("%s\n", udev_device_get_devpath(device));
                        return 0;
                case QUERY_PROPERTY:
                        list_entry = udev_device_get_properties_list_entry(device);
                        while (list_entry != NULL) {
                                if (properties && !strv_contains(properties, udev_list_entry_get_name(list_entry))) {
                                        list_entry = udev_list_entry_get_next(list_entry);
                                        continue;
                                }

                                if (export) {
                                        const char *prefix = export_prefix;

                                        if (prefix == NULL)
                                                prefix = "";
                                        printf("%s%s='%s'\n", prefix,
                                               udev_list_entry_get_name(list_entry),
                                               udev_list_entry_get_value(list_entry));
                                } else if (value)
                                        printf("%s\n", udev_list_entry_get_value(list_entry));
                                else
                                        printf("%s=%s\n", udev_list_entry_get_name(list_entry), udev_list_entry_get_value(list_entry));
                                list_entry = udev_list_entry_get_next(list_entry);
                        }
                        break;
                case QUERY_ALL:
                        if (!json_format_enabled(arg_json_format_flags))
                                print_record(device, NULL);
                        else
                                (void) record_to_json(device);
                        break;
                default:
                        assert_not_reached("unknown query type");
                }
                break;
        case ACTION_ATTRIBUTE_WALK:
                if (!device && argv[optind]) {
                        device = find_device(udev, argv[optind], NULL);
                        if (!device) {
                                fprintf(stderr, "Unknown device, absolute path in /dev/ or /sys expected.\n");
                                return 4;
                        }
                }
                if (!device) {
                        fprintf(stderr, "Unknown device, --name=, --path=, or absolute path in /dev/ or /sys expected.\n");
                        return 4;
                }
                if (wait_for_initialization(&device, wait_for_initialization_timeout) < 0)
                        return 1;
                if (!json_format_enabled(arg_json_format_flags))
                        r = print_device_chain(device);
                else
                        r = print_device_chain_in_json(device);
                if (r < 0)
                        return 1;
                break;
        case ACTION_DEVICE_ID_FILE:
                if (stat_device(name, export, export_prefix) != 0)
                        return 1;
                break;
        case ACTION_TREE:
                if (!device && argv[optind]) {
                        device = find_device(udev, argv[optind], NULL);
                        if (!device) {
                                fprintf(stderr, "Unknown device, --name=, --path=, or absolute path in /dev/ or /sys expected.\n");
                                return 4;
                        }
                }
                if (device && wait_for_initialization(&device, wait_for_initialization_timeout) < 0)
                        return 1;
                if (print_tree(udev, device) < 0)
                        return 1;
                break;
        }

        return 0;
}

const struct udevadm_cmd udevadm_info = {
        .name = "info",
        .cmd = uinfo,
        .help = "Query sysfs or the udev database",
};
