/***
  This file is part of systemd.

  Copyright 2008-2012 Kay Sievers <kay@vrfy.org>

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <linux/filter.h>

#include "libudev.h"
#include "libudev-private.h"
#include "def.h"
#include "fileio.h"
#include "id128-util.h"
#include "log.h"
#include "path-util.h"
#include "process-util.h"
#include "strv.h"
#include "time-util.h"
#include "utf8.h"

static int udev_device_tag(struct udev_device *dev, const char *tag, bool add)
{
        const char *id;
        char filename[UTIL_PATH_SIZE];

        id = udev_device_get_id_filename(dev);
        if (id == NULL)
                return -ENODEV;
        strscpyl(filename, sizeof(filename), UDEV_ROOT_RUN "/udev/tags/", tag, "/", id, NULL);

        if (add) {
                unsigned int i;
                int r = -ENOENT;

                /* A worker removing the last device of the tag may remove the directory of the tag
                 * right after it is created here, then create it again. */
                for (i = 0; i < 16; i++) {
                        int fd;

                        (void) mkdir_parents(filename, 0755);
                        fd = open(filename, O_WRONLY|O_CREAT|O_CLOEXEC|O_TRUNC|O_NOFOLLOW, 0444);
                        if (fd >= 0) {
                                close(fd);
                                return 0;
                        }
                        r = -errno;
                        if (r != -ENOENT)
                                break;
                }

                return r;
        } else {
                char *slash;

                if (unlink(filename) < 0)
                        return errno == ENOENT ? 0 : -errno;

                /* Unlike systemd, remove the directory of the tag when it is empty now, so that
                 * /run/udev/tags/ does not keep a directory for every tag that was ever used. This
                 * fails, as it should, when the directory is not empty, e.g. when another worker
                 * has just added a device to the tag. */
                slash = strrchr(filename, '/');
                if (slash) {
                        *slash = '\0';
                        (void) rmdir(filename);
                }

                return 0;
        }
}

int udev_device_tag_index(struct udev_device *dev, bool add)
{
        struct udev_list_entry *list_entry;
        int r = 0;

        /* Like systemd, handle every tag, and return the first error. */
        udev_list_entry_foreach(list_entry, udev_device_get_tags_list_entry(dev)) {
                int k;

                k = udev_device_tag(dev, udev_list_entry_get_name(list_entry), add);
                if (k < 0 && r >= 0)
                        r = k;
        }

        return r;
}

/* Restores the tag index after a failed event of the device: removes the entries of the tags that the device
 * has and the previous state old, e.g. as read from the database before the event, does not have, and adds
 * the entries of the tags of old again, unless it is NULL. Like udev_device_tag_index(), handles every tag,
 * and returns the first error. */
int udev_device_tag_index_restore(struct udev_device *dev, struct udev_device *old)
{
        struct udev_list_entry *list_entry;
        int r = 0, k;

        udev_list_entry_foreach(list_entry, udev_device_get_tags_list_entry(dev)) {
                const char *tag = udev_list_entry_get_name(list_entry);

                if (old && udev_device_has_tag(old, tag))
                        continue;

                k = udev_device_tag(dev, tag, false);
                if (k < 0 && r >= 0)
                        r = k;
        }

        if (old) {
                k = udev_device_tag_index(old, true);
                if (k < 0 && r >= 0)
                        r = k;
        }

        return r;
}

static bool device_has_info(struct udev_device *udev_device)
{
        struct udev_list_entry *list_entry;

        if (udev_device_get_devlinks_list_entry(udev_device) != NULL)
                return true;
        if (udev_device_get_devlink_priority(udev_device) != 0)
                return true;
        udev_list_entry_foreach(list_entry, udev_device_get_properties_list_entry(udev_device))
                if (udev_list_entry_get_num(list_entry))
                        return true;
        if (udev_device_get_tags_list_entry(udev_device) != NULL)
                return true;
        if (udev_device_get_current_tags_list_entry_raw(udev_device) != NULL)
                return true;
        return false;
}

/* Each entry of the database is a "<key>:<value>" line, and the database is read with lines of at
 * most LONG_LINE_MAX characters. libudev already refuses devlinks, properties and tags containing
 * control characters, but make sure that no entry can ever break the database, e.g. with a line
 * break. */
static bool db_entry_is_safe(struct udev_device *udev_device, const char *key, const char *name, const char *value)
{
        _cleanup_free_ char *escaped = NULL;
        size_t len;

        /* "<key>:<name>" or "<key>:<name>=<value>" must fit, see udev_device_read_db() */
        len = strlen(key) + 1 + strlen(name);
        if (value)
                len += 1 + strlen(value);

        if (!string_has_cc(name, NULL) && (!value || !string_has_cc(value, NULL)) && len < LONG_LINE_MAX)
                return true;

        escaped = utf8_escape_non_printable(name);
        log_debug("%s: not writing invalid or too long %s: entry '%s' to the db, ignoring",
                  udev_device_get_sysname(udev_device), key, escaped ?: "");
        return false;
}

int udev_device_update_db(struct udev_device *udev_device)
{
        bool has_info;
        const char *id;
        char filename[UTIL_PATH_SIZE];
        char filename_tmp[UTIL_PATH_SIZE];
        FILE *f = NULL;
        int r;

        id = udev_device_get_id_filename(udev_device);
        if (id == NULL)
                return -ENODEV;

        has_info = device_has_info(udev_device);
        strscpyl(filename, sizeof(filename), UDEV_ROOT_RUN "/udev/data/", id, NULL);

        /* do not store anything for otherwise empty devices */
        if (!has_info &&
            major(udev_device_get_devnum(udev_device)) == 0 &&
            udev_device_get_ifindex(udev_device) == 0) {
                if (unlink(filename) < 0 && errno != ENOENT)
                        return -errno;
                return 0;
        }

        /* write a database file */
        strscpyl(filename_tmp, sizeof(filename_tmp), filename, ".tmp", NULL);
        r = mkdir_parents(filename_tmp, 0755);
        if (r < 0) {
                log_debug_errno(r, "unable to create the parent directories of '%s': %m", filename_tmp);
                goto fail;
        }
        f = fopen(filename_tmp, "we");
        if (f == NULL) {
                r = log_debug_errno(errno, "unable to create temporary db file '%s': %m", filename_tmp);
                goto fail;
        }

        /*
         * set 'sticky' bit to indicate that we should not clean the
         * database when we transition from initramfs to the real root
         */
        if (udev_device_get_db_persist(udev_device) && fchmod(fileno(f), 01644) < 0) {
                r = log_debug_errno(errno, "unable to chmod temporary db file '%s': %m", filename_tmp);
                goto fail;
        }

        if (has_info) {
                struct udev_list_entry *list_entry;

                if (major(udev_device_get_devnum(udev_device)) > 0) {
                        udev_list_entry_foreach(list_entry, udev_device_get_devlinks_list_entry(udev_device)) {
                                const char *link = udev_list_entry_get_name(list_entry) + strlen("/dev/");

                                if (db_entry_is_safe(udev_device, "S", link, NULL))
                                        fprintf(f, "S:%s\n", link);
                        }
                        if (udev_device_get_devlink_priority(udev_device) != 0)
                                fprintf(f, "L:%i\n", udev_device_get_devlink_priority(udev_device));
                }

                if (udev_device_get_usec_initialized(udev_device) > 0)
                        fprintf(f, "I:"USEC_FMT"\n", udev_device_get_usec_initialized(udev_device));

                udev_list_entry_foreach(list_entry, udev_device_get_properties_list_entry(udev_device)) {
                        if (!udev_list_entry_get_num(list_entry) || !udev_list_entry_get_value(list_entry))
                                continue;
                        if (!db_entry_is_safe(udev_device, "E",
                                              udev_list_entry_get_name(list_entry),
                                              udev_list_entry_get_value(list_entry)))
                                continue;
                        fprintf(f, "E:%s=%s\n",
                                udev_list_entry_get_name(list_entry),
                                udev_list_entry_get_value(list_entry));
                }

                udev_list_entry_foreach(list_entry, udev_device_get_tags_list_entry(udev_device))
                        if (db_entry_is_safe(udev_device, "G", udev_list_entry_get_name(list_entry), NULL))
                                fprintf(f, "G:%s\n", udev_list_entry_get_name(list_entry)); /* Any tag */

                udev_list_entry_foreach(list_entry, udev_device_get_current_tags_list_entry_raw(udev_device))
                        if (db_entry_is_safe(udev_device, "Q", udev_list_entry_get_name(list_entry), NULL))
                                fprintf(f, "Q:%s\n", udev_list_entry_get_name(list_entry)); /* Current tag */

                /* Always write the latest database version here, instead of the value stored in
                 * the device, as which may be 0. */
                fprintf(f, "V:%u\n", LATEST_UDEV_DATABASE_VERSION);
        }

        errno = 0;
        if (fflush(f) != 0 || ferror(f)) {
                r = log_debug_errno(errno > 0 ? errno : EIO, "unable to write temporary db file '%s': %m", filename_tmp);
                goto fail;
        }
        r = fclose(f);
        f = NULL;
        if (r != 0) {
                r = log_debug_errno(errno, "unable to write temporary db file '%s': %m", filename_tmp);
                goto fail;
        }
        if (rename(filename_tmp, filename) < 0) {
                r = log_debug_errno(errno, "unable to rename temporary db file '%s' to '%s': %m", filename_tmp, filename);
                goto fail;
        }
        log_debug("created %s file '%s' for '%s'", has_info ? "db" : "empty",
             filename, udev_device_get_devpath(udev_device));
        return 0;

fail:
        /* Like systemd, do not leave the old database file behind when it cannot be updated. */
        if (f != NULL)
                fclose(f);
        (void) unlink(filename_tmp);
        (void) unlink(filename);
        return r;
}

int udev_device_delete_db(struct udev_device *udev_device)
{
        const char *id;
        char filename[UTIL_PATH_SIZE];

        id = udev_device_get_id_filename(udev_device);
        if (id == NULL)
                return -ENODEV;
        strscpyl(filename, sizeof(filename), UDEV_ROOT_RUN "/udev/data/", id, NULL);

        if (unlink(filename) < 0 && errno != ENOENT)
                return -errno;
        return 0;
}

/* Like device_should_have_db() of systemd: whether udev_device_update_db() writes a database file for
 * the device, rather than removing it. */
bool udev_device_should_have_db(struct udev_device *udev_device)
{
        return device_has_info(udev_device) ||
               major(udev_device_get_devnum(udev_device)) != 0 ||
               udev_device_get_ifindex(udev_device) != 0;
}

/* Like device_has_db() of systemd: whether the database file of the device exists. */
int udev_device_has_db(struct udev_device *udev_device)
{
        const char *id;
        char filename[UTIL_PATH_SIZE];

        id = udev_device_get_id_filename(udev_device);
        if (id == NULL)
                return -ENODEV;
        strscpyl(filename, sizeof(filename), UDEV_ROOT_RUN "/udev/data/", id, NULL);

        return access(filename, F_OK) >= 0;
}

/* Whether the database file of the device has the sticky bit of OPTIONS="db_persist", which
 * udev_device_update_db() sets for a device with udev_device_set_db_persist(). */
int udev_device_db_is_persistent(struct udev_device *udev_device)
{
        const char *id;
        char filename[UTIL_PATH_SIZE];
        struct stat st;

        id = udev_device_get_id_filename(udev_device);
        if (id == NULL)
                return -ENODEV;
        strscpyl(filename, sizeof(filename), UDEV_ROOT_RUN "/udev/data/", id, NULL);

        if (stat(filename, &st) < 0)
                return errno == ENOENT ? false : -errno;

        return (st.st_mode & S_ISVTX) != 0;
}

/* Reads a sysfs attribute. Unlike udev_device_get_sysattr_value(), returns a negative errno-style
 * error code: -ENOENT if the attribute does not exist or cannot be read. */
int device_get_sysattr_value(struct udev_device *device, const char *sysattr, const char **ret)
{
        const char *value;

        assert(device);
        assert(sysattr);

        value = udev_device_get_sysattr_value(device, sysattr);
        if (!value)
                return -ENOENT;

        if (ret)
                *ret = value;
        return 0;
}

bool sysattr_string_is_safe(const char *p)
{
        /* Like systemd's string_is_safe() with STRING_ALLOW_EMPTY, STRING_ALLOW_NEWLINES,
         * STRING_ALLOW_BACKSLASHES, STRING_ALLOW_QUOTES and STRING_ALLOW_GLOBS: the string must be
         * valid UTF-8 and must not contain control characters other than newline. */

        assert(p);

        return utf8_is_valid(p) && !string_has_cc(p, "\n");
}

/* Like device_get_sysattr_value(), but refuses with -ENXIO values that contain control characters
 * other than newline, or invalid UTF-8. Use it for strings that end up in properties, paths or log
 * messages. */
int device_get_sysattr_safe_string(struct udev_device *device, const char *sysattr, const char **ret)
{
        const char *value;
        int r;

        r = device_get_sysattr_value(device, sysattr, &value);
        if (r < 0)
                return r;

        if (!sysattr_string_is_safe(value)) {
                /* like systemd, also with the prefix of sd-device's messages, and the value escaped like
                 * the other values in messages */
                if (log_get_max_level() >= LOG_DEBUG) {
                        _cleanup_free_ char *escaped = utf8_escape_non_printable(value);

                        log_debug("%s: sd-device: '%s' sysattr contains invalid characters, refusing: %s",
                                  udev_device_get_sysname(device), sysattr, escaped ?: "(null)");
                }
                return -ENXIO;
        }

        if (ret)
                *ret = value;
        return 0;
}

/* The following return a negative errno-style error code on failure. On success they return 1 if
 * the value is positive, 0 otherwise. */
int device_get_sysattr_int(struct udev_device *device, const char *sysattr, int *ret)
{
        const char *value;
        int r, v;

        r = device_get_sysattr_value(device, sysattr, &value);
        if (r < 0)
                return r;

        r = safe_atoi(value, &v);
        if (r < 0)
                return log_debug_errno(r, "%s: Failed to parse '%s' attribute: %m",
                                       udev_device_get_sysname(device), sysattr);

        if (ret)
                *ret = v;
        return v > 0;
}

int device_get_sysattr_unsigned_full(struct udev_device *device, const char *sysattr, unsigned base, unsigned *ret)
{
        const char *value;
        unsigned v;
        int r;

        r = device_get_sysattr_value(device, sysattr, &value);
        if (r < 0)
                return r;

        r = safe_atou_full(value, base, &v);
        if (r < 0)
                return log_debug_errno(r, "%s: Failed to parse '%s' attribute: %m",
                                       udev_device_get_sysname(device), sysattr);

        if (ret)
                *ret = v;
        return v > 0;
}

int device_get_sysattr_bool(struct udev_device *device, const char *sysattr)
{
        const char *value;
        int r;

        r = device_get_sysattr_value(device, sysattr, &value);
        if (r < 0)
                return r;

        return parse_boolean(value);
}

int device_get_sysattr_u64(struct udev_device *device, const char *sysattr, uint64_t *ret)
{
        const char *value;
        uint64_t v;
        int r;

        r = device_get_sysattr_value(device, sysattr, &value);
        if (r < 0)
                return r;

        r = safe_atou64(value, &v);
        if (r < 0)
                return log_debug_errno(r, "%s: Failed to parse '%s' attribute: %m",
                                       udev_device_get_sysname(device), sysattr);

        if (ret)
                *ret = v;
        return v > 0;
}

/* Triggers a synthetic uevent of the device with the syspath by writing the action, e.g. "change", to its
 * uevent attribute, with the UUID, unless it is NULL, and then the arguments joined by
 * trigger_args_join(), unless they are NULL. */
static int uevent_trigger_full(const char *syspath, const char *action, const char *uuid, const char *args)
{
        _cleanup_close_ int fd = -1;
        char filename[UTIL_PATH_SIZE];
        const char *s;

        assert(syspath);
        assert(action);
        assert(uuid || !args);

        strscpyl(filename, sizeof(filename), syspath, "/uevent", NULL);
        s = !uuid ? action :
            !args ? strjoina(action, " ", uuid) :
                    strjoina(action, " ", uuid, " ", args);

        fd = open(filename, O_WRONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0)
                return -errno;

        if (write(fd, s, strlen(s)) < 0)
                return -errno;

        return 0;
}

static int uevent_trigger(const char *syspath, const char *action, const char *uuid)
{
        return uevent_trigger_full(syspath, action, uuid, NULL);
}

/* Like the checks of sd_device_trigger_with_args() of systemd 66563e97b7: joins the KEY VALUE pairs of
 * args to "KEY=VALUE KEY=VALUE ...". Returns -EINVAL if their number is odd, or one of them is empty or
 * not alphanumerical, and sets *ret to NULL if there are none. */
static int trigger_args_join(char * const *args, char **ret)
{
        _cleanup_free_ char *joined = NULL;
        char * const *k;

        assert(ret);

        if (strv_length(args) % 2 != 0)
                return -EINVAL;

        /* The kernel requests that both keys and values are alphanumerical. See action_arg_word_end() in
         * lib/kobject_uevent.c and Documentation/ABI/testing/sysfs-uevent in the kernel. */
        STRV_FOREACH(k, args)
                if (isempty(*k) || !in_charset(*k, ALPHANUMERICAL))
                        return -EINVAL;

        for (k = args; k && *k; k += 2) {
                char *t;

                t = joined ? strjoin(joined, " ", k[0], "=", k[1], NULL) : strjoin(k[0], "=", k[1], NULL);
                if (!t)
                        return -ENOMEM;

                free(joined);
                joined = t;
        }

        *ret = TAKE_PTR(joined);
        return 0;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev_monitor *, udev_monitor_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev_device *, udev_device_unref);

/* Like device_path_parse_major_minor() of systemd: the type and the number of a path /dev/block/MAJOR:MINOR or
 * /dev/char/MAJOR:MINOR, without looking at the file system. -ENODEV for other paths. Unlike systemd, there are
 * no synthetic inaccessible device nodes of /run/systemd/inaccessible/. */
static int device_path_parse_major_minor(const char *path, char *ret_type, dev_t *ret_devnum) {
        const char *w;
        dev_t devnum;
        char type;
        int r;

        w = path_startswith(path, "/dev/block/");
        if (w)
                type = 'b';
        else {
                w = path_startswith(path, "/dev/char/");
                if (!w)
                        return -ENODEV;

                type = 'c';
        }

        r = parse_devnum_id(w, &devnum);
        if (r < 0)
                return r;

        *ret_type = type;
        *ret_devnum = devnum;
        return 0;
}

/* Like device_new_from_devname() of systemd's sd-device: finds the device whose device node the path resolves
 * to, below /dev/, e.g. the path of a device node symlink. With strict, as for sd_device_new_from_devname(),
 * the path itself must be below /dev/ too; without, as for sd_device_new_from_path(), it may be any path, also
 * a relative one. Like in systemd, /dev/block/MAJOR:MINOR and /dev/char/MAJOR:MINOR are looked up by the number
 * in the path, also when the path does not exist. Returns -EINVAL if it is not below /dev/, -ENODEV if it does
 * not exist, -ENOTTY if it is not a device node, and the error of udev_device_new_from_devnum() otherwise, e.g.
 * -ENXIO if the device with its number has another number or type. */
static int device_new_from_devname_full(struct udev *udev, const char *devname, bool strict,
                                        struct udev_device **ret) {
        _cleanup_(udev_device_unrefp) struct udev_device *dev = NULL;
        _cleanup_free_ char *resolved = NULL;
        struct stat st;
        dev_t devnum;
        char type;
        int r;

        assert(udev);
        assert(devname);
        assert(ret);

        if (strict && isempty(path_startswith(devname, "/dev/")))
                return -EINVAL;

        /* Like systemd: shortcut when "/dev/block/maj:min" or "/dev/char/maj:min" is specified. In that
         * case, the path is converted to the device directly, hence it is not necessary that the specified
         * path exists. So, this works fine without udevd being running. */
        if (device_path_parse_major_minor(devname, &type, &devnum) >= 0) {
                dev = udev_device_new_from_devnum(udev, type, devnum);
                if (!dev)
                        return errno > 0 ? -errno : -ENODEV;

                *ret = TAKE_PTR(dev);
                return 0;
        }

        /* like chase_and_stat() in systemd, a path with a component longer than NAME_MAX is invalid */
        r = path_check_name_max(devname);
        if (r < 0)
                return r;

        resolved = realpath(devname, NULL);
        if (!resolved)
                return ERRNO_IS_DEVICE_ABSENT(errno) ? -ENODEV : -errno;

        if (isempty(path_startswith(resolved, "/dev/")))
                return -EINVAL;

        if (stat(resolved, &st) < 0)
                return ERRNO_IS_DEVICE_ABSENT(errno) ? -ENODEV : -errno;

        if (!S_ISCHR(st.st_mode) && !S_ISBLK(st.st_mode))
                return -ENOTTY;

        /* Like sd_device_new_from_stat_rdev() of systemd: major 0 fails with ENODEV, and a device with
         * another number or type with ENXIO, see udev_device_new_from_devnum(). */
        dev = udev_device_new_from_devnum(udev, S_ISBLK(st.st_mode) ? 'b' : 'c', st.st_rdev);
        if (!dev)
                return errno > 0 ? -errno : -ENODEV;

        *ret = TAKE_PTR(dev);
        return 0;
}

int device_new_from_devname(struct udev *udev, const char *devname, struct udev_device **ret) {
        return device_new_from_devname_full(udev, devname, /* strict= */ true, ret);
}

int device_new_from_path(struct udev *udev, const char *path, struct udev_device **ret) {
        _cleanup_free_ char *resolved = NULL;
        struct udev_device *dev;

        assert(udev);
        assert(path);
        assert(ret);

        if (device_new_from_devname_full(udev, path, /* strict= */ false, ret) >= 0)
                return 0;

        /* Like device_set_syspath() of systemd, the symlinks of the path are resolved first, so that it may
         * also be a relative path or a symlink, e.g. /sys/class/net/lo. */
        resolved = realpath(path, NULL);
        if (!resolved)
                return ERRNO_IS_DEVICE_ABSENT(errno) ? -ENODEV : -errno;

        if (isempty(path_startswith(resolved, "/sys/")))
                return -ENODEV;

        dev = udev_device_new_from_syspath(udev, resolved);
        if (!dev)
                return errno > 0 ? -errno : -ENODEV;

        *ret = dev;
        return 0;
}

/* Whether the kernel passes the UUID of a synthetic uevent on as SYNTH_UUID=, which it does since Linux 4.13,
 * as found out by uevent_trigger_with_uuid(); -1 as long as it is not known. It is in a shared mapping after
 * uevent_trigger_share_uuid_supported(). It is only read and written with atomic operations, as several
 * processes may probe at the same time, see uevent_trigger_set_uuid_supported(). */
static int synthetic_uuid_supported_private = -1;
static volatile int *synthetic_uuid_supported = &synthetic_uuid_supported_private;

int uevent_trigger_uuid_supported(void)
{
        return __atomic_load_n(synthetic_uuid_supported, __ATOMIC_ACQUIRE);
}

/* Stores the result of a probe of uevent_trigger_with_uuid(), but only while it is not known: the processes that
 * share it, e.g. udevd and its workers, may probe at the same time, e.g. a worker on a disk whose uevents the
 * kernel suppresses and udevd on another device, and then the result that is stored first stays, so that a
 * later negative cannot overwrite a positive. Returns the result that is stored now. */
static int uevent_trigger_set_uuid_supported(int supported)
{
        int expected = -1;

        if (!__atomic_compare_exchange_n(synthetic_uuid_supported, &expected, supported, false,
                                         __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
                return expected;

        return supported;
}

/* Moves the result of the probe of uevent_trigger_with_uuid() to a shared anonymous mapping, so that the
 * process and the child processes it forks afterwards share it: whichever of them finds out first whether the
 * kernel supports UUIDs, the others see the result too, also those forked before it was known. udevd uses it
 * for its workers and its "(udev-synth)" processes, which trigger uevents as well, so that they do not probe
 * again, each of them, which may take a second or two, and keep the result until udevd exits. */
int uevent_trigger_share_uuid_supported(void)
{
        int *p;

        if (synthetic_uuid_supported != &synthetic_uuid_supported_private)
                return 0;

        p = mmap(NULL, sizeof(int), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED)
                return -errno;

        *p = synthetic_uuid_supported_private;
        synthetic_uuid_supported = p;
        return 0;
}

/* How long uevent_trigger_with_uuid() waits for the uevent with the UUID that it triggered first, and then for
 * the uevent that it triggered without the UUID. The kernel sends a synthetic uevent before the write to the
 * uevent attribute returns, so that the uevent is queued on the netlink socket already; the time is only spent
 * when the uevent does not come while other uevents arrive, see uevent_seqnum(). */
#define SYNTHETIC_UUID_PROBE_USEC (1 * USEC_PER_SEC)

/* How often uevent_trigger_with_uuid() looks while it waits whether another process found out meanwhile whether
 * the kernel supports UUIDs, see uevent_trigger_set_uuid_supported(). */
#define SYNTHETIC_UUID_PROBE_CHECK_USEC (10 * USEC_PER_MSEC)

/* The receive buffer of the socket of uevent_trigger_with_uuid(), which gets every uevent of the kernel if the
 * filter of uevent_probe_filter() cannot be attached, so that a flood of uevents, e.g. of a coldplug, does not
 * fill it up while the process does not read, e.g. between binding the socket and triggering the uevent, so that
 * the kernel drops the uevent that the probe waits for (ENOBUFS); the default of net.core.rmem_default (208 KiB)
 * holds about 220 uevents. The kernel doubles the size for its bookkeeping, and every uevent takes about 960 bytes
 * of it, whatever its length, so the 32 MiB hold about 35000 uevents (Linux 7.1.8): about half a second of the
 * fastest flood measured, four processes writing to uevent files with udevd running, about 70000 uevents per
 * second in total (KVM, 2 CPUs), and much longer for a slower one. The buffer only takes memory for the uevents
 * that are queued and not read yet; udevd and udevadm monitor use 128 MiB. Beyond net.core.rmem_max, it needs
 * CAP_NET_ADMIN, see udev_monitor_set_receive_buffer_size(). */
#define SYNTHETIC_UUID_PROBE_RCVBUF (16 * 1024 * 1024)

/* The sequence number of the last uevent that the kernel sent, from /sys/kernel/uevent_seqnum, or UINT64_MAX if
 * it cannot be read. The kernel counts it up for every uevent it sends, and only then, before the write to the
 * uevent attribute that triggered the uevent returns, so when it is the same before and after such a write, the
 * write triggered no uevent at all. */
static uint64_t uevent_seqnum(void)
{
        _cleanup_free_ char *s = NULL;
        uint64_t seqnum;

        if (read_one_line_file("/sys/kernel/uevent_seqnum", &s) < 0 || safe_atou64(s, &seqnum) < 0)
                return UINT64_MAX;

        return seqnum;
}

static bool uevent_seqnum_unchanged(uint64_t before, uint64_t after)
{
        return before != UINT64_MAX && before == after;
}

/* Attaches a socket filter to the socket of the monitor that passes only the uevents of the kernel for the
 * device with the syspath with the action: the kernel starts every uevent message with "ACTION@DEVPATH" and a
 * NUL, which the filter compares, up to 4 bytes at a time, so the other uevents, e.g. of a flood, never reach
 * the socket, and cannot fill its buffer. The filters of udev_monitor_filter_add_match_subsystem_devtype()
 * cannot do that: their socket filter only looks at the messages of udevd, and passes every message of the
 * kernel, whose subsystem is not at a fixed place (systemd installs none for the uevents of the kernel).
 * Returns 0, or a negative errno, e.g. -E2BIG if the path is too long for a socket filter. */
static int uevent_probe_filter(struct udev_monitor *monitor, const char *syspath, const char *action)
{
        _cleanup_free_ struct sock_filter *ins = NULL;
        _cleanup_free_ char *header = NULL;
        struct sock_fprog prog = {};
        const char *devpath;
        const uint8_t *h;
        size_t len, n = 0, i;

        assert(monitor);
        assert(syspath);
        assert(action);

        devpath = startswith(syspath, "/sys");
        if (!devpath || devpath[0] != '/')
                return -EINVAL;

        header = strjoin(action, "@", devpath, NULL);
        if (!header)
                return -ENOMEM;

        /* with the NUL, so that a longer path, e.g. of a partition of the disk, does not match */
        len = strlen(header) + 1;

        /* three instructions for every 4 bytes, for the 2 and the 1 that may be left, and the last */
        if ((len / 4 + 2) * 3 + 1 > BPF_MAXINSNS)
                return -E2BIG;

        ins = new(struct sock_filter, (len / 4 + 2) * 3 + 1);
        if (!ins)
                return -ENOMEM;

        h = (const uint8_t *) header;
        for (i = 0; i < len;) {
                uint32_t value;
                uint16_t size;
                size_t k;

                if (len - i >= 4) {
                        size = BPF_W;
                        k = 4;
                        value = (uint32_t) h[i] << 24 | (uint32_t) h[i + 1] << 16 | (uint32_t) h[i + 2] << 8 | h[i + 3];
                } else if (len - i >= 2) {
                        size = BPF_H;
                        k = 2;
                        value = (uint32_t) h[i] << 8 | h[i + 1];
                } else {
                        size = BPF_B;
                        k = 1;
                        value = h[i];
                }

                /* load the bytes at the offset in network byte order (a message that is shorter is dropped),
                 * and drop the message if they differ */
                ins[n++] = (struct sock_filter) BPF_STMT(BPF_LD|size|BPF_ABS, i);
                ins[n++] = (struct sock_filter) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, value, 1, 0);
                ins[n++] = (struct sock_filter) BPF_STMT(BPF_RET|BPF_K, 0);
                i += k;
        }

        /* the whole header matched, pass the message */
        ins[n++] = (struct sock_filter) BPF_STMT(BPF_RET|BPF_K, 0xffffffff);

        prog.len = n;
        prog.filter = ins;
        if (setsockopt(udev_monitor_get_fd(monitor), SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0)
                return -errno;

        return 0;
}

/* What uevent_trigger_with_uuid() saw of the uevents of the kernel while it waited. */
struct uevent_probe {
        const char *syspath;
        const char *action;
        /* the uevent was triggered again without the UUID; the uevent of that has a sequence number after
         * plain_after, up to plain_until, as far as they are known */
        bool plain_written;
        uint64_t plain_after;
        uint64_t plain_until;
        /* a uevent with SYNTH_UUID= arrived, which kernels since 4.13 add to every synthetic uevent, as
         * SYNTH_UUID=0 if it was triggered without a UUID, and older kernels never add */
        bool synth_uuid_seen;
        /* the uevent triggered without the UUID arrived */
        bool plain_seen;
        /* the socket lost uevents (ENOBUFS), or one could not be read */
        bool lost;
};

static void uevent_probe_check(struct uevent_probe *p, struct udev_device *d)
{
        unsigned long long seqnum;

        assert(p);
        assert(d);

        /* the uevent with the UUID, or any other uevent with SYNTH_UUID=, whoever triggered it: the kernel
         * supports UUIDs */
        if (udev_device_get_property_value(d, "SYNTH_UUID"))
                p->synth_uuid_seen = true;

        if (!p->plain_written ||
            !streq_ptr(udev_device_get_syspath(d), p->syspath) ||
            !streq_ptr(udev_device_get_action(d), p->action))
                return;

        /* not a uevent that the kernel sent for the device before */
        seqnum = udev_device_get_seqnum(d);
        if (seqnum <= p->plain_after || seqnum > p->plain_until)
                return;

        p->plain_seen = true;
}

/* Reads the uevents that arrive on the socket of the monitor until one tells whether the kernel supports UUIDs:
 * a uevent with SYNTH_UUID=, e.g. the one with the UUID, or the uevent triggered without the UUID, once it was
 * written. At the deadline, the uevents that arrived until then are still read, so that a process that was
 * not scheduled for a while does not miss a uevent that is queued already; it stops at the first uevent that
 * the kernel sent after the deadline, so that a flood of uevents does not keep it reading, or, if the sequence
 * number cannot be read, SYNTHETIC_UUID_PROBE_USEC after the deadline. The same is done when the uevent
 * triggered without the UUID arrived: the kernel queued it before the write returned, so when another uevent
 * of the device with the same action came first, e.g. one that the kernel sent on its own at the same time,
 * the own one, which may carry SYNTH_UUID=0, is read too. It also stops when another process that shares the
 * result stored it meanwhile. Returns 0, or a negative errno if poll() failed. */
static int uevent_probe_wait(struct udev_monitor *monitor, struct uevent_probe *p, usec_t deadline)
{
        struct pollfd pfd = {
                .fd = udev_monitor_get_fd(monitor),
                .events = POLLIN,
        };
        uint64_t last = UINT64_MAX;
        bool drain = false;

        assert(monitor);
        assert(p);

        for (;;) {
                _cleanup_(udev_device_unrefp) struct udev_device *d = NULL;
                usec_t n;
                int r;

                if (p->synth_uuid_seen || uevent_trigger_uuid_supported() >= 0)
                        return 0;

                n = now(CLOCK_MONOTONIC);
                if (!drain && (p->plain_seen || n >= deadline)) {
                        drain = true;
                        last = uevent_seqnum();
                }
                if (drain && n >= usec_add(deadline, SYNTHETIC_UUID_PROBE_USEC))
                        return 0;

                r = poll(&pfd, 1, drain ? 0 : (int) DIV_ROUND_UP(MIN(deadline - n, SYNTHETIC_UUID_PROBE_CHECK_USEC),
                                                                 USEC_PER_MSEC));
                if (r < 0) {
                        if (errno == EINTR)
                                continue;
                        return -errno;
                }
                if (r == 0) {
                        if (drain)
                                return 0;
                        continue;
                }

                d = udev_monitor_receive_device(monitor);
                if (!d) {
                        /* e.g. ENOBUFS, when uevents were lost, maybe the one that tells */
                        if (errno != EAGAIN && errno != EINTR)
                                p->lost = true;
                        continue;
                }

                uevent_probe_check(p, d);

                if (drain && last != UINT64_MAX && udev_device_get_seqnum(d) > last)
                        return 0;
        }
}

/* Whether the kernel sends a uevent when one is triggered with the uevent attribute of the kobject with the
 * syspath: not for a device without a subsystem, i.e. without a bus or class (dev_uevent_filter()), and not for a
 * hidden block device, whose "hidden" attribute is 1, e.g. a path device of native NVMe multipath (nvme0c0n1):
 * the kernel suppresses its uevents for good, the write succeeds, but there is no uevent (and there was no "add"
 * either, so udevd does not know the device). Kernels without the attribute cannot tell. Only devices are
 * checked, as the other kobjects with an uevent attribute, e.g. buses, drivers and modules, have no subsystem
 * link, but send uevents. */
bool syspath_sends_uevents(const char *syspath)
{
        _cleanup_free_ char *subsystem = NULL, *hidden = NULL;

        assert(syspath);

        if (!startswith(syspath, "/sys/devices/"))
                return true;

        if (readlink_malloc(strjoina(syspath, "/subsystem"), &subsystem) < 0)
                return access(strjoina(syspath, "/subsystem"), F_OK) >= 0;

        if (!streq(eudev_basename(subsystem), "block"))
                return true;

        return read_one_line_file(strjoina(syspath, "/hidden"), &hidden) < 0 || !streq(hidden, "1");
}

/* Triggers a synthetic uevent of the device with the syspath with the action and the UUID, followed by the
 * arguments joined by trigger_args_join() unless they are NULL, like uevent_trigger_full(), but when the
 * kernel refuses the uevent with ENOMEM, triggers it again without the arguments, and then without the UUID.
 *
 * The kernel builds every uevent in a buffer of UEVENT_BUFFER_SIZE (2048) bytes for at most UEVENT_NUM_ENVP
 * (64) variables: ACTION=, DEVPATH=, SUBSYSTEM=, SYNTH_UUID= (SYNTH_UUID=0 without a UUID), one
 * SYNTH_ARG_KEY=VALUE for every argument, the variables of the device, as in its uevent file, and SEQNUM=.
 * If they do not fit, it sends no uevent, and the write fails with ENOMEM (older kernels accept the write
 * without an error then). The UUID takes 36 bytes more than SYNTH_UUID=0, and the arguments of
 * device_build_default_trigger_args() with the timestamps about 165 bytes and 5 variables, so a device whose
 * uevent is close to the limit, e.g. an input device with a long PHYS string, could get no uevent at all from
 * a trigger with them, while the kernel's own uevent and a trigger with the plain action still work. Unlike
 * systemd 66563e97b7, which then fails, the uevent is triggered again in the smaller form, as the arguments
 * are informational only, and the UUID is only needed to recognize the uevent; the kernel logs its error for
 * the refused write. The space is not estimated beforehand, which would need to read the uevent file of the
 * device for every trigger, and could still be wrong; the kernel knows it. An input device with a MODALIAS
 * that is too long does not fail on recent kernels (e.g. 6.8.12): the kernel cuts it to the space that is
 * left, so the UUID and the arguments make it shorter, as SYNTH_UUID=0 of a plain trigger already does; its
 * beginning, which e.g. the hwdb matches, stays. Returns 1 if the uevent was triggered with the UUID, 0 if
 * it was triggered without it, and a negative errno on failure. */
static int uevent_trigger_fitting(const char *syspath, const char *action, const char *uuid, const char *args)
{
        int r;

        assert(syspath);
        assert(action);

        if (uuid && args) {
                r = uevent_trigger_full(syspath, action, uuid, args);
                if (r != -ENOMEM)
                        return r < 0 ? r : 1;

                log_debug_errno(r, "%s: The kernel refused the uevent with the caller arguments, they may not fit into it, triggering '%s' without them: %m",
                                syspath, action);
        }

        if (uuid) {
                r = uevent_trigger_full(syspath, action, uuid, NULL);
                if (r != -ENOMEM)
                        return r < 0 ? r : 1;

                log_debug_errno(r, "%s: The kernel refused the uevent with the UUID, it may not fit into it, triggering '%s' without it: %m",
                                syspath, action);
        }

        r = uevent_trigger_full(syspath, action, NULL, NULL);
        return r < 0 ? r : 0;
}

/* Triggers a synthetic uevent of the device with the syspath with the action and the UUID, followed by the
 * arguments joined by trigger_args_join() unless they are NULL, as long as the kernel supports UUIDs, and
 * otherwise without both, see uevent_trigger_fitting(). Linux 4.13 brought both, the kernel passes them on
 * as SYNTH_UUID= and SYNTH_ARG_KEY=VALUE. Kernels before 4.13 accept the write of an action with a UUID, log
 * "uevent: unknown action-string", and send no uevent at all, so their missing support cannot be told from
 * the result of the write. So, unlike systemd, which looks at the result of the write, as long as it is not
 * known, the uevent is triggered with the UUID, and the uevents of the kernel are watched: if the uevent with
 * the UUID arrives, the kernel supports UUIDs. If it does not arrive within a second, the uevent is triggered
 * again without the UUID, so that the device gets its uevent, and the uevent of that decides: kernels since
 * 4.13 add SYNTH_UUID=0 to a synthetic uevent without a UUID, older kernels add nothing. Any other uevent with
 * SYNTH_UUID= that arrives meanwhile, triggered by whoever, also shows that the kernel supports UUIDs. When the
 * uevent without the UUID does not arrive either within a second, e.g. as the kernel suppresses the uevents
 * of a disk while add_disk() scans its partitions, or when the socket lost uevents, nothing is decided, and
 * the next call tries again: a missing uevent alone never decides. A decided result is kept for all further
 * calls of the process, and of the processes that share it, see uevent_trigger_share_uuid_supported(); when
 * another of them decides first, the waiting stops, and its result stays, see
 * uevent_trigger_set_uuid_supported(). The waits are skipped when /sys/kernel/uevent_seqnum shows that the
 * write triggered no uevent at all, see uevent_seqnum(). The device gets the uevent with the UUID when the
 * kernel supports UUIDs, and the one without it when it does not, as it would anyway; but when nothing could
 * be decided, it may get none, when the kernel sent none, or both, when the kernel sent the first one, which
 * the socket lost or which did not arrive in time. When the uevents of the kernel cannot be watched, or the
 * kernel refused the uevent with the UUID, the uevent is triggered without the UUID, and the next call tries
 * again. A device that never sends uevents, without a subsystem or a hidden block device, see
 * syspath_sends_uevents(), cannot tell, and is triggered with the UUID, without waiting; the next call tries
 * again. Returns 1 if the uevent was triggered with the UUID, 0 if it was triggered without it, and a negative
 * errno on failure. */
static int uevent_trigger_with_uuid(struct udev *udev, const char *syspath, const char *action,
                                    const char *uuid, const char *args)
{
        _cleanup_(udev_monitor_unrefp) struct udev_monitor *monitor = NULL;
        struct uevent_probe p = {
                .syspath = syspath,
                .action = action,
        };
        uint64_t before, after;
        int r;

        assert(udev);
        assert(syspath);
        assert(action);
        assert(uuid);

        r = uevent_trigger_uuid_supported();
        if (r > 0)
                return uevent_trigger_fitting(syspath, action, uuid, args);

        if (r == 0) {
                r = uevent_trigger(syspath, action, NULL);
                return r < 0 ? r : 0;
        }

        if (!syspath_sends_uevents(syspath))
                return uevent_trigger_fitting(syspath, action, uuid, args);

        /* The socket must be bound before the uevent is triggered. */
        monitor = udev_monitor_new_from_netlink(udev, "kernel");
        if (monitor) {
                (void) udev_monitor_set_receive_buffer_size(monitor, SYNTHETIC_UUID_PROBE_RCVBUF);

                r = uevent_probe_filter(monitor, syspath, action);
                if (r < 0)
                        log_debug_errno(r, "Failed to filter the uevents of the kernel for %s, ignoring: %m", syspath);
        }
        if (!monitor || udev_monitor_enable_receiving(monitor) < 0) {
                log_debug("Failed to watch the uevents of the kernel, triggering '%s' on %s without a UUID.",
                          action, syspath);
                r = uevent_trigger(syspath, action, NULL);
                return r < 0 ? r : 0;
        }

        before = uevent_seqnum();
        r = uevent_trigger_fitting(syspath, action, uuid, args);
        if (r <= 0)
                /* without the UUID, which the kernel refused, its support cannot be told */
                return r;
        after = uevent_seqnum();

        if (!uevent_seqnum_unchanged(before, after)) {
                r = uevent_probe_wait(monitor, &p, usec_add(now(CLOCK_MONOTONIC), SYNTHETIC_UUID_PROBE_USEC));
                if (r < 0)
                        log_debug_errno(r, "Failed to wait for the uevent with UUID %s, ignoring: %m", uuid);
        }

        if (p.synth_uuid_seen) {
                if (uevent_trigger_set_uuid_supported(1) > 0)
                        log_debug("The kernel supports UUIDs of synthetic uevents.");
                return 1;
        }

        /* Another process found out meanwhile: the uevent was triggered with the UUID, or there was none. */
        r = uevent_trigger_uuid_supported();
        if (r > 0)
                return 1;
        if (r == 0) {
                r = uevent_trigger(syspath, action, NULL);
                return r < 0 ? r : 0;
        }

        /* The uevent with the UUID did not come: the kernel does not support UUIDs, or sent no uevent for the
         * device, or the socket lost it. The device gets its uevent without the UUID, which tells. */
        before = uevent_seqnum();
        r = uevent_trigger(syspath, action, NULL);
        if (r < 0)
                return r;
        after = uevent_seqnum();

        p.plain_written = true;
        p.plain_after = before != UINT64_MAX && after != UINT64_MAX ? before : 0;
        p.plain_until = before != UINT64_MAX && after != UINT64_MAX ? after : UINT64_MAX;

        if (!uevent_seqnum_unchanged(before, after)) {
                r = uevent_probe_wait(monitor, &p, usec_add(now(CLOCK_MONOTONIC), SYNTHETIC_UUID_PROBE_USEC));
                if (r < 0)
                        log_debug_errno(r, "Failed to wait for the uevent of %s without a UUID, ignoring: %m", syspath);
        }

        if (p.synth_uuid_seen) {
                if (uevent_trigger_set_uuid_supported(1) > 0)
                        log_debug("The kernel supports UUIDs of synthetic uevents, but the uevent with UUID %s of %s did not arrive, triggered '%s' without a UUID.",
                                  uuid, syspath, action);
                return 0;
        }

        if (uevent_trigger_uuid_supported() >= 0)
                /* another process found out meanwhile */
                return 0;

        if (p.plain_seen && !p.lost) {
                if (uevent_trigger_set_uuid_supported(0) == 0)
                        log_debug("The kernel does not support UUIDs of synthetic uevents (its synthetic uevents carry no SYNTH_UUID=, as before Linux 4.13), triggering uevents without them.");
                return 0;
        }

        log_debug("Could not find out whether the kernel supports UUIDs of synthetic uevents, %s, triggered '%s' on %s without a UUID, trying again with the next uevent.",
                  p.lost ? "uevents were lost" : "no uevent of the device arrived", action, syspath);
        return 0;
}

/* Like sd_device_trigger_with_args() of systemd 66563e97b7: triggers a synthetic uevent of the device with
 * the syspath with the action, e.g. "change", a random UUID, and the arguments, which are KEY VALUE pairs,
 * unless args is NULL, see uevent_trigger_with_uuid(). The kernel passes the arguments on as
 * SYNTH_ARG_KEY=VALUE. Returns 1 if the uevent was triggered with the UUID, which is then stored in ret_uuid
 * unless it is NULL, with or without the arguments, 0 if it was triggered without the UUID and the
 * arguments, as the kernel does not support them, or refused the uevent with them, and ret_uuid is set to
 * the empty string, and a negative errno on failure, e.g. -EINVAL if the arguments are not KEY VALUE pairs of
 * alphanumerical words. */
int uevent_trigger_with_args(struct udev *udev, const char *syspath, const char *action, char * const *args,
                             char *ret_uuid)
{
        _cleanup_free_ char *joined = NULL;
        char uuid[ID128_UUID_STRING_MAX];
        id128_t id;
        int r;

        assert(udev);
        assert(syspath);
        assert(action);

        r = trigger_args_join(args, &joined);
        if (r < 0)
                return r;

        id128_randomize(&id);
        id128_to_uuid_string(id, uuid);

        r = uevent_trigger_with_uuid(udev, syspath, action, uuid, joined);
        if (r < 0)
                return r;

        if (ret_uuid)
                strcpy(ret_uuid, r > 0 ? uuid : "");
        return r;
}

int device_trigger_with_args(struct udev_device *device, const char *action, char * const *args, char *ret_uuid)
{
        const char *syspath;

        assert(device);
        assert(action);

        syspath = udev_device_get_syspath(device);
        if (!syspath)
                return -ENODEV;

        return uevent_trigger_with_args(udev_device_get_udev(device), syspath, action, args, ret_uuid);
}

static int strv_extend_pair(char ***l, const char *key, const char *value)
{
        int r;

        r = strv_extend(l, key);
        if (r < 0)
                return r;

        return strv_extend(l, value);
}

/* Like get_arg0_or_comm() of systemd b1df918307: the name of the program, argv[0] without its directory, or
 * the comm of the process if that is empty, with the characters that are not alphanumerical removed, as the
 * kernel only accepts those, e.g. "systemd-udevd" becomes "systemdudevd". Unlike systemd, which reads argv[0]
 * from /proc/self/cmdline, it is program_invocation_short_name, which is the same as eudev does not change its
 * argv. */
static int get_arg0_or_comm(char **ret)
{
        _cleanup_free_ char *comm = NULL;
        char *p, *q;
        int r;

        assert(ret);

        /* comm may be truncated, let's use argv[0] if possible. */
        if (!isempty(program_invocation_short_name)) {
                comm = strdup(program_invocation_short_name);
                if (!comm)
                        return -ENOMEM;
        } else {
                r = get_process_comm(0, &comm);
                if (r < 0)
                        return r;
        }

        /* The kernel only accepts alphanumerical. Drop unsupported characters. */
        for (p = q = comm; *p != '\0'; p++)
                if (strchr(ALPHANUMERICAL, *p))
                        *q++ = *p;
        *q = '\0';

        if (isempty(comm))
                return -ENOENT;

        *ret = TAKE_PTR(comm);
        return 0;
}

/* Like append_timestamp() of systemd b1df918307: appends TimestampRealtime, TimestampMonotonic and
 * TimestampBoottime with the current times in microseconds to the KEY VALUE pairs of args. On failure, args
 * may be left with a part of them, so the callers discard it then. */
static int append_timestamp(char ***args)
{
        char buf[DECIMAL_STR_MAX(usec_t)];
        usec_t realtime, monotonic, boottime;
        int r;

        assert(args);

        if (strv_length(*args) % 2 != 0)
                return -EINVAL;

        realtime = now(CLOCK_REALTIME);
        monotonic = now(CLOCK_MONOTONIC);
        boottime = now(CLOCK_BOOTTIME);

        xsprintf(buf, USEC_FMT, realtime);
        r = strv_extend_pair(args, "TimestampRealtime", buf);
        if (r < 0)
                return r;

        xsprintf(buf, USEC_FMT, monotonic);
        r = strv_extend_pair(args, "TimestampMonotonic", buf);
        if (r < 0)
                return r;

        xsprintf(buf, USEC_FMT, boottime);
        return strv_extend_pair(args, "TimestampBoottime", buf);
}

/* Like device_build_default_trigger_args() of systemd b1df918307: the arguments for uevent_trigger_with_args()
 * that tell which process triggered the uevent: its PID, its name (Comm), unless it has none, and, with
 * with_timestamp, the current time. Unlike systemd, there is no PIDFDID, the inode number of the pidfd of the
 * process, as eudev has no helpers for pidfds, and no InvocationID, the ID of the service of systemd that runs
 * the process, which means nothing without systemd. */
int device_build_default_trigger_args(bool with_timestamp, char ***ret)
{
        _cleanup_strv_free_ char **args = NULL;
        _cleanup_free_ char *comm = NULL;
        char buf[DECIMAL_STR_MAX(pid_t)];
        int r;

        assert(ret);

        xsprintf(buf, PID_FMT, getpid());
        r = strv_extend_pair(&args, "PID", buf);
        if (r < 0)
                return r;

        if (get_arg0_or_comm(&comm) >= 0) {
                r = strv_extend_pair(&args, "Comm", comm);
                if (r < 0)
                        return r;
        }

        if (with_timestamp) {
                r = append_timestamp(&args);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(args);
        return 0;
}

/* Like device_trigger_with_timestamp() of systemd b1df918307: device_trigger_with_args() with args, which
 * must not contain timestamps, and the current time appended to them. */
int device_trigger_with_timestamp(struct udev_device *device, const char *action, char * const *args,
                                  char *ret_uuid)
{
        _cleanup_strv_free_ char **copy = NULL;
        int r;

        assert(device);

        /* This assumes the input args does not contain timestamps. */

        copy = strv_copy(args);
        if (!copy)
                return -ENOMEM;

        r = append_timestamp(&copy);
        if (r < 0)
                return r;

        return device_trigger_with_args(device, action, copy, ret_uuid);
}

int device_get_sysnum_unsigned(struct udev_device *device, unsigned *ret)
{
        const char *s;
        unsigned n;
        int r;

        s = udev_device_get_sysnum(device);
        if (!s)
                return -ENOENT;

        r = safe_atou_full(s, SAFE_ATO_REFUSE_PLUS_MINUS | SAFE_ATO_REFUSE_LEADING_WHITESPACE | 10, &n);
        if (r < 0)
                return r;

        if (ret)
                *ret = n;
        return 0;
}
