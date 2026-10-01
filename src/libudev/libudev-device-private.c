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
#include <sys/stat.h>
#include <sys/sysmacros.h>

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

/* Like sd_device_trigger_with_uuid() of systemd: triggers a synthetic uevent of the device with the action,
 * e.g. "change", by writing it to the uevent attribute, with the UUID, unless it is NULL. The kernel passes
 * the UUID on as SYNTH_UUID= since Linux 4.13; older kernels log an error and send no uevent at all, see
 * uevent_trigger_with_uuid(). */
int device_trigger(struct udev_device *device, const char *action, const char *uuid)
{
        const char *syspath;

        assert(device);
        assert(action);

        syspath = udev_device_get_syspath(device);
        if (!syspath)
                return -ENODEV;

        return uevent_trigger(syspath, action, uuid);
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
 * as found out by uevent_trigger_with_uuid(); -1 as long as it is not known. */
static int synthetic_uuid_supported = -1;

/* How long uevent_trigger_with_uuid() waits for the uevent with the UUID that it triggered first. The kernel
 * sends a synthetic uevent before the write to the uevent attribute returns, so that the uevent is queued on
 * the netlink socket already; the time is only spent on kernels without UUIDs. */
#define SYNTHETIC_UUID_PROBE_USEC (1 * USEC_PER_SEC)

/* Whether the kernel sends a uevent when one is triggered with the uevent attribute of the kobject with the
 * syspath: not for a device without a subsystem, i.e. without a bus or class (dev_uevent_filter()). Only devices
 * are checked, as the other kobjects with an uevent attribute, e.g. buses, drivers and modules, have no subsystem
 * link, but send uevents. */
bool syspath_sends_uevents(const char *syspath)
{
        assert(syspath);

        if (!startswith(syspath, "/sys/devices/"))
                return true;

        return access(strjoina(syspath, "/subsystem"), F_OK) >= 0;
}

/* Triggers a synthetic uevent of the device with the syspath, like device_trigger() with the UUID, followed by
 * the arguments joined by trigger_args_join() unless they are NULL, as long as the kernel supports UUIDs, and
 * otherwise without both; Linux 4.13 brought both, the kernel passes them on as SYNTH_UUID= and
 * SYNTH_ARG_KEY=VALUE. Kernels before 4.13 accept the write of an action with
 * a UUID, log "uevent: unknown action-string", and send no uevent at all, so their missing support cannot be
 * told from the result of the write. So, unlike systemd, which looks at the result of the write, the first
 * call of the process triggers the uevent with the UUID on the device, and watches the uevents of the kernel
 * for it, for at most a second: if it does not arrive, the uevent is triggered again without the UUID, and all
 * further calls trigger their uevents without UUIDs. Apart from the time on such old kernels, this has no
 * side effects: the device gets exactly the uevent it would get anyway. When the uevents of the kernel cannot
 * be watched, the uevent is triggered without the UUID, and the next call tries again. A device without a
 * subsystem, i.e. without a bus or class, never sends uevents, so it cannot tell, and is triggered with the
 * UUID, without waiting; the next call tries again. Returns 1 if the uevent was triggered with the UUID, 0 if
 * it was triggered without it, and a negative errno on failure. */
static int uevent_trigger_with_uuid(struct udev *udev, const char *syspath, const char *action,
                                    const char *uuid, const char *args)
{
        _cleanup_(udev_monitor_unrefp) struct udev_monitor *monitor = NULL;
        usec_t deadline;
        int r;

        assert(udev);
        assert(syspath);
        assert(action);
        assert(uuid);

        if (synthetic_uuid_supported > 0) {
                r = uevent_trigger_full(syspath, action, uuid, args);
                return r < 0 ? r : 1;
        }

        if (synthetic_uuid_supported == 0) {
                r = uevent_trigger(syspath, action, NULL);
                return r < 0 ? r : 0;
        }

        if (!syspath_sends_uevents(syspath)) {
                r = uevent_trigger_full(syspath, action, uuid, args);
                return r < 0 ? r : 1;
        }

        /* The socket must be bound before the uevent is triggered. */
        monitor = udev_monitor_new_from_netlink(udev, "kernel");
        if (!monitor || udev_monitor_enable_receiving(monitor) < 0) {
                log_debug("Failed to watch the uevents of the kernel, triggering '%s' on %s without a UUID.",
                          action, syspath);
                r = uevent_trigger(syspath, action, NULL);
                return r < 0 ? r : 0;
        }

        r = uevent_trigger_full(syspath, action, uuid, args);
        if (r < 0)
                return r;

        deadline = usec_add(now(CLOCK_MONOTONIC), SYNTHETIC_UUID_PROBE_USEC);
        for (;;) {
                _cleanup_(udev_device_unrefp) struct udev_device *d = NULL;
                struct pollfd pfd = {
                        .fd = udev_monitor_get_fd(monitor),
                        .events = POLLIN,
                };
                usec_t n;

                n = now(CLOCK_MONOTONIC);
                if (n >= deadline)
                        break;

                r = poll(&pfd, 1, (deadline - n + USEC_PER_MSEC - 1) / USEC_PER_MSEC);
                if (r < 0) {
                        if (errno == EINTR)
                                continue;
                        /* the uevent was triggered with the UUID, but it is not known if the kernel
                         * supports it, so try again next time */
                        return log_debug_errno(errno, "Failed to wait for the uevent with UUID %s: %m", uuid);
                }
                if (r == 0)
                        break;

                d = udev_monitor_receive_device(monitor);
                if (d && streq_ptr(udev_device_get_property_value(d, "SYNTH_UUID"), uuid)) {
                        synthetic_uuid_supported = 1;
                        return 1;
                }
        }

        synthetic_uuid_supported = 0;
        log_debug("The kernel does not support UUIDs of synthetic uevents (Linux 4.13 or newer is needed), triggering uevents without them.");

        r = uevent_trigger(syspath, action, NULL);
        return r < 0 ? r : 0;
}

/* Like sd_device_trigger_with_args() of systemd 66563e97b7: triggers a synthetic uevent of the device with
 * the syspath with the action, e.g. "change", a random UUID, and the arguments, which are KEY VALUE pairs,
 * unless args is NULL, see uevent_trigger_with_uuid(). The kernel passes the arguments on as
 * SYNTH_ARG_KEY=VALUE. Returns 1 if the uevent was triggered with the UUID, which is then stored in ret_uuid
 * unless it is NULL, 0 if it was triggered without the UUID and the arguments, as the kernel does not
 * support them, and ret_uuid is set to the empty string, and a negative errno on failure, e.g. -EINVAL
 * if the arguments are not KEY VALUE pairs of alphanumerical words. */
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
