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
#include <dirent.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/utsname.h>
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
        log_device_debug(udev_device, "not writing invalid or too long %s: entry '%s' to the db, ignoring",
                         key, escaped ?: "");
        return false;
}

int udev_device_update_db(struct udev_device *udev_device)
{
        _cleanup_free_ char *lesc1 = NULL, *lesc2 = NULL;
        _cleanup_free_ char *filename_tmp = NULL;
        bool has_info;
        const char *id;
        char filename[UTIL_PATH_SIZE];
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

        /* Write a database file. Like systemd, which uses fopen_temporary(), through a temporary file with a
         * unique name in the same directory, ".#<id>" and six random characters, which is renamed over the
         * database file: two workers may write the entry of the same device at once, e.g. for events of the
         * device that arrived out of order, and with a fixed name one of them would write into the file of
         * the other, and then fail to rename it, as the other renamed it already. */
        r = mkdir_parents(filename, 0755);
        if (r < 0) {
                log_debug_errno(r, "unable to create the parent directories of '%s': %m",
                                utf8_escape_for_log(filename, &lesc1));
                goto fail;
        }
        r = fopen_temporary(filename, &f, &filename_tmp);
        if (r < 0) {
                log_debug_errno(r, "unable to create temporary db file for '%s': %m",
                                utf8_escape_for_log(filename, &lesc1));
                goto fail;
        }

        /*
         * the temporary file is created with mode 0600; like systemd, set the mode of the database
         * file, with the 'sticky' bit to indicate that we should not clean the database when we
         * transition from initramfs to the real root
         */
        if (fchmod(fileno(f), udev_device_get_db_persist(udev_device) ? 01644 : 0644) < 0) {
                r = log_debug_errno(errno, "unable to chmod temporary db file '%s': %m",
                                    utf8_escape_for_log(filename_tmp, &lesc1));
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
                r = log_debug_errno(errno > 0 ? errno : EIO, "unable to write temporary db file '%s': %m",
                                    utf8_escape_for_log(filename_tmp, &lesc1));
                goto fail;
        }
        r = fclose(f);
        f = NULL;
        if (r != 0) {
                r = log_debug_errno(errno, "unable to write temporary db file '%s': %m",
                                    utf8_escape_for_log(filename_tmp, &lesc1));
                goto fail;
        }
        if (rename(filename_tmp, filename) < 0) {
                r = log_debug_errno(errno, "unable to rename temporary db file '%s' to '%s': %m",
                                    utf8_escape_for_log(filename_tmp, &lesc1), utf8_escape_for_log(filename, &lesc2));
                goto fail;
        }
        log_debug("created %s file '%s' for '%s'", has_info ? "db" : "empty",
             utf8_escape_for_log(filename, &lesc1), utf8_escape_for_log(udev_device_get_devpath(udev_device), &lesc2));
        return 0;

fail:
        /* Like systemd, do not leave the old database file behind when it cannot be updated. */
        if (f != NULL)
                fclose(f);
        if (filename_tmp)
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
                /* like systemd, with the prefix of the library, "libudev:" where systemd has "sd-device:",
                 * and the value escaped like the other values in messages */
                if (log_get_max_level() >= LOG_DEBUG) {
                        _cleanup_free_ char *escaped = utf8_escape_non_printable(value);

                        log_device_debug(device, "libudev: '%s' sysattr contains invalid characters, refusing: %s",
                                         sysattr, escaped ?: "(null)");
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
        _cleanup_free_ char *lesc1 = NULL;
        const char *value;
        int r, v;

        r = device_get_sysattr_value(device, sysattr, &value);
        if (r < 0)
                return r;

        r = safe_atoi(value, &v);
        if (r < 0)
                return log_device_debug_errno(device, r, "Failed to parse '%s' attribute: %m",
                                              utf8_escape_for_log(sysattr, &lesc1));

        if (ret)
                *ret = v;
        return v > 0;
}

int device_get_sysattr_unsigned_full(struct udev_device *device, const char *sysattr, unsigned base, unsigned *ret)
{
        _cleanup_free_ char *lesc1 = NULL;
        const char *value;
        unsigned v;
        int r;

        r = device_get_sysattr_value(device, sysattr, &value);
        if (r < 0)
                return r;

        r = safe_atou_full(value, base, &v);
        if (r < 0)
                return log_device_debug_errno(device, r, "Failed to parse '%s' attribute: %m",
                                              utf8_escape_for_log(sysattr, &lesc1));

        if (ret)
                *ret = v;
        return v > 0;
}

int device_get_sysattr_u16_full(struct udev_device *device, const char *sysattr, unsigned base, uint16_t *ret)
{
        _cleanup_free_ char *lesc1 = NULL;
        const char *value;
        uint16_t v;
        int r;

        r = device_get_sysattr_value(device, sysattr, &value);
        if (r < 0)
                return r;

        r = safe_atou16_full(value, base, &v);
        if (r < 0)
                return log_device_debug_errno(device, r, "Failed to parse '%s' attribute: %m",
                                              utf8_escape_for_log(sysattr, &lesc1));

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
        _cleanup_free_ char *lesc1 = NULL;
        const char *value;
        uint64_t v;
        int r;

        r = device_get_sysattr_value(device, sysattr, &value);
        if (r < 0)
                return r;

        r = safe_atou64(value, &v);
        if (r < 0)
                return log_device_debug_errno(device, r, "Failed to parse '%s' attribute: %m",
                                              utf8_escape_for_log(sysattr, &lesc1));

        if (ret)
                *ret = v;
        return v > 0;
}

/* Like device_property_can_set() of systemd, the same names: ENV{} assignments of them are refused when the
 * rules are read, and the imports and the builtins skip them, see udev-rules.c and udev_builtin_add_property(). */
bool device_property_can_set(const char *property)
{
        return property &&
                !STR_IN_SET(property,
                            /* basic properties set by kernel, only in netlink event */
                            "ACTION", "SEQNUM", "SYNTH_UUID",
                            /* basic properties set by kernel, both in netlink event and uevent file */
                            "DEVPATH", "DEVPATH_OLD", "SUBSYSTEM", "DEVTYPE", "DRIVER", "MODALIAS",
                            /* device node */
                            "DEVNAME", "DEVMODE", "DEVUID", "DEVGID", "MAJOR", "MINOR",
                            /* block device */
                            "DISKSEQ", "PARTN",
                            /* network interface (INTERFACE_OLD is set by udevd) */
                            "IFINDEX", "INTERFACE", "INTERFACE_OLD",
                            /* basic properties set by udevd */
                            "DEVLINKS", "TAGS", "CURRENT_TAGS", "USEC_INITIALIZED", "UDEV_DATABASE_VERSION") &&
                /* Similar to SYNTH_UUID, but set based on KEY=VALUE arguments passed by userspace.
                 * See kernel's f36776fafbaa0094390dd4e7e3e29805e0b82730 (v4.13) */
                !startswith(property, "SYNTH_ARG_");
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

/* A version of the kernel, as kernel_version() returns it. */
#define KERNEL_VERSION_CODE(major, minor, patch) ((int) ((major) << 24 | (minor) << 16 | (patch)))
#define KERNEL_VERSION_CODE_MAX KERNEL_VERSION_CODE(0x7fu, 0xffu, 0xffffu)

/* The version of the running kernel, from the release that uname() returns, as KERNEL_VERSION_CODE(), where a
 * missing patch level counts as 0, or -EINVAL if the release does not start with a version. Distributions often
 * put another number there, e.g. Debian's "4.19.0-21-amd64" for 4.19.249, so the version can be older than the
 * code that runs, but not newer; the checks below then take the side of the older kernel. The release does not
 * change, so it is parsed only once in a process, and the child processes that it starts after that, e.g. the
 * workers of udevd, inherit the result. */
static int kernel_version(void)
{
        /* 0 as long as it is not parsed */
        static int version = 0;
        unsigned major, minor, patch = 0;
        struct utsname u;
        int v;

        v = __atomic_load_n(&version, __ATOMIC_RELAXED);
        if (v != 0)
                return v;

        if (uname(&u) >= 0 && sscanf(u.release, "%u.%u.%u", &major, &minor, &patch) >= 2 &&
            major > 0 && major <= 0x7f && minor <= 0xff)
                v = KERNEL_VERSION_CODE(major, minor, MIN(patch, 0xffffu));
        else
                v = -EINVAL;
        __atomic_store_n(&version, v, __ATOMIC_RELAXED);

        return v;
}

/* Whether the version of the running kernel is in one of the n ranges, each from its first version up to before
 * its second one; false if the version cannot be parsed. */
static bool kernel_version_in(const int (*ranges)[2], size_t n)
{
        int v;

        v = kernel_version();
        if (v < 0)
                return false;

        for (size_t i = 0; i < n; i++)
                if (v >= ranges[i][0] && v < ranges[i][1])
                        return true;

        return false;
}

/* Whether the running kernel reports Linux 4.13 or newer, which supports UUIDs of synthetic uevents, so that
 * uevent_trigger_with_uuid() needs no probe, like eudev before the probe (b3a70f99f). A kernel that reports an
 * older version may have the support backported, so it is probed, as is one whose version cannot be parsed. */
static bool kernel_version_supports_uuid(void)
{
        return kernel_version() >= KERNEL_VERSION_CODE(4, 13, 0);
}

/* Whether the running kernel may accept the write of a synthetic uevent that it refused, without reporting an
 * error, see uevent_trigger_fitting(). Since Linux f36776fafbaa ("kobject: support passing in variables for
 * synthetic uevents"), 4.13, the uevent attributes ignore the result of kobject_synth_uevent(), as they ignored
 * that of kobject_action_type() before, until Linux df44b479654f ("kobject: return error code if writing
 * /sys/.../uevent fails"), 5.0, which the stable releases 4.14.99, 4.19.21 and 4.20.8 got too, but not 4.15 to
 * 4.18. So it may for a version before 4.14.99, which before 4.13 gets here only with the UUIDs backported, from
 * 4.15 to before 4.19.21, and from 4.20 to before 4.20.8, and for one that cannot be parsed. */
static bool kernel_may_refuse_uevent_silently(void)
{
        static const int silent[][2] = {
                { 0,                             KERNEL_VERSION_CODE(4, 14, 99) },
                { KERNEL_VERSION_CODE(4, 15, 0), KERNEL_VERSION_CODE(4, 19, 21) },
                { KERNEL_VERSION_CODE(4, 20, 0), KERNEL_VERSION_CODE(4, 20, 8)  },
        };

        return kernel_version() < 0 || kernel_version_in(silent, ELEMENTSOF(silent));
}

/* The file in which uevent_trigger_with_uuid() keeps a decided result of its probe for the rest of the boot, on
 * kernels that report a version before 4.13, see uevent_uuid_cache_read(). */
#define UEVENT_UUID_CACHE_DIR UDEV_ROOT_RUN "/udev"
#define UEVENT_UUID_CACHE_NAME "uevent-uuid-support"
#define UEVENT_UUID_CACHE UEVENT_UUID_CACHE_DIR "/" UEVENT_UUID_CACHE_NAME

/* The boot ID and the release of the running kernel, which a result in UEVENT_UUID_CACHE must match. */
static int uevent_uuid_cache_key(char **ret_boot_id, char **ret_release)
{
        _cleanup_free_ char *boot_id = NULL, *release = NULL;
        struct utsname u;
        int r;

        assert(ret_boot_id);
        assert(ret_release);

        r = read_one_line_file("/proc/sys/kernel/random/boot_id", &boot_id);
        if (r < 0)
                return r;
        if (isempty(boot_id))
                return -EINVAL;

        if (uname(&u) < 0)
                return -errno;

        release = strdup(u.release);
        if (!release)
                return -ENOMEM;

        *ret_boot_id = TAKE_PTR(boot_id);
        *ret_release = TAKE_PTR(release);
        return 0;
}

/* Reads the result of an earlier probe from UEVENT_UUID_CACHE: 1 if the kernel supports UUIDs, 0 if it does not,
 * or a negative errno if there is none, e.g. -ENOENT, or it is of another boot or another kernel release, which
 * can only be when /run is not a tmpfs (-ESTALE), or it cannot be parsed (-EBADMSG), or it cannot be read; see
 * uevent_trigger_with_uuid() for the messages. The probe runs once per boot then,
 * instead of once in every udevadm run and in every udevd, which matters on kernels before 4.13, where it waits
 * for a uevent that never comes, see uevent_trigger_with_uuid(). The file is written only by root, as
 * UDEV_ROOT_RUN/udev is. */
static int uevent_uuid_cache_read(void)
{
        _cleanup_free_ char *contents = NULL, *boot_id = NULL, *release = NULL;
        const char *file_boot_id = NULL, *file_release = NULL, *file_supported = NULL;
        char *line, *state = NULL;
        int r;

        r = read_full_file(UEVENT_UUID_CACHE, &contents, NULL);
        if (r < 0)
                return r;

        for (line = strtok_r(contents, "\n", &state); line; line = strtok_r(NULL, "\n", &state)) {
                const char *v;

                if ((v = startswith(line, "BOOT_ID=")))
                        file_boot_id = v;
                else if ((v = startswith(line, "RELEASE=")))
                        file_release = v;
                else if ((v = startswith(line, "SUPPORTED=")))
                        file_supported = v;
        }

        if (!file_boot_id || !file_release || !file_supported || !STR_IN_SET(file_supported, "0", "1"))
                return -EBADMSG;

        r = uevent_uuid_cache_key(&boot_id, &release);
        if (r < 0)
                return r;

        if (!streq(file_boot_id, boot_id) || !streq(file_release, release))
                return -ESTALE;

        return streq(file_supported, "1");
}

/* Removes the temporary files of uevent_uuid_cache_write() that a process left behind when it was killed between
 * creating one and renaming it, ".#uevent-uuid-support" and six more characters, see tempfn_xxxxxx(). Another
 * process that writes the file at the same time loses its temporary file then, and keeps its result to itself,
 * see uevent_trigger_decide_uuid_supported(). */
static void uevent_uuid_cache_remove_leftovers(void)
{
        _cleanup_free_ char *lesc1 = NULL;
        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;
        int dfd;

        d = opendir(UEVENT_UUID_CACHE_DIR);
        if (!d)
                return;
        dfd = dirfd(d);
        assert(dfd >= 0);

        while ((de = readdir(d))) {
                const char *suffix = startswith(de->d_name, ".#" UEVENT_UUID_CACHE_NAME);

                if (!suffix || strlen(suffix) != 6)
                        continue;

                if (unlinkat(dfd, de->d_name, 0) < 0)
                        log_debug_errno(errno, "Failed to remove leftover temporary file %s/%s, ignoring: %m",
                                        UEVENT_UUID_CACHE_DIR, utf8_escape_for_log(de->d_name, &lesc1));
                else
                        log_debug("Removed leftover temporary file %s/%s.",
                                  UEVENT_UUID_CACHE_DIR, utf8_escape_for_log(de->d_name, &lesc1));
        }
}

/* Writes a decided result of the probe to UEVENT_UUID_CACHE, atomically: a temporary file in the same directory,
 * renamed over it; leftover temporary files of earlier writes are removed before. Fails, e.g. with ENOENT or
 * EROFS, when UDEV_ROOT_RUN/udev does not exist or is read-only, or with EACCES when not run by root; it is not
 * created here, the result is then kept only in the process and the processes that share it, see
 * uevent_trigger_share_uuid_supported(). */
static int uevent_uuid_cache_write(int supported)
{
        _cleanup_free_ char *boot_id = NULL, *release = NULL, *contents = NULL, *temp = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        r = uevent_uuid_cache_key(&boot_id, &release);
        if (r < 0)
                return r;

        contents = strjoin("# Whether the kernel supports UUIDs of synthetic uevents, found out by eudev,\n"
                           "# see udevadm(8)\n"
                           "BOOT_ID=", boot_id, "\n"
                           "RELEASE=", release, "\n"
                           "SUPPORTED=", supported > 0 ? "1" : "0", "\n", NULL);
        if (!contents)
                return -ENOMEM;

        uevent_uuid_cache_remove_leftovers();

        r = fopen_temporary(UEVENT_UUID_CACHE, &f, &temp);
        if (r < 0)
                return r;

        (void) fchmod(fileno(f), 0644);
        r = write_string_stream(f, contents);
        if (r >= 0 && rename(temp, UEVENT_UUID_CACHE) < 0)
                r = -errno;
        if (r < 0)
                (void) unlink(temp);
        return r;
}

/* Stores a decided result of the probe, and keeps it in UEVENT_UUID_CACHE, unless another process stored another
 * one meanwhile. */
static bool uevent_trigger_decide_uuid_supported(int supported)
{
        int r;

        if (uevent_trigger_set_uuid_supported(supported) != supported)
                return false;

        r = uevent_uuid_cache_write(supported);
        if (r < 0)
                log_debug_errno(r, "Failed to keep whether the kernel supports UUIDs of synthetic uevents in %s, ignoring: %m",
                                UEVENT_UUID_CACHE);
        return true;
}

/* Moves the result of the probe of uevent_trigger_with_uuid() to a shared anonymous mapping, so that the
 * process and the child processes it forks afterwards share it: whichever of them finds out first whether the
 * kernel supports UUIDs, the others see the result too, also those forked before it was known. udevd uses it
 * for its workers and its "(udev-synth)" processes, which trigger uevents as well, so that they do not probe
 * again, each of them, which may take a second or two on kernels that report a version before 4.13, and keep
 * the result until udevd exits. */
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
 * write triggered no uevent at all, see uevent_seqnum_unchanged(). */
uint64_t uevent_seqnum(void)
{
        _cleanup_free_ char *s = NULL;
        uint64_t seqnum;

        if (read_one_line_file("/sys/kernel/uevent_seqnum", &s) < 0 || safe_atou64(s, &seqnum) < 0)
                return UINT64_MAX;

        return seqnum;
}

/* Whether the sequence numbers of uevent_seqnum() read before and after a write to an uevent attribute show that
 * the kernel sent no uevent for it, e.g. as it suppresses the uevents of a disk while add_disk() scans its
 * partitions, or of a hidden block device, see syspath_sends_uevents(). False when the number could not be read
 * before. */
bool uevent_seqnum_unchanged(uint64_t before, uint64_t after)
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

/* Whether the running kernel keeps the uevents of a hidden block device suppressed for good: since Linux
 * 9ec491447b90 ("block: Suppress uevent for hidden device when removed"), 5.12, which the stable releases
 * 5.11.11, 5.10.27, 5.4.109 and 4.19.184 got too. Before, since Linux 8ddcd653257c ("block: introduce
 * GENHD_FL_HIDDEN"), 4.15, register_disk() lifted the suppression of a hidden disk without sending "add", so a
 * synthetic uevent of it is sent. A release that cannot be parsed counts as one that sends them: when it does not,
 * uevent_seqnum() shows that a trigger sent nothing. */
static bool kernel_suppresses_hidden_disks(void)
{
        static const int suppressed[][2] = {
                { KERNEL_VERSION_CODE(4, 19, 184), KERNEL_VERSION_CODE(4, 20, 0) },
                { KERNEL_VERSION_CODE(5, 4, 109),  KERNEL_VERSION_CODE(5, 5, 0)  },
                { KERNEL_VERSION_CODE(5, 10, 27),  KERNEL_VERSION_CODE(5, 11, 0) },
                { KERNEL_VERSION_CODE(5, 11, 11),  KERNEL_VERSION_CODE_MAX       },
        };

        return kernel_version_in(suppressed, ELEMENTSOF(suppressed));
}

/* Whether the kernel sends a uevent when one is triggered with the uevent attribute of the kobject with the
 * syspath: not for a device without a subsystem, i.e. without a bus or class (dev_uevent_filter()), and not for a
 * hidden block device, whose "hidden" attribute is 1, e.g. a path device of native NVMe multipath (nvme0c0n1), on
 * a kernel that keeps its uevents suppressed for good, see kernel_suppresses_hidden_disks(): the write succeeds,
 * but there is no uevent (and there was no "add" either, so udevd does not know the device). Kernels without the
 * attribute cannot tell. Only devices are checked, as the other kobjects with an uevent attribute, e.g. buses,
 * drivers and modules, have no subsystem link, but send uevents. */
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

        return read_one_line_file(strjoina(syspath, "/hidden"), &hidden) < 0 || !streq(hidden, "1") ||
               !kernel_suppresses_hidden_disks();
}

/* The size of the buffer in which the kernel builds a uevent, UEVENT_BUFFER_SIZE of the kernel. */
#define KERNEL_UEVENT_BUFFER_SIZE 2048U

/* The number of variables that fit into a uevent, UEVENT_NUM_ENVP of the kernel: 32, and 64 since Linux
 * 655078f5f528 ("kobject: increase allowed number of uevent variables"), 5.8, which no stable series got; 32 for a
 * release that cannot be parsed. */
static size_t kernel_uevent_num_envp(void)
{
        return kernel_version() >= KERNEL_VERSION_CODE(5, 8, 0) ? 64 : 32;
}

/* Whether the input subsystem of the running kernel cuts keys out of the MODALIAS= of an input device that does
 * not fit into the buffer of a uevent, so that the rest of it fits, marked with "+,", instead of failing with
 * ENOMEM, without a warning, which makes the kernel refuse the uevent: since Linux 0774d19038c4 ("Input: try
 * trimming too long modalias strings"), 6.10, which the stable releases 4.19.317, 5.4.279, 5.10.221, 5.15.162,
 * 6.1.95, 6.6.33, 6.8.12 and 6.9.3 got too. Since then, MODALIAS= also leaves UEVENT_ENV_EXTRA_LEN, 96 bytes, free
 * behind it, for SEQNUM= and the variables of a uevent helper; before, a MODALIAS= that fits, but leaves too little
 * room for SEQNUM=, makes add_uevent_var() fail for SEQNUM=, with a warning, and the kernel refuse the uevent. A
 * release that cannot be parsed counts as one that does not cut it. */
static bool kernel_trims_input_modalias(void)
{
        static const int trims[][2] = {
                { KERNEL_VERSION_CODE(4, 19, 317), KERNEL_VERSION_CODE(4, 20, 0) },
                { KERNEL_VERSION_CODE(5, 4, 279),  KERNEL_VERSION_CODE(5, 5, 0)  },
                { KERNEL_VERSION_CODE(5, 10, 221), KERNEL_VERSION_CODE(5, 11, 0) },
                { KERNEL_VERSION_CODE(5, 15, 162), KERNEL_VERSION_CODE(5, 16, 0) },
                { KERNEL_VERSION_CODE(6, 1, 95),   KERNEL_VERSION_CODE(6, 2, 0)  },
                { KERNEL_VERSION_CODE(6, 6, 33),   KERNEL_VERSION_CODE(6, 7, 0)  },
                { KERNEL_VERSION_CODE(6, 8, 12),   KERNEL_VERSION_CODE(6, 9, 0)  },
                { KERNEL_VERSION_CODE(6, 9, 3),    KERNEL_VERSION_CODE_MAX       },
        };

        return kernel_version_in(trims, ELEMENTSOF(trims));
}

/* The room that UEVENT_ENV_EXTRA_LEN of the kernel keeps free behind the MODALIAS= of an input device, see
 * input_modalias_trimmed(). */
#define KERNEL_INPUT_UEVENT_ENV_EXTRA_LEN 96U

/* Whether the kernel cuts keys out of the MODALIAS= of the input device whose uevent file has the contents of the
 * size, rather than refusing a uevent in which it does not fit, and the number of bytes that it can cut, in
 * ret_cuttable. MODALIAS= is "input:b<bus>v<vendor>p<product>e<version>-e<bits>k<bits>r<bits>a<bits>...", each bit
 * as a hexadecimal number in upper case and a comma, and the last variable of input_dev_uevent() in
 * drivers/input/input.c. A kernel that trims it, see kernel_trims_input_modalias(), adds it only when it is shorter
 * than what is left of the buffer less UEVENT_ENV_EXTRA_LEN (96) bytes, which cover SEQNUM= and the variables of a
 * uevent helper that come after it, and otherwise cuts keys off the end of the part from "k" up to "r", down to
 * "k+,", when the rest fits then (input_print_modalias_parts()); so it can cut all of that part but three bytes.
 * Keys that already end with "+," show that the kernel cuts them, whatever version it reports, e.g. a
 * distribution's kernel with a stable release that is newer than its version. Other kernels cut nothing, and keep
 * nothing free. */
static bool input_modalias_trimmed(const char *contents, size_t size, size_t *ret_cuttable)
{
        const char *p, *end = NULL, *dash, *k = NULL, *r = NULL;

        assert(contents);
        assert(ret_cuttable);

        *ret_cuttable = 0;

        for (p = contents; p < contents + size; p = end + 1) {
                end = memchr(p, '\n', contents + size - p);
                if (!end)
                        end = contents + size;
                if ((size_t) (end - p) > STRLEN("MODALIAS=input:") && startswith(p, "MODALIAS=input:"))
                        break;
        }
        if (p >= contents + size)
                return false;

        dash = memchr(p, '-', end - p);
        if (dash)
                k = memchr(dash, 'k', end - dash);
        if (k)
                r = memchr(k, 'r', end - k);

        if (!kernel_trims_input_modalias() && !(r && r - k > 3 && r[-2] == '+' && r[-1] == ','))
                return false;

        if (r && r - k > 3)
                *ret_cuttable = r - k - 3;
        return true;
}

/* Whether reading the uevent file of a device of the subsystem can take long, as the uevent() function of the
 * kernel for it asks the hardware, or waits for a lock that is held while the driver does: the one of the class of
 * a power supply, power_supply_uevent() in drivers/power/supply/power_supply_sysfs.c, gets the value of each of its
 * properties from the driver, e.g. from a battery over I2C, SMBus or ACPI, or with HID reports, and the one of the
 * device type of a remote control receiver, rc_dev_uevent() in drivers/media/rc/rc-main.c, takes the lock of the
 * device, which lirc_transmit() holds while the driver sends an infrared signal (tx_ir()), and rc_open() while it
 * opens the device. The uevent() functions of the other subsystems use what the kernel knows already, or locks that
 * are seldom held for long. */
static bool subsystem_uevent_may_be_slow(const char *subsystem)
{
        return STR_IN_SET(subsystem, "power_supply", "rc");
}

/* Whether uevent_show() in drivers/base/core.c, which fills the uevent file of a device, takes the lock of the
 * device (device_lock()) in some release of the series of the running kernel, so that a read of the file waits while
 * the lock is held, e.g. for as long as a driver probes the device, which can take minutes, or while it is unbound:
 * since Linux c0a40097f0bc ("drivers: core: synchronize really_probe() and dev_uevent()"), 6.10, until Linux
 * 15fffc6a5624 ("driver core: Fix uevent_show() vs driver detach race"), 6.11, again since its revert, Linux
 * 9a71892cbcdb, 6.12, until the revert of the first one, Linux dc1771f71854, 6.15, and in releases of the stable
 * series 4.19, 5.4, 5.10, 5.15, 6.1, 6.6, 6.9 and 6.11, which got them. Not 6.7 and 6.8, whose last releases,
 * 6.7.12 (2024-04-03) and 6.8.12 (2024-05-30), came before c0a40097f0bc was merged, in 6.10-rc4 (2024-06-16), and
 * backported, from 6.9.6, 6.6.35 and 6.1.95 (2024-06-21) on. The release that uname() returns does not tell the
 * stable release on some distributions, e.g. Debian's "6.1.0-NN-amd64" for 6.1.NNN, so the whole series counts, by
 * its major and minor version only. A release that cannot be parsed does not count. */
static bool kernel_uevent_show_may_lock_device(void)
{
        static const int locked[][2] = {
                { KERNEL_VERSION_CODE(4, 19, 0), KERNEL_VERSION_CODE(4, 20, 0) },
                { KERNEL_VERSION_CODE(5, 4, 0),  KERNEL_VERSION_CODE(5, 5, 0)  },
                { KERNEL_VERSION_CODE(5, 10, 0), KERNEL_VERSION_CODE(5, 11, 0) },
                { KERNEL_VERSION_CODE(5, 15, 0), KERNEL_VERSION_CODE(5, 16, 0) },
                { KERNEL_VERSION_CODE(6, 1, 0),  KERNEL_VERSION_CODE(6, 2, 0)  },
                { KERNEL_VERSION_CODE(6, 6, 0),  KERNEL_VERSION_CODE(6, 7, 0)  },
                { KERNEL_VERSION_CODE(6, 9, 0),  KERNEL_VERSION_CODE(6, 15, 0) },
        };

        return kernel_version_in(locked, ELEMENTSOF(locked));
}

/* The number of variables that power_supply_uevent() of a kernel before Linux 5.8 adds at most for the power supply
 * with the syspath, without reading its uevent file: POWER_SUPPLY_NAME=, and POWER_SUPPLY_<PROPERTY>= for each
 * property of the driver whose value it gets. Each property of the driver has a readable attribute file of its
 * name in the directory of the device, and "type" is always there (power_supply_attr_is_visible()), as are the
 * attributes that the driver adds itself; so one variable per readable file but "uevent", and one, are at least
 * as many as it adds. dev_uevent() adds nothing else for a power supply there: it has no device number, its
 * device type has no name, it has no driver, and the power supply core keeps its devicetree node in psy->of_node,
 * not in the device. From Linux 5.8, it adds POWER_SUPPLY_TYPE= on top, and later kernels more, but those take up
 * to 64 variables. This bounds the number of the variables only, not their bytes, which cannot be told without the
 * values: a power supply with long string properties, e.g. its model name, manufacturer and serial number, can still
 * overflow the buffer with the UUID and the arguments, which makes the kernel log a warning and refuse the uevent
 * with ENOMEM, as power_supply_uevent() is the last uevent() function for it, and the uevent is then triggered again
 * in the smaller form, see uevent_trigger_fitting(). */
static int power_supply_uevent_vars_max(const char *syspath, size_t *ret)
{
        _cleanup_closedir_ DIR *d = NULL;
        size_t n = 1;
        int dfd;

        assert(syspath);
        assert(ret);

        d = opendir(syspath);
        if (!d)
                return negative_errno();
        dfd = dirfd(d);
        assert(dfd >= 0);

        for (;;) {
                struct dirent *de;
                struct stat st;

                errno = 0;
                de = readdir(d);
                if (!de) {
                        if (errno > 0)
                                return negative_errno();
                        break;
                }

                if (de->d_name[0] == '.' || streq(de->d_name, "uevent") || !IN_SET(de->d_type, DT_REG, DT_UNKNOWN))
                        continue;
                /* the attributes of sysfs show their values only when they are read */
                if (fstatat(dfd, de->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0)
                        continue;
                if (S_ISREG(st.st_mode) && (st.st_mode & 0444) != 0)
                        n++;
        }

        *ret = n;
        return 0;
}

/* What uevent_room_of_device() tells about the room that a synthetic uevent of a device takes in the buffer of the
 * kernel without the variables of the caller. */
struct uevent_room {
        /* the number of its variables, and of their bytes, each with its NUL, with all keys of the MODALIAS= of an
         * input device */
        size_t vars, bytes;
        /* the bytes that the kernel can cut out of the keys of the MODALIAS= of an input device, see
         * input_modalias_trimmed() */
        size_t cuttable;
        /* whether they are counted as the kernel counts them, for an input device on a kernel that cuts keys out
         * of its MODALIAS=, rather than with room to spare */
        bool exact;
        /* whether only the variables are counted, at most, for a power supply before Linux 5.8, see
         * power_supply_uevent_vars_max() */
        bool vars_only;
};

/* The room in the buffer of the kernel that a synthetic uevent of the device with the syspath and the action takes
 * without the variables of the caller, SYNTH_UUID= and SYNTH_ARG_*, see uevent_trigger_fitting(). The variables of
 * the device are those of its uevent file, which the kernel fills with the same uevent() function of the kset of
 * the device as the uevent, on an empty buffer (uevent_show() in drivers/base/core.c). Around them,
 * kobject_uevent_env() in lib/kobject_uevent.c adds ACTION=, DEVPATH= and SUBSYSTEM= before, and SEQNUM= after
 * them, and, when a uevent helper is set in /sys/kernel/uevent_helper, HOME=, PATH= and the subsystem as the
 * argument of the helper, after it sent the uevent. For an input device on a kernel that cuts keys out of its
 * MODALIAS=, see input_modalias_trimmed(), they are counted as the kernel counts them: MODALIAS= fits when the
 * variables up to it leave more than the 96 bytes free that cover the rest, and the keys that the kernel can cut
 * are told apart, which only the UUID may cost, see uevent_trigger_fitting(). Otherwise SEQNUM= is counted with the
 * largest number, and a variable and 96 bytes are kept to spare, for variables of the device that change until the
 * write, e.g. DRIVER=. The uevent file of a power supply or a remote control receiver is not read, see
 * subsystem_uevent_may_be_slow(); for a power supply before Linux 5.8, which allows only 32 variables, they are
 * counted at most, see power_supply_uevent_vars_max(), and not their bytes. On the kernel series in which the read
 * of a uevent file may wait for the lock of the device, no uevent file is read, and only that bound of a power
 * supply is counted, see kernel_uevent_show_may_lock_device() and uevent_trigger_fitting(). Returns 0, or a
 * negative errno if the room cannot be told, e.g. -EACCES for the uevent files of buses, drivers and modules, which
 * cannot be read, -ENOENT for a kobject without one, e.g. /sys/bus/<bus>/drivers, -ENODATA for an empty one, e.g.
 * of an LED, which has no variables, or of a device whose uevent() fails, and -EOPNOTSUPP for a device whose uevent
 * file is not read, e.g. a power supply from Linux 5.8 and a remote control receiver, whose uevents are small, and
 * any other device on those kernel series. */
static int uevent_room_of_device(const char *syspath, const char *action, struct uevent_room *ret)
{
        _cleanup_free_ char *contents = NULL, *subsystem = NULL, *helper = NULL;
        struct uevent_room room = {};
        const char *devpath, *name;
        bool with_helper;
        size_t size;
        int r, k;

        assert(syspath);
        assert(action);
        assert(ret);

        devpath = startswith(syspath, "/sys");
        if (!devpath || devpath[0] != '/')
                return -EINVAL;

        /* the subsystem first, for power supplies; buses, drivers and modules have none */
        r = readlink_malloc(strjoina(syspath, "/subsystem"), &subsystem);
        if (r >= 0 && subsystem_uevent_may_be_slow(eudev_basename(subsystem))) {
                size_t n;

                if (!streq(eudev_basename(subsystem), "power_supply") || kernel_uevent_num_envp() > 32)
                        return -EOPNOTSUPP;

                k = power_supply_uevent_vars_max(syspath, &n);
                if (k < 0)
                        return k;

                with_helper = read_one_line_file("/sys/kernel/uevent_helper", &helper) >= 0 && !isempty(helper);

                /* ACTION=, DEVPATH=, SUBSYSTEM=, its own, SEQNUM= and those of a helper */
                *ret = (struct uevent_room) {
                        .vars = 3 + n + 1 + (with_helper ? 2 : 0),
                        .vars_only = true,
                };
                return 0;
        }

        /* On the kernel series in which a read of the uevent file may wait for the lock of the device, the file is
         * not read, and only the bound of a power supply above is counted, which reads none. */
        if (kernel_uevent_show_may_lock_device())
                return -EOPNOTSUPP;

        with_helper = read_one_line_file("/sys/kernel/uevent_helper", &helper) >= 0 && !isempty(helper);

        k = read_full_file(strjoina(syspath, "/uevent"), &contents, &size);
        if (k < 0)
                return k;
        if (size == 0)
                return -ENODATA;

        if (r < 0)
                return r;
        name = eudev_basename(subsystem);

        /* a variable per line, with its NUL in place of the newline */
        for (size_t i = 0; i < size; i++)
                if (contents[i] == '\n')
                        room.vars++;
        room.bytes = size;
        if (contents[size - 1] != '\n') {
                room.vars++;
                room.bytes++;
        }

        if (streq(name, "input"))
                room.exact = input_modalias_trimmed(contents, size, &room.cuttable);

        /* ACTION=, DEVPATH=, SUBSYSTEM= and SEQNUM= */
        room.vars += 4;
        room.bytes += STRLEN("ACTION=") + strlen(action) + 1 +
                      STRLEN("DEVPATH=") + strlen(devpath) + 1 +
                      STRLEN("SUBSYSTEM=") + strlen(name) + 1;
        if (with_helper)
                room.vars += 2;

        if (room.exact)
                /* the value of MODALIAS= has to be shorter than the room left less UEVENT_ENV_EXTRA_LEN, so the
                 * variables up to it can take all of the buffer but that and a byte; SEQNUM= and the variables of a
                 * helper, at most 28 + 7 + 35 + 6 bytes, fit into it */
                room.bytes += KERNEL_INPUT_UEVENT_ENV_EXTRA_LEN + 1;
        else {
                room.bytes += STRLEN("SEQNUM=18446744073709551615") + 1;
                if (with_helper)
                        room.bytes += STRLEN("HOME=/") + 1 + STRLEN("PATH=/sbin:/bin:/usr/sbin:/usr/bin") + 1 +
                                      strlen(name) + 1;
                room.vars++;
                room.bytes += 96;
        }

        *ret = room;
        return 0;
}

/* The room that the arguments joined by trigger_args_join() take in a uevent, as SYNTH_ARG_KEY=VALUE each. */
static void trigger_args_room(const char *args, size_t *ret_vars, size_t *ret_bytes)
{
        size_t vars = 0, bytes = 0;

        assert(args);

        for (const char *p = args; *p; ) {
                size_t n = strcspn(p, " ");

                if (n > 0) {
                        vars++;
                        bytes += STRLEN("SYNTH_ARG_") + n + 1;
                }
                p += n;
                p += strspn(p, " ");
        }

        *ret_vars = vars;
        *ret_bytes = bytes;
}

/* One write of uevent_trigger_fitting(): like uevent_trigger_full(), but with check_sent, -ENODATA when the
 * write succeeded although /sys/kernel/uevent_seqnum, read before and after it, shows that the kernel sent no
 * uevent at all, see uevent_seqnum_unchanged(). */
static int uevent_trigger_fitting_one(const char *syspath, const char *action, const char *uuid, const char *args,
                                      bool check_sent)
{
        uint64_t before;
        int r;

        before = check_sent ? uevent_seqnum() : UINT64_MAX;

        r = uevent_trigger_full(syspath, action, uuid, args);
        if (r < 0)
                return r;

        if (check_sent && uevent_seqnum_unchanged(before, uevent_seqnum()))
                return -ENODATA;

        return 0;
}

/* Triggers a synthetic uevent of the device with the syspath with the action and the UUID, followed by the
 * arguments joined by trigger_args_join() unless they are NULL, like uevent_trigger_full(), but leaves the
 * arguments, and then the UUID, out when the uevent would not fit into the buffer of the kernel with them, and
 * when the kernel refuses the uevent with ENOMEM, triggers it again without the arguments, and then without the
 * UUID.
 *
 * The kernel builds every uevent in a buffer of KERNEL_UEVENT_BUFFER_SIZE (2048) bytes for at most UEVENT_NUM_ENVP
 * variables, 32, and 64 since Linux 5.8, see kernel_uevent_num_envp(): ACTION=, DEVPATH=, SUBSYSTEM=, SYNTH_UUID=
 * (SYNTH_UUID=0 without a UUID), one SYNTH_ARG_KEY=VALUE for every argument, the variables of the device, as in
 * its uevent file, and SEQNUM=, in this order (kobject_uevent_env() in lib/kobject_uevent.c), so the variables of
 * the caller come before those of the device. What happens when they do not fit depends on where the room runs
 * out: add_uevent_var() logs a warning with a backtrace for every variable that does not fit (and panics with
 * panic_on_warn), and dev_uevent() in drivers/base/core.c ignores its failures for MAJOR=, MINOR=, DEVNAME=,
 * DEVMODE=, DEVUID=, DEVGID=, DEVTYPE=, DRIVER= and the OF_* variables, and those of the uevent() functions of the
 * bus and the class of the device when a later one succeeds: then the kernel sends the uevent without those
 * variables of the device, and the write succeeds. When the last of those functions fails, or SEQNUM= does not
 * fit, it sends no uevent, and the write fails with ENOMEM, unless the kernel does not report it, see below; the
 * sequence number is taken before SEQNUM= is added, so it changes then although no uevent was sent. The input
 * subsystem prints the values of its bitmaps, e.g. KEY=, and of MODALIAS= into the buffer itself, behind their
 * names, and fails with ENOMEM, without a warning, when they do not fit; as input_dev_uevent() is the last uevent()
 * function of an input device, the kernel then refuses the uevent as a whole, and no variable is lost
 * (input_add_uevent_bm_var() and input_add_uevent_modalias_var() in drivers/input/input.c, the same in 4.19.316,
 * 5.10.220, 6.1.94 and 6.9.2). Since Linux 6.10, and in some stable releases, it cuts keys out of a MODALIAS= that
 * does not fit instead, marked with "+,", see kernel_trims_input_modalias(). The UUID takes 36 bytes more than
 * SYNTH_UUID=0, and the arguments of device_build_default_trigger_args() with the timestamps about 165 bytes and 5
 * variables, so a device whose variables come close to the limit, e.g. an input device with a long PHYS string or
 * many keys, could lose some of them, or get no uevent at all, from a trigger with them, while the kernel's own
 * uevent and a trigger with the plain action still work. So the room that the uevent of the device takes is read
 * from its uevent file first, see uevent_room_of_device(), and the arguments, and then the UUID, are only written
 * when they fit, as the arguments are informational only, and the UUID is only needed to recognize the uevent. On
 * the kernels that cut keys out of the MODALIAS= of an input device, the UUID may cost it keys at its end, which the
 * kernel marks, as the callers wait for the uevent with the UUID, but no other variables; the arguments are only
 * written when they fit with all its keys. For a power supply before Linux 5.8, only an upper bound of its variables
 * is counted, see power_supply_uevent_vars_max(). When the room cannot be told, e.g. for a power supply since Linux
 * 5.8 or a remote control receiver, see subsystem_uevent_may_be_slow(), they are written, with a debug message only
 * when that is not expected, and when the kernel refuses the uevent with ENOMEM, unlike systemd 66563e97b7, which
 * then fails, it is triggered again in the smaller form; when a uevent helper is set, and the variables that the
 * kernel adds for it after it sent the uevent do not fit, the kernel reports ENOMEM too, and the device gets the
 * uevent a second time from that.
 *
 * On the kernel series in which some release takes the lock of the device to fill its uevent file, see
 * kernel_uevent_show_may_lock_device(), no uevent file is read, and only the variables of a power supply before
 * Linux 5.8 are counted, from its attribute files: a read would wait there for as long as a driver probes or
 * releases the device, which can take minutes, in every trigger, and in the main process of udevd, which triggers
 * the change uevents of watched devices (synthesize_change_one()) and re-reads partition tables when it cannot fork,
 * or cannot allocate the struct reread of the re-read, so that it would handle no uevents meanwhile; it looks up a
 * watched device without reading its uevent file too, see udev_watch_lookup(). The write itself does not take the
 * lock (uevent_store() calls kobject_synth_uevent() without it). There, the arguments and the UUID are written as
 * before, but for a power supply that may not fit with them, and the retries below handle what does not fit, with
 * the messages of the kernel: a large input device makes the kernel refuse the uevent with the arguments, and maybe
 * with the UUID, without a warning, also on the releases whose input subsystem cuts MODALIAS=, where the arguments
 * may also cost it keys at the end of its MODALIAS=; another device whose variables come close to the limit may lose
 * some of them, with a warning.
 *
 * Linux 4.13 to 4.20, before the stable releases 4.14.99, 4.19.21 and 4.20.8, accept such a write without an
 * error, although they sent no uevent, see kernel_may_refuse_uevent_silently(). With check_sent, which the caller
 * passes when the kernel supports UUIDs and may refuse a uevent that way (when it is not known whether the kernel
 * supports UUIDs, the probe of uevent_trigger_with_uuid() deals with a write that sent nothing),
 * /sys/kernel/uevent_seqnum is read before and after the write with the UUID, and if it did not change, the
 * kernel sent no uevent at all, and the smaller form is triggered as for ENOMEM, unless the device never sends
 * uevents, see syspath_sends_uevents(). That costs two reads of the file for a write, and a write or two more
 * for a device whose uevents the kernel suppresses for the moment, e.g. a disk while add_disk() scans its
 * partitions, which get no uevent from them either; if the kernel stops suppressing them meanwhile, the device
 * gets the smaller uevent. If any other uevent was sent between the two reads, e.g. of another device, the
 * number changed, and a write that the kernel refused that way is not noticed, as before. On the other kernels,
 * which report the refusal, the file is not read, and a write that sent nothing, e.g. for a device whose uevents
 * the kernel suppresses, is not repeated: the kernel never reports an error for a uevent that it drops because
 * the device suppresses its uevents (kobj->uevent_suppress), the filter of its kset rejects it, e.g. a device
 * without a bus and a class, or it has no subsystem.
 * Returns 1 if the uevent was triggered with the UUID, 0 if it was triggered without it, and a negative errno
 * on failure. */
static int uevent_trigger_fitting(const char *syspath, const char *action, const char *uuid, const char *args,
                                  bool check_sent)
{
        _cleanup_free_ char *lesc1 = NULL, *lesc2 = NULL;
        int r;

        assert(syspath);
        assert(action);

        if (uuid) {
                struct uevent_room room;

                r = uevent_room_of_device(syspath, action, &room);
                if (r < 0) {
                        /* no message for an empty uevent file, the uevent files of buses, drivers and modules, a
                         * kobject without one, and the devices whose uevent files are not read, see
                         * uevent_room_of_device() */
                        if (!IN_SET(r, -ENODATA, -EACCES, -ENOENT, -EOPNOTSUPP))
                                log_debug_errno(r, "%s: Failed to read the variables of the device, not checking whether the uevent fits into the buffer of the kernel with the UUID and the caller arguments: %m",
                                                utf8_escape_for_log(syspath, &lesc1));
                } else if (room.vars_only) {
                        size_t max_vars = kernel_uevent_num_envp();

                        room.vars++;

                        if (args) {
                                size_t avars, abytes;

                                trigger_args_room(args, &avars, &abytes);
                                if (room.vars + avars > max_vars) {
                                        log_debug("%s: The uevent of the power supply could have more variables than fit into the buffer of the kernel with the caller arguments (up to %zu of %zu), triggering '%s' without them.",
                                                  utf8_escape_for_log(syspath, &lesc1), room.vars + avars, max_vars,
                                                  utf8_escape_for_log(action, &lesc2));
                                        args = NULL;
                                }
                        }

                        if (room.vars > max_vars) {
                                log_debug("%s: The uevent of the power supply could have more variables than fit into the buffer of the kernel with the UUID (up to %zu of %zu), triggering '%s' without it.",
                                          utf8_escape_for_log(syspath, &lesc1), room.vars, max_vars,
                                          utf8_escape_for_log(action, &lesc2));
                                uuid = NULL;
                                args = NULL;
                        }
                } else {
                        size_t max_vars = kernel_uevent_num_envp();
                        const char *how_args, *how_uuid;

                        how_args = how_uuid = "with room to spare";
                        if (room.exact && room.cuttable > 0) {
                                how_args = "as the kernel counts them, with all keys of MODALIAS=";
                                how_uuid = "as the kernel counts them, without the keys it can cut out of MODALIAS=";
                        } else if (room.exact)
                                how_args = how_uuid = "as the kernel counts them";

                        room.vars++;
                        room.bytes += STRLEN("SYNTH_UUID=") + strlen(uuid) + 1;

                        /* the arguments only when they fit with all keys of MODALIAS= */
                        if (args) {
                                size_t avars, abytes;

                                trigger_args_room(args, &avars, &abytes);
                                if (room.vars + avars > max_vars ||
                                    room.bytes + abytes > KERNEL_UEVENT_BUFFER_SIZE) {
                                        log_debug("%s: The uevent would not fit into the buffer of the kernel with the caller arguments (%zu of %zu variables, %zu of %u bytes, %s), triggering '%s' without them.",
                                                  utf8_escape_for_log(syspath, &lesc1), room.vars + avars, max_vars,
                                                  room.bytes + abytes, KERNEL_UEVENT_BUFFER_SIZE, how_args,
                                                  utf8_escape_for_log(action, &lesc2));
                                        args = NULL;
                                }
                        }

                        /* the UUID also when the kernel has to cut keys out of MODALIAS= for it */
                        if (room.vars > max_vars || room.bytes - room.cuttable > KERNEL_UEVENT_BUFFER_SIZE) {
                                log_debug("%s: The uevent would not fit into the buffer of the kernel with the UUID (%zu of %zu variables, %zu of %u bytes, %s), triggering '%s' without it.",
                                          utf8_escape_for_log(syspath, &lesc1), room.vars, max_vars,
                                          room.bytes - room.cuttable, KERNEL_UEVENT_BUFFER_SIZE, how_uuid,
                                          utf8_escape_for_log(action, &lesc2));
                                uuid = NULL;
                                args = NULL;
                        }
                }
        }

        if (uuid && args) {
                r = uevent_trigger_fitting_one(syspath, action, uuid, args, check_sent);
                if (r == -ENODATA && !syspath_sends_uevents(syspath))
                        return 1;
                if (!IN_SET(r, -ENOMEM, -ENODATA))
                        return r < 0 ? r : 1;

                if (r == -ENOMEM)
                        log_debug_errno(r, "%s: The kernel refused the uevent with the caller arguments, they may not fit into it, triggering '%s' without them: %m",
                                        utf8_escape_for_log(syspath, &lesc1), utf8_escape_for_log(action, &lesc2));
                else
                        log_debug("%s: The kernel sent no uevent with the caller arguments, it may have refused it without saying so, as they may not fit into it, or it suppresses the uevents of the device, triggering '%s' without them.",
                                  utf8_escape_for_log(syspath, &lesc1), utf8_escape_for_log(action, &lesc2));
        }

        if (uuid) {
                r = uevent_trigger_fitting_one(syspath, action, uuid, NULL, check_sent);
                if (r == -ENODATA && !syspath_sends_uevents(syspath))
                        return 1;
                if (!IN_SET(r, -ENOMEM, -ENODATA))
                        return r < 0 ? r : 1;

                if (r == -ENOMEM)
                        log_debug_errno(r, "%s: The kernel refused the uevent with the UUID, it may not fit into it, triggering '%s' without it: %m",
                                        utf8_escape_for_log(syspath, &lesc1), utf8_escape_for_log(action, &lesc2));
                else
                        log_debug("%s: The kernel sent no uevent with the UUID, it may have refused it without saying so, as it may not fit into it, or it suppresses the uevents of the device, triggering '%s' without it.",
                                  utf8_escape_for_log(syspath, &lesc1), utf8_escape_for_log(action, &lesc2));
        }

        r = uevent_trigger_full(syspath, action, NULL, NULL);
        return r < 0 ? r : 0;
}

/* Triggers a synthetic uevent of the device with the syspath with the action and the UUID, followed by the
 * arguments joined by trigger_args_join() unless they are NULL, as long as the kernel supports UUIDs, and
 * otherwise without both, see uevent_trigger_fitting(). Linux 4.13 brought both, the kernel passes them on as
 * SYNTH_UUID= and SYNTH_ARG_KEY=VALUE. Kernels before 4.13 accept the write of an action with a UUID, log "uevent:
 * unknown action-string", and send no uevent at all, so their missing support cannot be told from the result of
 * the write. A kernel that reports Linux 4.13 or newer is known to support them, see
 * kernel_version_supports_uuid(). On one that reports an older version, which may have the support backported,
 * unlike systemd, which looks at the result of the write, as long as it is not known, the uevent is triggered with
 * the UUID, and the uevents of the kernel are watched: if the uevent with the UUID arrives, the kernel supports
 * UUIDs. If it does not arrive within a second, the uevent is triggered again without the UUID, so that the device
 * gets its uevent, and the uevent of that decides: kernels since 4.13 add SYNTH_UUID=0 to a synthetic uevent
 * without a UUID, older kernels add nothing. Any other uevent with SYNTH_UUID= that arrives meanwhile, triggered
 * by whoever, also shows that the kernel supports UUIDs. When the uevent without the UUID does not arrive either
 * within a second, e.g. as the kernel suppresses the uevents of a disk while add_disk() scans its partitions, or
 * when the socket lost uevents, nothing is decided, and the next call tries again: a missing uevent alone never
 * decides. A decided result is kept for all further calls of the process, and of the processes that share it, see
 * uevent_trigger_share_uuid_supported(); when another of them decides first, the waiting stops, and its result
 * stays, see uevent_trigger_set_uuid_supported(). It is also kept in UEVENT_UUID_CACHE for the rest of the boot,
 * see uevent_uuid_cache_read(), so that later processes, e.g. the next udevadm runs and a restarted udevd, use it
 * instead of probing again; an undecided probe keeps nothing there. The waits are skipped when
 * /sys/kernel/uevent_seqnum shows that the write triggered no uevent at all, see uevent_seqnum(). The device gets
 * the uevent with the UUID when the kernel supports UUIDs, and the one without it when it does not, as it would
 * anyway; but when nothing could be decided, it may get none, when the kernel sent none, or both, when the kernel
 * sent the first one, which the socket lost or which did not arrive in time. When the uevents of the kernel cannot
 * be watched, or the kernel refused the uevent with the UUID, the uevent is triggered without the UUID, and the
 * next call tries again. A device that never sends uevents, without a subsystem or a hidden block device whose
 * uevents the kernel suppresses, see syspath_sends_uevents(), cannot tell, and is triggered with the UUID, without
 * waiting; the next call tries again. Returns 1 if the uevent was triggered with the UUID, 0 if it was triggered
 * without it, and a negative errno on failure. */
static int uevent_trigger_with_uuid(struct udev *udev, const char *syspath, const char *action,
                                    const char *uuid, const char *args)
{
        _cleanup_free_ char *lesc1 = NULL, *lesc2 = NULL;
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
        if (r < 0 && kernel_version_supports_uuid()) {
                r = uevent_trigger_set_uuid_supported(1);
                if (r > 0)
                        log_debug("The kernel is Linux 4.13 or newer, it supports UUIDs of synthetic uevents.");
        } else if (r < 0) {
                int cached;

                cached = uevent_uuid_cache_read();
                if (cached >= 0) {
                        r = uevent_trigger_set_uuid_supported(cached);
                        if (r == cached)
                                log_debug("The kernel %s UUIDs of synthetic uevents, as found out before in this boot, see %s.",
                                          cached ? "supports" : "does not support", UEVENT_UUID_CACHE);
                } else if (cached == -ESTALE)
                        log_debug("Ignoring %s, which is from another boot or kernel.", UEVENT_UUID_CACHE);
                else if (cached == -EBADMSG)
                        log_debug("Ignoring %s, which cannot be parsed.", UEVENT_UUID_CACHE);
                else if (cached != -ENOENT)
                        log_debug_errno(cached, "Failed to read whether the kernel supports UUIDs of synthetic uevents from %s, ignoring: %m",
                                        UEVENT_UUID_CACHE);
        }
        if (r > 0)
                return uevent_trigger_fitting(syspath, action, uuid, args,
                                              /* check_sent= */ kernel_may_refuse_uevent_silently());

        if (r == 0) {
                r = uevent_trigger(syspath, action, NULL);
                return r < 0 ? r : 0;
        }

        if (!syspath_sends_uevents(syspath))
                return uevent_trigger_fitting(syspath, action, uuid, args, /* check_sent= */ false);

        /* The socket must be bound before the uevent is triggered. */
        monitor = udev_monitor_new_from_netlink(udev, "kernel");
        if (monitor) {
                (void) udev_monitor_set_receive_buffer_size(monitor, SYNTHETIC_UUID_PROBE_RCVBUF);

                r = uevent_probe_filter(monitor, syspath, action);
                if (r < 0)
                        log_debug_errno(r, "Failed to filter the uevents of the kernel for %s, ignoring: %m",
                                        utf8_escape_for_log(syspath, &lesc1));
        }
        if (!monitor || udev_monitor_enable_receiving(monitor) < 0) {
                log_debug("Failed to watch the uevents of the kernel, triggering '%s' on %s without a UUID.",
                          utf8_escape_for_log(action, &lesc1), utf8_escape_for_log(syspath, &lesc2));
                r = uevent_trigger(syspath, action, NULL);
                return r < 0 ? r : 0;
        }

        before = uevent_seqnum();
        r = uevent_trigger_fitting(syspath, action, uuid, args, /* check_sent= */ false);
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
                if (uevent_trigger_decide_uuid_supported(1))
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
                        log_debug_errno(r, "Failed to wait for the uevent of %s without a UUID, ignoring: %m",
                                        utf8_escape_for_log(syspath, &lesc1));
        }

        if (p.synth_uuid_seen) {
                if (uevent_trigger_decide_uuid_supported(1))
                        log_debug("The kernel supports UUIDs of synthetic uevents, but the uevent with UUID %s of %s did not arrive, triggered '%s' without a UUID.",
                                  uuid, utf8_escape_for_log(syspath, &lesc1), utf8_escape_for_log(action, &lesc2));
                return 0;
        }

        if (uevent_trigger_uuid_supported() >= 0)
                /* another process found out meanwhile */
                return 0;

        if (p.plain_seen && !p.lost) {
                if (uevent_trigger_decide_uuid_supported(0))
                        log_debug("The kernel does not support UUIDs of synthetic uevents (its synthetic uevents carry no SYNTH_UUID=, as before Linux 4.13), triggering uevents without them.");
                return 0;
        }

        log_debug("Could not find out whether the kernel supports UUIDs of synthetic uevents, %s, triggered '%s' on %s without a UUID, trying again with the next uevent.",
                  p.lost ? "uevents were lost" : "no uevent of the device arrived",
                  utf8_escape_for_log(action, &lesc1), utf8_escape_for_log(syspath, &lesc2));
        return 0;
}

/* Like sd_device_trigger_with_args() of systemd 66563e97b7: triggers a synthetic uevent of the device with
 * the syspath with the action, e.g. "change", a random UUID, and the arguments, which are KEY VALUE pairs,
 * unless args is NULL, see uevent_trigger_with_uuid(). The kernel passes the arguments on as
 * SYNTH_ARG_KEY=VALUE. Returns 1 if the uevent was triggered with the UUID, which is then stored in ret_uuid
 * unless it is NULL, with or without the arguments, 0 if it was triggered without the UUID and the
 * arguments, as the kernel does not support them, or the uevent would not fit with them, or the kernel refused
 * it with them, and ret_uuid is set to
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
 * from /proc/self/cmdline, it is program_invocation_short_name: argv[0] without its directory, or the new
 * name of a process that renamed itself with rename_process(), which writes it over argv[0]. The workers of
 * udevd and the children that run programs, "(udev-worker)" and "(spawn)", point it at their complete name
 * then, which /proc/self/cmdline may show only cut to the length of the original argv[0], so a worker
 * triggers uevents with "udevworker", like the workers of systemd. */
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
