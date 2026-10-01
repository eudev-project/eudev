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
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include "libudev.h"
#include "libudev-private.h"
#include "fileio.h"
#include "log.h"
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

        escaped = cescape(name);
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
                log_debug("%s: '%s' sysattr contains invalid characters, refusing.",
                          udev_device_get_sysname(device), sysattr);
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
