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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <ctype.h>
#include <net/if.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/vfs.h>
#include <linux/magic.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <sys/sysmacros.h>

#include "libudev.h"
#include "libudev-private.h"
#include "def.h"
#include "fileio.h"
#include "path-util.h"
#include "utf8.h"

static int udev_device_read_uevent_file(struct udev_device *udev_device);
static void devname_simplify(char *path);
static int udev_device_set_devnode(struct udev_device *udev_device, const char *devnode);
static struct udev_list_entry *udev_device_add_property_internal(struct udev_device *udev_device, const char *key, const char *value);

/**
 * SECTION:libudev-device
 * @short_description: kernel sys devices
 *
 * Representation of kernel sys devices. Devices are uniquely identified
 * by their syspath, every device has exactly one path in the kernel sys
 * filesystem. Devices usually belong to a kernel subsystem, and have
 * a unique name inside that subsystem.
 */

/**
 * udev_device:
 *
 * Opaque object representing one kernel sys device.
 */
struct udev_device {
        struct udev *udev;
        struct udev_device *parent_device;
        char *syspath;
        const char *devpath;
        char *sysname;
        const char *sysnum;
        char *devnode;
        mode_t devnode_mode;
        uid_t devnode_uid;
        gid_t devnode_gid;
        char *subsystem;
        char *devtype;
        char *driver;
        char *action;
        char *devpath_old;
        char *id_filename;
        char **envp;
        char *monitor_buf;
        size_t monitor_buf_len;
        struct udev_list devlinks_list;
        struct udev_list properties_list;
        struct udev_list sysattr_value_list;
        struct udev_list sysattr_list;
        struct udev_list tags_list;             /* all tags, sticky until the device is removed */
        struct udev_list current_tags_list;     /* the tags assigned by the latest event */
        unsigned database_version;              /* of the database or netlink message read, see LATEST_UDEV_DATABASE_VERSION */
        unsigned long long int seqnum;
        usec_t usec_initialized;
        int devlink_priority;
        int refcount;
        dev_t devnum;
        int ifindex;
        int watch_handle;
        char *parse_major, *parse_minor;        /* MAJOR= and MINOR= while parsing a message */
        bool parent_set;
        bool subsystem_set;
        bool devtype_set;
        bool devlinks_uptodate;
        bool envp_uptodate;
        bool tags_uptodate;
        bool driver_set;
        bool info_loaded;
        bool db_loaded;
        bool uevent_loaded;
        bool is_initialized;
        bool sysattr_list_read;
        bool db_persist;
};

/**
 * udev_device_get_seqnum:
 * @udev_device: udev device
 *
 * This is only valid if the device was received through a monitor. Devices read from
 * sys do not have a sequence number.
 *
 * Returns: the kernel event sequence number, or 0 if there is no sequence number available.
 **/
_public_ unsigned long long int udev_device_get_seqnum(struct udev_device *udev_device)
{
        if (udev_device == NULL)
                return 0;
        return udev_device->seqnum;
}

static int udev_device_set_seqnum(struct udev_device *udev_device, unsigned long long int seqnum)
{
        char num[32];

        udev_device->seqnum = seqnum;
        snprintf(num, sizeof(num), "%llu", seqnum);
        udev_device_add_property_internal(udev_device, "SEQNUM", num);
        return 0;
}

int udev_device_get_ifindex(struct udev_device *udev_device)
{
        if (!udev_device->info_loaded)
                udev_device_read_uevent_file(udev_device);
        return udev_device->ifindex;
}

static int udev_device_set_ifindex(struct udev_device *udev_device, int ifindex)
{
        char num[32];

        udev_device->ifindex = ifindex;
        snprintf(num, sizeof(num), "%d", ifindex);
        udev_device_add_property_internal(udev_device, "IFINDEX", num);
        return 0;
}

/**
 * udev_device_get_devnum:
 * @udev_device: udev device
 *
 * Get the device major/minor number.
 *
 * Returns: the dev_t number.
 **/
_public_ dev_t udev_device_get_devnum(struct udev_device *udev_device)
{
        if (udev_device == NULL)
                return makedev(0, 0);
        if (!udev_device->info_loaded)
                udev_device_read_uevent_file(udev_device);
        return udev_device->devnum;
}

static int udev_device_set_devnum(struct udev_device *udev_device, dev_t devnum)
{
        char num[32];

        udev_device->devnum = devnum;

        snprintf(num, sizeof(num), "%u", major(devnum));
        udev_device_add_property_internal(udev_device, "MAJOR", num);
        snprintf(num, sizeof(num), "%u", minor(devnum));
        udev_device_add_property_internal(udev_device, "MINOR", num);
        return 0;
}

const char *udev_device_get_devpath_old(struct udev_device *udev_device)
{
        return udev_device->devpath_old;
}

static int udev_device_set_devpath_old(struct udev_device *udev_device, const char *devpath_old)
{
        const char *pos;

        free(udev_device->devpath_old);
        udev_device->devpath_old = strdup(devpath_old);
        if (udev_device->devpath_old == NULL)
                return -ENOMEM;
        udev_device_add_property_internal(udev_device, "DEVPATH_OLD", udev_device->devpath_old);

        pos = strrchr(udev_device->devpath_old, '/');
        if (pos == NULL)
                return -EINVAL;
        return 0;
}

/**
 * udev_device_get_driver:
 * @udev_device: udev device
 *
 * Get the kernel driver name.
 *
 * Returns: the driver name string, or #NULL if there is no driver attached.
 **/
_public_ const char *udev_device_get_driver(struct udev_device *udev_device)
{
        char driver[UTIL_NAME_SIZE];

        if (udev_device == NULL)
                return NULL;
        if (!udev_device->driver_set) {
                udev_device->driver_set = true;
                if (util_get_sys_core_link_value(udev_device->udev, "driver", udev_device->syspath, driver, sizeof(driver)) > 0)
                        udev_device->driver = strdup(driver);
        }
        return udev_device->driver;
}

static int udev_device_set_driver(struct udev_device *udev_device, const char *driver)
{
        free(udev_device->driver);
        udev_device->driver = strdup(driver);
        if (udev_device->driver == NULL)
                return -ENOMEM;
        udev_device->driver_set = true;
        udev_device_add_property_internal(udev_device, "DRIVER", udev_device->driver);
        return 0;
}

/**
 * udev_device_get_devtype:
 * @udev_device: udev device
 *
 * Retrieve the devtype string of the udev device.
 *
 * Returns: the devtype name of the udev device, or #NULL if it can not be determined
 **/
_public_ const char *udev_device_get_devtype(struct udev_device *udev_device)
{
        if (udev_device == NULL)
                return NULL;
        if (!udev_device->devtype_set) {
                udev_device->devtype_set = true;
                udev_device_read_uevent_file(udev_device);
        }
        return udev_device->devtype;
}

static int udev_device_set_devtype(struct udev_device *udev_device, const char *devtype)
{
        free(udev_device->devtype);
        udev_device->devtype = strdup(devtype);
        if (udev_device->devtype == NULL)
                return -ENOMEM;
        udev_device->devtype_set = true;
        udev_device_add_property_internal(udev_device, "DEVTYPE", udev_device->devtype);
        return 0;
}

static int udev_device_set_subsystem(struct udev_device *udev_device, const char *subsystem)
{
        free(udev_device->subsystem);
        udev_device->subsystem = strdup(subsystem);
        if (udev_device->subsystem == NULL)
                return -ENOMEM;
        udev_device->subsystem_set = true;
        udev_device_add_property_internal(udev_device, "SUBSYSTEM", udev_device->subsystem);
        return 0;
}

/**
 * udev_device_get_subsystem:
 * @udev_device: udev device
 *
 * Retrieve the subsystem string of the udev device. The string does not
 * contain any "/".
 *
 * Returns: the subsystem name of the udev device, or #NULL if it can not be determined
 **/
_public_ const char *udev_device_get_subsystem(struct udev_device *udev_device)
{
        char subsystem[UTIL_NAME_SIZE];

        if (udev_device == NULL)
                return NULL;
        /* Like sd_device_get_subsystem() of systemd, read the uevent file first, so that the property
         * SUBSYSTEM follows its properties. */
        if (!udev_device->subsystem_set && !udev_device->info_loaded)
                udev_device_read_uevent_file(udev_device);
        if (!udev_device->subsystem_set) {
                udev_device->subsystem_set = true;
                /* read "subsystem" link */
                if (util_get_sys_core_link_value(udev_device->udev, "subsystem", udev_device->syspath, subsystem, sizeof(subsystem)) > 0) {
                        udev_device_set_subsystem(udev_device, subsystem);
                        return udev_device->subsystem;
                }
                /* implicit names */
                if (startswith(udev_device->devpath, "/module/")) {
                        udev_device_set_subsystem(udev_device, "module");
                        return udev_device->subsystem;
                }
                if (strstr(udev_device->devpath, "/drivers/") != NULL ||
                    endswith(udev_device->devpath, "/drivers")) {
                        udev_device_set_subsystem(udev_device, "drivers");
                        return udev_device->subsystem;
                }
                if (startswith(udev_device->devpath, "/subsystem/") ||
                    startswith(udev_device->devpath, "/class/") ||
                    startswith(udev_device->devpath, "/bus/")) {
                        udev_device_set_subsystem(udev_device, "subsystem");
                        return udev_device->subsystem;
                }
        }
        return udev_device->subsystem;
}

mode_t udev_device_get_devnode_mode(struct udev_device *udev_device)
{
        if (!udev_device->info_loaded)
                udev_device_read_uevent_file(udev_device);
        return udev_device->devnode_mode;
}

static int udev_device_set_devnode_mode(struct udev_device *udev_device, mode_t mode)
{
        char num[32];

        udev_device->devnode_mode = mode;
        snprintf(num, sizeof(num), "%#o", mode);
        udev_device_add_property_internal(udev_device, "DEVMODE", num);
        return 0;
}

uid_t udev_device_get_devnode_uid(struct udev_device *udev_device)
{
        if (!udev_device->info_loaded)
                udev_device_read_uevent_file(udev_device);
        return udev_device->devnode_uid;
}

static int udev_device_set_devnode_uid(struct udev_device *udev_device, uid_t uid)
{
        char num[32];

        udev_device->devnode_uid = uid;
        snprintf(num, sizeof(num), "%u", uid);
        udev_device_add_property_internal(udev_device, "DEVUID", num);
        return 0;
}

gid_t udev_device_get_devnode_gid(struct udev_device *udev_device)
{
        if (!udev_device->info_loaded)
                udev_device_read_uevent_file(udev_device);
        return udev_device->devnode_gid;
}

static int udev_device_set_devnode_gid(struct udev_device *udev_device, gid_t gid)
{
        char num[32];

        udev_device->devnode_gid = gid;
        snprintf(num, sizeof(num), "%u", gid);
        udev_device_add_property_internal(udev_device, "DEVGID", num);
        return 0;
}

static bool property_is_valid(const char *key, const char *value)
{
        /* Device properties may be saved to database file, then may be parsed from the file. When if a
         * property contains spurious characters, then the parser may be confused. Let's refuse spurious
         * properties, even if it is internal, which will not be saved to database file, for consistency. */

        if (isempty(key) || !in_charset(key, ALPHANUMERICAL "_."))
                return false;

        /* an empty value means unset the property, hence that's fine. */
        if (isempty(value))
                return true;

        /* refuse invalid UTF8 and control characters */
        if (!utf8_is_valid(value) || string_has_cc(value, NULL))
                return false;

        return true;
}

/* Sets, or with an empty or NULL value removes, a property. Returns -EINVAL for an invalid property
 * and -ENOMEM on allocation failure. The new list entry is returned in ret_entry, NULL on removal. */
static int udev_device_add_property_internal_full(struct udev_device *udev_device, const char *key, const char *value,
                                                  struct udev_list_entry **ret_entry)
{
        struct udev_list_entry *list_entry;

        if (ret_entry)
                *ret_entry = NULL;

        if (!property_is_valid(key, value)) {
                if (log_get_max_level() >= LOG_DEBUG) {
                        _cleanup_free_ char *escaped_key = utf8_escape_non_printable(key ?: ""),
                                *escaped_value = utf8_escape_non_printable(value ?: "");
                        log_debug("%s%sRefusing invalid property: %s=%s",
                                  udev_device->sysname ?: "", udev_device->sysname ? ": " : "",
                                  escaped_key ?: "(null)", escaped_value ?: "(null)");
                }
                return -EINVAL;
        }

        udev_device->envp_uptodate = false;
        if (isempty(value)) {
                /* Look at the list as it is: like sd-device, removing a property must not read the uevent
                 * file or the database, which would add their properties in the middle. */
                list_entry = udev_list_get_entry(&udev_device->properties_list);
                list_entry = udev_list_entry_get_by_name(list_entry, key);
                if (list_entry != NULL)
                        udev_list_entry_delete(list_entry);
                return 0;
        }

        list_entry = udev_list_entry_add(&udev_device->properties_list, key, value);
        if (list_entry == NULL)
                return -ENOMEM;

        if (ret_entry)
                *ret_entry = list_entry;
        return 0;
}

static struct udev_list_entry *udev_device_add_property_internal(struct udev_device *udev_device, const char *key, const char *value)
{
        struct udev_list_entry *list_entry;

        (void) udev_device_add_property_internal_full(udev_device, key, value, &list_entry);
        return list_entry;
}

int udev_device_add_property(struct udev_device *udev_device, const char *key, const char *value)
{
        struct udev_list_entry *property;
        int r;

        r = udev_device_add_property_internal_full(udev_device, key, value, &property);
        if (r < 0)
                return r;

        /* store in db, skip private keys */
        if (key[0] != '.')
                udev_list_entry_set_num(property, true);

        return 0;
}

static struct udev_list_entry *udev_device_add_property_from_string(struct udev_device *udev_device, const char *property)
{
        _cleanup_free_ char *name = NULL;
        char *val;

        name = strdup(property);
        if (name == NULL)
                return NULL;
        val = strchr(name, '=');
        if (val == NULL)
                return NULL;
        val[0] = '\0';
        val = &val[1];
        if (val[0] == '\0')
                val = NULL;
        return udev_device_add_property_internal(udev_device, name, val);
}

/* Resolves all symlinks, "." and ".." of a path below /sys, like chase() in device_set_syspath() of
 * systemd, and checks that the result is below /sys too, e.g. not for /sys/../tmp or for a symlink out
 * of /sys. When /sys is a symlink to the mount point of sysfs, the result is translated back to
 * /sys. */
static int sysfs_resolve(const char *path, char **ret)
{
        _cleanup_free_ char *resolved = NULL, *real_sys = NULL;
        const char *p;
        char *t;

        resolved = realpath(path, NULL);
        if (!resolved)
                return -errno;

        if (!isempty(path_startswith(resolved, "/sys/"))) {
                *ret = TAKE_PTR(resolved);
                return 0;
        }

        if (path_equal(resolved, "/sys")) {
                log_debug("%s resolves to /sys itself", path);
                return -ENODEV;
        }

        real_sys = realpath("/sys", NULL);
        if (!real_sys)
                return -errno;

        p = path_equal(real_sys, "/sys") ? NULL : path_startswith(resolved, real_sys);
        if (isempty(p)) {
                log_debug("%s resolves to %s, which is outside of /sys", path, resolved);
                return -ENODEV;
        }

        t = strjoin("/sys/", p, NULL);
        if (!t)
                return -ENOMEM;

        *ret = t;
        return 0;
}

/* Like device_set_syspath() of systemd: only operate on sysfs, i.e. refuse a syspath like /sys/fs/cgroup/...,
 * where things are not arranged as kobjects of the kernel, unless $UDEV_DEVICE_VERIFY_SYSFS, or
 * $SYSTEMD_DEVICE_VERIFY_SYSFS when it is not set, is false, e.g. for tests with a directory as /sys. */
static int sysfs_verify(const char *path)
{
        const char *name = "UDEV_DEVICE_VERIFY_SYSFS", *e;
        struct statfs sfs;
        int r;

        e = secure_getenv(name);
        if (!e) {
                name = "SYSTEMD_DEVICE_VERIFY_SYSFS";
                e = secure_getenv(name);
        }
        if (e) {
                r = parse_boolean(e);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse $%s value: %m", name);
                else if (r == 0)
                        return 0;
        }

        if (statfs(path, &sfs) < 0)
                return log_debug_errno(errno, "failed to check if syspath \"%s\" is backed by sysfs: %m", path);
        if (!F_TYPE_EQUAL(sfs.f_type, SYSFS_MAGIC)) {
                log_debug("the syspath \"%s\" is outside of sysfs, refusing.", path);
                return -ENODEV;
        }

        return 0;
}

static int udev_device_set_syspath(struct udev_device *udev_device, const char *syspath)
{
        const char *pos;
        size_t len, n;

        free(udev_device->syspath);
        udev_device->syspath = strdup(syspath);
        if (udev_device->syspath ==  NULL)
                return -ENOMEM;
        udev_device->devpath = udev_device->syspath + strlen("/sys");
        udev_device_add_property_internal(udev_device, "DEVPATH", udev_device->devpath);

        /* clear the previous sysname and sysnum, e.g. when the device is renamed */
        free(udev_device->sysname);
        udev_device->sysname = NULL;
        udev_device->sysnum = NULL;

        pos = strrchr(udev_device->syspath, '/');
        if (pos == NULL)
                return -EINVAL;
        udev_device->sysname = strdup(&pos[1]);
        if (udev_device->sysname == NULL)
                return -ENOMEM;

        /* some devices have '!' in their name, change that to '/' */
        len = 0;
        while (udev_device->sysname[len] != '\0') {
                if (udev_device->sysname[len] == '!')
                        udev_device->sysname[len] = '/';
                len++;
        }

        /* trailing number */
        n = 0;
        while (n < len && ascii_isdigit(udev_device->sysname[len - n - 1]))
                n++;

        /* do not set sysnum for number only sysname */
        if (n > 0 && n < len)
                udev_device->sysnum = &udev_device->sysname[len - n];

        return 0;
}

static void udev_device_set_usec_initialized(struct udev_device *udev_device, usec_t usec_initialized)
{
        char num[DECIMAL_STR_MAX(usec_t)];

        udev_device->usec_initialized = usec_initialized;
        snprintf(num, sizeof(num), USEC_FMT, usec_initialized);
        udev_device_add_property_internal(udev_device, "USEC_INITIALIZED", num);
}

void udev_device_ensure_usec_initialized(struct udev_device *udev_device, struct udev_device *old_device)
{
        if (old_device && old_device->usec_initialized != 0)
                udev_device_set_usec_initialized(udev_device, old_device->usec_initialized);
        else
                udev_device_set_usec_initialized(udev_device, now(CLOCK_MONOTONIC));
}

static int udev_device_set_action(struct udev_device *udev_device, const char *action)
{
        free(udev_device->action);
        udev_device->action = strdup(action);
        if (udev_device->action == NULL)
                return -ENOMEM;
        udev_device_add_property_internal(udev_device, "ACTION", udev_device->action);
        return 0;
}

/* like systemd's STR_IN_SET() */
static bool str_in_set(const char *s, const char *const *set)
{
        for (; *set; set++)
                if (streq(s, *set))
                        return true;
        return false;
}
#define STR_IN_SET(s, ...) str_in_set((s), (const char *const[]) { __VA_ARGS__, NULL })

/* Parses the numbers of the properties libudev interprets, like systemd's sd-device does. */

/* DEVMODE=, like device_set_devmode() of systemd: with safe_atou(), so e.g. "0660" is octal */
static int parse_devmode(const char *s, mode_t *ret)
{
        unsigned u;
        int r;

        r = safe_atou(s, &u);
        if (r < 0)
                return r;
        if (u > 07777)
                return -EINVAL;
        *ret = u;
        return 0;
}

/* DEVUID= and DEVGID=, like parse_uid() of systemd: decimal only, without a sign, leading zeros or
 * whitespace, and neither (uid_t) -1 nor the 16-bit -1 */
static int parse_devuid(const char *s, uid_t *ret)
{
        unsigned u;
        int r;

        r = safe_atou_full(s, 10 | SAFE_ATO_REFUSE_PLUS_MINUS | SAFE_ATO_REFUSE_LEADING_ZERO |
                              SAFE_ATO_REFUSE_LEADING_WHITESPACE, &u);
        if (r < 0)
                return r;
        if (u == 0xFFFFFFFFU || u == 0xFFFFU)
                return -ENXIO;
        *ret = u;
        return 0;
}

/* IFINDEX=, like parse_ifindex() of systemd */
static int parse_ifindex(const char *s, int *ret)
{
        unsigned u;
        int r;

        r = safe_atou_full(s, 0, &u);
        if (r < 0)
                return r;
        if (u == 0 || u > INT_MAX)
                return -EINVAL;
        *ret = u;
        return 0;
}

/* MAJOR= and MINOR=, like device_set_devnum() of systemd. A major number of 0 means no device
 * node, then the minor number is not checked. */
static int parse_devnum(const char *major_str, const char *minor_str, dev_t *ret)
{
        unsigned maj, min = 0;
        int r;

        r = safe_atou_full(major_str, 0, &maj);
        if (r < 0)
                return r;
        if (maj == 0) {
                *ret = 0;
                return 0;
        }
        if (maj > (1U << 12) - 1)
                return -EINVAL;

        if (minor_str) {
                r = safe_atou_full(minor_str, 0, &min);
                if (r < 0)
                        return r;
                if (min > (1U << 20) - 1)
                        return -EINVAL;
        }

        *ret = makedev(maj, min);
        return 0;
}

/* DEVPATH=: like device_set_syspath() of systemd, the path below /sys is simplified, and must not
 * be empty */
static int udev_device_set_devpath(struct udev_device *udev_device, const char *devpath)
{
        _cleanup_free_ char *syspath = NULL;

        if (devpath[0] != '/')
                return -EINVAL;

        syspath = strjoin("/sys", devpath, NULL);
        if (!syspath)
                return -ENOMEM;
        devname_simplify(syspath);
        if (!startswith(syspath, "/sys/"))
                return -EINVAL;

        return udev_device_set_syspath(udev_device, syspath);
}

/* DEVLINKS=: split at whitespace, like extract_first_word() with EXTRACT_RETAIN_ESCAPE */
static int udev_device_add_devlinks_from_string(struct udev_device *udev_device, const char *value)
{
        const char *p = value;

        for (;;) {
                _cleanup_free_ char *word = NULL;
                size_t n;
                int r;

                p += strspn(p, WHITESPACE);
                if (*p == '\0')
                        return 0;

                n = strcspn(p, WHITESPACE);
                word = strndup(p, n);
                if (!word)
                        return -ENOMEM;
                p += n;

                r = udev_device_add_devlink(udev_device, word);
                if (r < 0)
                        return r;
        }
}

/* TAGS= and CURRENT_TAGS=: split at ':', like extract_first_word() with
 * EXTRACT_DONT_COALESCE_SEPARATORS, i.e. a backslash takes the next character literally, and
 * empty words are skipped */
static int udev_device_add_tags_from_string(struct udev_device *udev_device, const char *value, bool both)
{
        _cleanup_free_ char *word = NULL;
        const char *p = value;

        word = malloc(strlen(value) + 1);
        if (!word)
                return -ENOMEM;

        for (;;) {
                size_t n = 0;
                bool end;
                int r;

                while (*p != '\0' && *p != ':') {
                        if (*p == '\\') {
                                p++;
                                if (*p == '\0')
                                        return -EINVAL;
                        }
                        word[n++] = *(p++);
                }
                word[n] = '\0';

                end = *p == '\0';
                if (!end)
                        p++;

                if (n > 0) {
                        r = udev_device_add_tag(udev_device, word, both);
                        if (r < 0)
                                return r;
                }

                if (end)
                        return 0;
        }
}

static bool action_is_valid(const char *action)
{
        return STR_IN_SET(action, "add", "remove", "change", "move", "online", "offline", "bind", "unbind");
}

/*
 * Parses one "KEY=VALUE" of a netlink message or of the environment, and updates the internal
 * values of the properties libudev interprets, like device_amend() of systemd's sd-device.
 *
 * Returns a negative error when the device must be refused: the entry is not a key-value pair, or
 * the value of one of the interpreted properties is invalid. Other invalid properties are ignored,
 * see systemd commit 354b51ddbfa3c735cccaab455b3f954dab746a43.
 *
 * udev_device_add_property_from_string_parse_finish() needs to be
 * called after adding properties, and its return value checked
 *
 * udev_device_set_info_loaded() needs to be set, to avoid trying
 * to use a device without a DEVPATH set
 */
static int udev_device_add_property_from_string_parse(struct udev_device *udev_device, const char *property)
{
        _cleanup_free_ char *key = NULL;
        const char *value, *eq;
        int r = 0;

        eq = strchr(property, '=');
        if (!eq) {
                if (log_get_max_level() >= LOG_DEBUG) {
                        _cleanup_free_ char *escaped = utf8_escape_non_printable(property);

                        log_debug("%s%sNot a key-value pair: '%s'",
                                  udev_device->sysname ?: "", udev_device->sysname ? ": " : "",
                                  escaped ?: "(null)");
                }
                return -EINVAL;
        }

        key = strndup(property, eq - property);
        if (!key)
                return log_oom();
        value = eq + 1;

        if (streq(key, "MAJOR"))
                r = free_and_strdup(&udev_device->parse_major, value);
        else if (streq(key, "MINOR"))
                r = free_and_strdup(&udev_device->parse_minor, value);
        else if (STR_IN_SET(key, "DEVPATH", "SUBSYSTEM", "DEVTYPE", "DRIVER") && !property_is_valid(key, value))
                r = -EINVAL;
        else if (streq(key, "DEVPATH"))
                r = udev_device_set_devpath(udev_device, value);
        else if (streq(key, "SUBSYSTEM"))
                r = udev_device_set_subsystem(udev_device, value);
        else if (streq(key, "DEVTYPE"))
                r = udev_device_set_devtype(udev_device, value);
        else if (streq(key, "DRIVER"))
                r = udev_device_set_driver(udev_device, value);
        else if (streq(key, "DEVNAME"))
                r = udev_device_set_devnode(udev_device, value);
        else if (streq(key, "DEVLINKS"))
                r = udev_device_add_devlinks_from_string(udev_device, value);
        else if (STR_IN_SET(key, "TAGS", "CURRENT_TAGS"))
                r = udev_device_add_tags_from_string(udev_device, value, streq(key, "CURRENT_TAGS"));
        else if (streq(key, "UDEV_DATABASE_VERSION"))
                r = safe_atou_full(value, 0, &udev_device->database_version);
        else if (streq(key, "USEC_INITIALIZED")) {
                uint64_t t;

                r = safe_atou64_full(value, 0, &t);
                if (r >= 0)
                        udev_device_set_usec_initialized(udev_device, t);
        } else if (streq(key, "ACTION")) {
                if (!action_is_valid(value))
                        r = -EINVAL;
                else
                        r = udev_device_set_action(udev_device, value);
        } else if (STR_IN_SET(key, "SEQNUM", "DISKSEQ")) {
                uint64_t u;

                r = safe_atou64_full(value, 0, &u);
                if (r >= 0 && u == 0)
                        r = -EINVAL;
                else if (r >= 0 && streq(key, "SEQNUM"))
                        r = udev_device_set_seqnum(udev_device, u);
                else if (r >= 0)
                        r = udev_device_add_property_internal_full(udev_device, key, value, NULL);
        } else if (streq(key, "IFINDEX")) {
                int ifindex;

                r = parse_ifindex(value, &ifindex);
                if (r >= 0)
                        r = udev_device_set_ifindex(udev_device, ifindex);
        } else if (streq(key, "DEVMODE")) {
                mode_t mode;

                r = parse_devmode(value, &mode);
                if (r >= 0)
                        r = udev_device_set_devnode_mode(udev_device, mode);
        } else if (STR_IN_SET(key, "DEVUID", "DEVGID")) {
                uid_t id;

                r = parse_devuid(value, &id);
                if (r >= 0 && streq(key, "DEVUID"))
                        r = udev_device_set_devnode_uid(udev_device, id);
                else if (r >= 0)
                        r = udev_device_set_devnode_gid(udev_device, id);
        } else {
                /* An ordinary property. The kernel may pass invalid characters, e.g. in UNIQ= of USB
                 * serial devices. Ignore only such key-value pairs. */
                if (!property_is_valid(key, value)) {
                        if (log_get_max_level() >= LOG_DEBUG) {
                                _cleanup_free_ char *escaped = utf8_escape_non_printable(property);

                                log_debug("%s%sInvalid property '%s', ignoring",
                                          udev_device->sysname ?: "", udev_device->sysname ? ": " : "",
                                          escaped ?: "(null)");
                        }
                        return 0;
                }

                if (streq(key, "DEVPATH_OLD")) {
                        /* an ordinary property for systemd, never refuse the device for it */
                        r = udev_device_set_devpath_old(udev_device, value);
                        if (r != -ENOMEM)
                                r = 0;
                } else if (!udev_device_add_property_from_string(udev_device, property) && !isempty(value))
                        r = -ENOMEM;
        }

        if (r < 0 && log_get_max_level() >= LOG_DEBUG) {
                _cleanup_free_ char *escaped = utf8_escape_non_printable(property);

                log_debug_errno(r, "%s%sFailed to set '%s': %m",
                                udev_device->sysname ?: "", udev_device->sysname ? ": " : "",
                                escaped ?: "(null)");
        }

        return r;
}

static int udev_device_add_property_from_string_parse_finish(struct udev_device *udev_device)
{
        int r = 0;

        if (udev_device->parse_major) {
                dev_t devnum;

                r = parse_devnum(udev_device->parse_major, udev_device->parse_minor, &devnum);
                if (r < 0)
                        log_debug_errno(r, "Failed to set devnum %s:%s: %m",
                                        udev_device->parse_major, udev_device->parse_minor ?: "n/a");
                else if (major(devnum) > 0)
                        udev_device_set_devnum(udev_device, devnum);
        }
        free(udev_device->parse_major);
        free(udev_device->parse_minor);
        udev_device->parse_major = udev_device->parse_minor = NULL;
        if (r < 0)
                return r;

        /* like device_verify() of systemd */
        if (udev_device->devpath == NULL || udev_device->subsystem == NULL ||
            udev_device->action == NULL || udev_device->seqnum == 0) {
                log_debug("device lacks devpath, subsystem, action or seqnum");
                return -EINVAL;
        }
        return 0;
}

/**
 * udev_device_get_property_value:
 * @udev_device: udev device
 * @key: property name
 *
 * Get the value of a given property.
 *
 * Returns: the property string, or #NULL if there is no such property.
 **/
_public_ const char *udev_device_get_property_value(struct udev_device *udev_device, const char *key)
{
        struct udev_list_entry *list_entry;

        if (udev_device == NULL)
                return NULL;
        if (key == NULL)
                return NULL;

        list_entry = udev_device_get_properties_list_entry(udev_device);
        list_entry = udev_list_entry_get_by_name(list_entry, key);
        return udev_list_entry_get_value(list_entry);
}

int udev_device_read_db(struct udev_device *udev_device)
{
        char filename[UTIL_PATH_SIZE];
        const char *id;
        FILE *f;

        if (udev_device->db_loaded)
                return 0;

        id = udev_device_get_id_filename(udev_device);
        if (id == NULL)
                return -1;

        strscpyl(filename, sizeof(filename), UDEV_ROOT_RUN "/udev/data/", id, NULL);

        /* We will retry if we couldn't access the file, e.g. because the device has not been
         * processed by udevd yet, but not if parsing failed. Like systemd, a missing file is not
         * logged: the device properties are read many times, and most devices have no database. */
        f = fopen(filename, "re");
        if (f == NULL) {
                if (errno == ENOENT)
                        return -ENOENT;
                return log_debug_errno(errno, "failed to read db file %s: %m", filename);
        }

        udev_device->db_loaded = true;

        /* devices with a database entry are initialized */
        udev_device->is_initialized = true;

        /* a database without the V: line has version 0 */
        udev_device->database_version = 0;

        for (;;) {
                _cleanup_free_ char *line = NULL, *path = NULL;
                const char *val;
                struct udev_list_entry *entry;
                int r;

                /* The lines of the entries are not limited in systemd, but take a limit of 1 MiB, like
                 * IMPORT{file} has. */
                r = read_line(f, LONG_LINE_MAX, &line);
                if (r == -ENOBUFS) {
                        /* Ignore the line as a whole, its remainder must not be parsed as a line of
                         * its own. */
                        log_debug("overlong line in db file %s, ignoring", filename);
                        (void) read_line(f, SIZE_MAX, NULL);
                        continue;
                }
                if (r < 0) {
                        log_debug_errno(r, "failed to read db file %s: %m", filename);
                        break;
                }
                if (r == 0)
                        break;

                if (strlen(line) < 2 || line[1] != ':')
                        continue;
                val = &line[2];
                switch(line[0]) {
                case 'S':
                        path = strjoin("/dev/", val, NULL);
                        if (path)
                                udev_device_add_devlink(udev_device, path);
                        break;
                case 'L':
                        udev_device_set_devlink_priority(udev_device, atoi(val));
                        break;
                case 'E':
                        entry = udev_device_add_property_from_string(udev_device, val);
                        udev_list_entry_set_num(entry, true);
                        break;
                case 'G': /* Any tag */
                case 'Q': /* Current tag */
                        udev_device_add_tag(udev_device, val, line[0] == 'Q');
                        break;
                case 'W':
                        /* Deprecated. Previously, watch handle is both saved in database and /run/udev/watch.
                         * However, the handle saved in database may not be updated when the handle is updated
                         * or removed. Moreover, it is not necessary to store the handle within the database,
                         * as its value becomes meaningless when udevd is restarted. */
                        break;
                case 'I':
                        udev_device_set_usec_initialized(udev_device, strtoull(val, NULL, 10));
                        break;
                case 'V':
                        if (safe_atou(val, &udev_device->database_version) < 0)
                                log_debug("invalid database version '%s' in db file %s, ignoring", val, filename);
                        break;
                }
        }
        fclose(f);

        log_trace("device %p filled with db file data", udev_device);
        return 0;
}

/* Handles one line of the uevent file, like handle_uevent_line() of systemd's sd-device */
static int udev_device_handle_uevent_line(struct udev_device *udev_device, const char *key, const char *value)
{
        int r;

        if (streq(key, "MAJOR"))
                return free_and_strdup(&udev_device->parse_major, value);
        if (streq(key, "MINOR"))
                return free_and_strdup(&udev_device->parse_minor, value);

        /* The kernel may pass invalid characters, e.g. in UNIQ= of USB serial devices. Ignore
         * only such key-value pairs. */
        if (!property_is_valid(key, value))
                return -EINVAL;

        if (streq(key, "DEVTYPE"))
                return udev_device_set_devtype(udev_device, value);
        if (streq(key, "DEVNAME"))
                return udev_device_set_devnode(udev_device, value);
        if (streq(key, "IFINDEX")) {
                int ifindex;

                r = parse_ifindex(value, &ifindex);
                if (r < 0)
                        return r;
                return udev_device_set_ifindex(udev_device, ifindex);
        }
        if (streq(key, "DEVMODE")) {
                mode_t mode;

                r = parse_devmode(value, &mode);
                if (r < 0)
                        return r;
                return udev_device_set_devnode_mode(udev_device, mode);
        }
        if (STR_IN_SET(key, "DEVUID", "DEVGID")) {
                uid_t id;

                r = parse_devuid(value, &id);
                if (r < 0)
                        return r;
                if (streq(key, "DEVUID"))
                        return udev_device_set_devnode_uid(udev_device, id);
                return udev_device_set_devnode_gid(udev_device, id);
        }
        if (streq(key, "DISKSEQ")) {
                uint64_t u;

                r = safe_atou64_full(value, 0, &u);
                if (r < 0)
                        return r;
                if (u == 0)
                        return -EINVAL;
        }

        /* An ordinary property, like device_add_property_internal() in handle_uevent_line() of
         * systemd's sd-device. */
        return udev_device_add_property_internal_full(udev_device, key, value, NULL);
}

static int udev_device_read_uevent_file(struct udev_device *udev_device)
{
        _cleanup_free_ char *filename = NULL, *uevent = NULL;
        size_t size;
        char *p;
        int r;

        if (udev_device->uevent_loaded)
                return 0;

        filename = strjoin(udev_device->syspath, "/uevent", NULL);
        if (!filename)
                return -ENOMEM;
        /* Read like an attribute, with read_virtual_file(), as systemd does, which unlike systemd opens the
         * file with O_NONBLOCK and refuses anything but a regular file, so that e.g. a FIFO named "uevent" in
         * a directory used as /sys for tests does not block. Like in systemd, the content ends at a NUL. */
        r = read_virtual_file(filename, SIZE_MAX, &uevent, &size);
        if (r == -EACCES)
                /* empty uevent files may be write-only */
                return 0;
        if (r < 0)
                return r;
        udev_device->uevent_loaded = true;

        /* Like systemd, split the lines at "\n" and "\r", and skip empty lines. */
        for (p = uevent;;) {
                char *line, *eq;
                size_t n;

                p += strspn(p, NEWLINE);
                if (*p == '\0')
                        break;

                line = p;
                n = strcspn(p, NEWLINE);
                p += n;
                if (*p != '\0')
                        *(p++) = '\0';

                eq = strchr(line, '=');
                if (!eq) {
                        if (log_get_max_level() >= LOG_DEBUG) {
                                _cleanup_free_ char *escaped = utf8_escape_non_printable(line);

                                log_debug("%s: Invalid uevent line, ignoring: %s",
                                          udev_device->sysname ?: "n/a", escaped ?: "(null)");
                        }
                        continue;
                }

                *eq = '\0';
                r = udev_device_handle_uevent_line(udev_device, line, eq + 1);
                *eq = '=';
                if (r < 0 && log_get_max_level() >= LOG_DEBUG) {
                        _cleanup_free_ char *escaped = utf8_escape_non_printable(line);

                        log_debug_errno(r, "%s: Failed to handle uevent entry '%s', ignoring: %m",
                                        udev_device->sysname ?: "n/a", escaped ?: "(null)");
                }
        }

        if (udev_device->parse_major) {
                dev_t devnum;

                r = parse_devnum(udev_device->parse_major, udev_device->parse_minor, &devnum);
                if (r < 0)
                        log_debug_errno(r, "%s: Failed to set 'MAJOR=%s' and/or 'MINOR=%s' from uevent, ignoring: %m",
                                        udev_device->sysname ?: "n/a", udev_device->parse_major,
                                        udev_device->parse_minor ?: "n/a");
                else if (major(devnum) > 0)
                        udev_device_set_devnum(udev_device, devnum);
        }
        free(udev_device->parse_major);
        free(udev_device->parse_minor);
        udev_device->parse_major = udev_device->parse_minor = NULL;

        /* Like device_read_uevent_file() of systemd, which looks up the subsystem at the end, the property
         * SUBSYSTEM follows the properties of the uevent file. */
        (void) udev_device_get_subsystem(udev_device);

        return 0;
}

void udev_device_set_info_loaded(struct udev_device *device)
{
        device->info_loaded = true;
}

static struct udev_device *udev_device_new(struct udev *udev)
{
        struct udev_device *udev_device;

        if (udev == NULL) {
                errno = EINVAL;
                return NULL;
        }

        udev_device = new0(struct udev_device, 1);
        if (udev_device == NULL) {
                errno = ENOMEM;
                return NULL;
        }
        udev_device->refcount = 1;
        udev_device->udev = udev;
        udev_list_init(udev, &udev_device->devlinks_list, true);
        /* like the properties of sd-device, in the order in which they are added */
        udev_list_init_ordered(udev, &udev_device->properties_list);
        udev_list_init(udev, &udev_device->sysattr_value_list, true);
        udev_list_init(udev, &udev_device->sysattr_list, false);
        udev_list_init(udev, &udev_device->tags_list, true);
        udev_list_init(udev, &udev_device->current_tags_list, true);
        udev_device->watch_handle = -1;
        /* The tags of a device created by this libudev are current tags. Reading a database or a
         * message of an older udevd sets an older version. */
        udev_device->database_version = LATEST_UDEV_DATABASE_VERSION;

        return udev_device;
}

/**
 * udev_device_new_from_syspath:
 * @udev: udev library context
 * @syspath: sys device path including sys directory
 *
 * Create new udev device, and fill in information from the sys
 * device and the udev database entry. The syspath is the absolute
 * path to the device, including the sys mount point.
 *
 * Like in systemd, a device below /sys/devices, and /sys/devices itself, must have a
 * "uevent" file, and any other directory below /sys, e.g. /sys/class/net or /sys/class,
 * is taken as a pseudo-device; otherwise, and for /sys itself and a path that does not
 * exist, the call fails with ENODEV. A path that does not start with /sys/ fails with
 * EINVAL.
 *
 * Like in systemd, the device must be on sysfs, otherwise the call fails with ENODEV,
 * unless the environment variable UDEV_DEVICE_VERIFY_SYSFS, or SYSTEMD_DEVICE_VERIFY_SYSFS
 * when it is not set, is false, e.g. "0", to allow tests with a directory as /sys. The
 * variables are ignored in programs that run with elevated privileges (setuid etc.).
 *
 * The initial refcount is 1, and needs to be decremented to
 * release the resources of the udev device.
 *
 * Returns: a new udev device, or #NULL, if it does not exist
 **/
_public_ struct udev_device *udev_device_new_from_syspath(struct udev *udev, const char *syspath)
{
        _cleanup_free_ char *path = NULL;
        struct stat statbuf;
        struct udev_device *udev_device;
        int r;

        if (udev == NULL) {
                errno = EINVAL;
                return NULL;
        }

        if (syspath == NULL) {
                errno = EINVAL;
                return NULL;
        }

        /* path is below /sys, e.g. not /sysfoo; like systemd, /sys itself is refused below with ENODEV */
        if (!path_startswith(syspath, "/sys/")) {
                log_debug("not in sys :%s", syspath);
                errno = EINVAL;
                return NULL;
        }

        /* resolve symlinks, "." and "..", and check that the device is still below /sys; like
         * device_set_syspath() of systemd, a path that does not exist is no device */
        r = sysfs_resolve(syspath, &path);
        if (r == -ENOENT)
                r = -ENODEV;
        if (r < 0) {
                log_debug_errno(r, "failed to resolve %s: %m", syspath);
                errno = -r;
                return NULL;
        }

        /* like systemd, /sys alone is no device; sysfs_resolve() refuses it already */
        if (path_equal(path, "/sys")) {
                errno = ENODEV;
                return NULL;
        }

        /* Like device_set_syspath() of systemd: the devices in /sys/devices, also /sys/devices itself,
         * must have a "uevent" file; everything else just needs to be a directory, e.g. /sys/class/net
         * or /sys/class, which are pseudo-devices then. */
        if (path_startswith(path, "/sys/devices")) {
                _cleanup_free_ char *file = NULL;

                file = strjoin(path, "/uevent", NULL);
                if (!file) {
                        errno = ENOMEM;
                        return NULL;
                }
                if (stat(file, &statbuf) != 0) {
                        if (IN_SET(errno, ENOENT, ENOTDIR))
                                errno = ENODEV;
                        return NULL;
                }
        } else {
                if (stat(path, &statbuf) != 0) {
                        if (errno == ENOENT)
                                errno = ENODEV;
                        return NULL;
                }

                if (!S_ISDIR(statbuf.st_mode)) {
                        errno = ENODEV;
                        return NULL;
                }
        }

        r = sysfs_verify(path);
        if (r < 0) {
                errno = -r;
                return NULL;
        }

        udev_device = udev_device_new(udev);
        if (udev_device == NULL)
                return NULL;

        r = udev_device_set_syspath(udev_device, path);
        if (r < 0) {
                udev_device_unref(udev_device);
                errno = -r;
                return NULL;
        }
        log_trace("device %p has devpath '%s'", udev_device, udev_device_get_devpath(udev_device));

        return udev_device;
}

/**
 * udev_device_new_from_devnum:
 * @udev: udev library context
 * @type: char or block device
 * @devnum: device major/minor number
 *
 * Create new udev device, and fill in information from the sys
 * device and the udev database entry. The device is looked-up
 * by its major/minor number and type. Character and block device
 * numbers are not unique across the two types.
 *
 * Like in systemd, a device number with the major number 0 fails with
 * ENODEV, and the device that is found must have the device number and
 * the type, a block device being one of the "block" subsystem, otherwise
 * the call fails with ENXIO.
 *
 * The initial refcount is 1, and needs to be decremented to
 * release the resources of the udev device.
 *
 * Returns: a new udev device, or #NULL, if it does not exist
 **/
_public_ struct udev_device *udev_device_new_from_devnum(struct udev *udev, char type, dev_t devnum)
{
        char path[STRLEN("/sys/dev/block/") + DECIMAL_STR_MAX(unsigned) * 2 + 2];
        struct udev_device *dev;
        const char *type_str;

        if (type == 'b')
                type_str = "block";
        else if (type == 'c')
                type_str = "char";
        else {
                errno = EINVAL;
                return NULL;
        }

        /* like device_new_from_mode_and_devnum() of systemd */
        if (major(devnum) == 0) {
                errno = ENODEV;
                return NULL;
        }

        /* use /sys/dev/{block,char}/<maj>:<min> link */
        xsprintf(path, "/sys/dev/%s/%u:%u", type_str, major(devnum), minor(devnum));
        dev = udev_device_new_from_syspath(udev, path);
        if (!dev)
                return NULL;

        /* the device must have the number, and the type */
        if (udev_device_get_devnum(dev) != devnum ||
            streq_ptr(udev_device_get_subsystem(dev), "block") != (type == 'b')) {
                udev_device_unref(dev);
                errno = ENXIO;
                return NULL;
        }

        return dev;
}

/* Like parse_devnum() of systemd: "MAJOR:MINOR" in decimal, the major number made of digits only, both
 * valid for the kernel. */
static int parse_devnum_id(const char *s, dev_t *ret)
{
        _cleanup_free_ char *major = NULL;
        unsigned x, y;
        size_t n;
        int r;

        n = strspn(s, DIGITS);
        if (n == 0 || n > DECIMAL_STR_MAX(dev_t) || s[n] != ':')
                return -EINVAL;

        major = strndup(s, n);
        if (!major)
                return -ENOMEM;

        r = safe_atou(major, &x);
        if (r < 0)
                return r;

        r = safe_atou(s + n + 1, &y);
        if (r < 0)
                return r;

        if (x > (1U << 12) - 1 || y > (1U << 20) - 1)
                return -ERANGE;

        *ret = makedev(x, y);
        return 0;
}

/**
 * udev_device_new_from_device_id:
 * @udev: udev library context
 * @id: text string identifying a kernel device
 *
 * Create new udev device, and fill in information from the sys
 * device and the udev database entry. The device is looked-up
 * by a special string:
 *   b8:2          - block device major:minor
 *   c128:1        - char device major:minor
 *   n3            - network device ifindex
 *   +sound:card29 - kernel driver core subsystem:device name
 *
 * Like in systemd, an ID that is not valid fails with EINVAL, or ERANGE for a device
 * number that is too large, and the ID of a device that does not exist with ENODEV.
 * When the network interface of the index was renamed or replaced in the meantime, the
 * call fails with ENXIO.
 *
 * The initial refcount is 1, and needs to be decremented to
 * release the resources of the udev device.
 *
 * Returns: a new udev device, or #NULL, if it does not exist
 **/
_public_ struct udev_device *udev_device_new_from_device_id(struct udev *udev, const char *id)
{
        const char *sep;
        int r;

        if (id == NULL) {
                errno = EINVAL;
                return NULL;
        }

        /* Like sd_device_new_from_device_id() of systemd, an ID that is not valid fails with EINVAL, or
         * ERANGE for a device number that is too large, and one of a device that does not exist with
         * ENODEV, or ENXIO for an interface index that no longer has the name. */
        switch(id[0]) {
        case 'b':
        case 'c': {
                dev_t devnum;

                r = parse_devnum_id(id + 1, &devnum);
                if (r < 0) {
                        errno = -r;
                        return NULL;
                }
                return udev_device_new_from_devnum(udev, id[0], devnum);
        }
        case 'n': {
                _cleanup_free_ char *path = NULL;
                int sk;
                struct ifreq ifr;
                struct udev_device *dev;
                int ifindex;

                /* like parse_ifindex() of systemd's socket-util */
                r = safe_atoi(id + 1, &ifindex);
                if (r < 0) {
                        errno = -r;
                        return NULL;
                }
                if (ifindex <= 0) {
                        errno = EINVAL;
                        return NULL;
                }

                sk = socket(PF_INET, SOCK_DGRAM, 0);
                if (sk < 0)
                        return NULL;
                memzero(&ifr, sizeof(struct ifreq));
                ifr.ifr_ifindex = ifindex;
                if (ioctl(sk, SIOCGIFNAME, &ifr) != 0) {
                        close(sk);
                        return NULL;
                }
                close(sk);

                /* like sd_device_new_from_ifindex() of systemd: the device of the interface name, which
                 * must still have the index, otherwise the interface was renamed in the meantime */
                path = strjoin("/sys/class/net/", ifr.ifr_name, NULL);
                if (!path) {
                        errno = ENOMEM;
                        return NULL;
                }
                dev = udev_device_new_from_syspath(udev, path);
                if (dev == NULL)
                        return NULL;
                if (udev_device_get_ifindex(dev) == ifindex)
                        return dev;

                udev_device_unref(dev);
                errno = ENXIO;
                return NULL;
        }
        case '+': {
                _cleanup_free_ char *subsys = NULL, *sysname = NULL;
                char *p;

                sep = strchr(id + 1, ':');
                if (!sep || sep[1] == '\0') {
                        errno = EINVAL;
                        return NULL;
                }

                subsys = strndup(id + 1, sep - id - 1);
                sysname = strdup(sep + 1);
                if (!subsys || !sysname) {
                        errno = ENOMEM;
                        return NULL;
                }

                /* Like systemd: the device ID has the name of the directory of the device, which may contain
                 * '!', while udev_device_new_from_subsystem_sysname() takes the sysname, with '/' instead. */
                for (p = sysname; *p; p++)
                        if (*p == '!')
                                *p = '/';

                return udev_device_new_from_subsystem_sysname(udev, subsys, sysname);
        }
        default:
                errno = EINVAL;
                return NULL;
        }
}

/* Like path_is_normalized() of systemd: checks that a name does not contain "." or ".." path components or
 * duplicated slashes, so that it cannot be used to escape the directories in /sys, and that it is not too long
 * for a path, with no component longer than NAME_MAX. */
static bool name_is_normalized(const char *p)
{
        const char *c;

        if (isempty(p) || strlen(p) >= PATH_MAX)
                return false;

        if (streq(p, ".") || streq(p, ".."))
                return false;

        if (startswith(p, "../") || endswith(p, "/..") || strstr(p, "/../"))
                return false;

        if (startswith(p, "./") || endswith(p, "/.") || strstr(p, "/./"))
                return false;

        if (strstr(p, "//"))
                return false;

        for (c = p; *c; c += strspn(c, "/")) {
                size_t n = strcspn(c, "/");

                if (n > NAME_MAX)
                        return false;
                c += n;
        }

        return true;
}

/* Like device_new_from_path_join() of systemd: looks up the device at the path joined from a, b, c and d,
 * and checks that it really has the requested subsystem (no subsystem when it is NULL), the requested
 * subsystem of the driver for a device of the "drivers" pseudo-subsystem (none for other devices), and the
 * requested sysname. Returns 1 when the device matches and is stored in *device, or matches the one stored
 * there already; 0 when there is no such device; -ETOOMANYREFS when a different device was found before,
 * as the subsystem and sysname are not unique, e.g. /sys/bus/gpio/devices/gpiochip0 and
 * /sys/class/gpio/gpiochip0; or another error of udev_device_new_from_syspath(). */
static int device_new_from_path_join(struct udev *udev, struct udev_device **device,
                                     const char *subsystem, const char *driver_subsystem, const char *sysname,
                                     const char *a, const char *b, const char *c, const char *d)
{
        _cleanup_free_ char *p = NULL, *new_driver_subsystem = NULL;
        struct udev_device *new_device;
        int r;

        assert(device);
        assert(sysname);

        p = path_join(a, b, c, d);
        if (!p)
                return -ENOMEM;

        new_device = udev_device_new_from_syspath(udev, p);
        if (!new_device)
                return errno == ENODEV ? 0 : -errno;

        r = 0;
        if (!streq_ptr(udev_device_get_subsystem(new_device), subsystem))
                goto finish;

        (void) device_get_driver_subsystem(new_device, &new_driver_subsystem);
        if (!streq_ptr(driver_subsystem, new_driver_subsystem))
                goto finish;

        if (!streq_ptr(udev_device_get_sysname(new_device), sysname))
                goto finish;

        /* the first device that is found is taken */
        r = 1;
        if (!*device) {
                *device = new_device;
                return r;
        }

        /* if one was found before, it must be the same */
        if (!streq(udev_device_get_devpath(*device), udev_device_get_devpath(new_device)))
                r = log_debug_errno(ETOOMANYREFS,
                                    "found multiple devices for subsystem=%s and sysname=%s, refusing: %s, %s",
                                    strna(subsystem), sysname, udev_device_get_devpath(*device),
                                    udev_device_get_devpath(new_device));
finish:
        udev_device_unref(new_device);
        return r;
}

/**
 * udev_device_new_from_subsystem_sysname:
 * @udev: udev library context
 * @subsystem: the subsystem of the device
 * @sysname: the name of the device
 *
 * Create new udev device, and fill in information from the sys device
 * and the udev database entry. The device is looked up by the subsystem
 * and name string of the device, like "mem" / "zero", or "block" / "sda".
 *
 * Like in systemd, the device is looked up below /sys/bus and /sys/class,
 * and below /sys/firmware for a device without a subsystem, e.g.
 * "devicetree" / "base", and the device that is found must have the
 * requested subsystem and name. A device that does not exist fails with
 * ENODEV; when two different devices are found, e.g. one below /sys/bus
 * and one below /sys/class, the call fails with ETOOMANYREFS.
 *
 * The initial refcount is 1, and needs to be decremented to
 * release the resources of the udev device.
 *
 * Returns: a new udev device, or #NULL, if it does not exist
 **/
_public_ struct udev_device *udev_device_new_from_subsystem_sysname(struct udev *udev, const char *subsystem, const char *sysname)
{
        _cleanup_free_ char *name = NULL;
        struct udev_device *device = NULL;
        char *p;
        int r;

        if (subsystem == NULL || sysname == NULL ||
            !name_is_normalized(subsystem) || !name_is_normalized(sysname)) {
                errno = EINVAL;
                return NULL;
        }

        /* translate sysname back to sysfs filename */
        name = strdup(sysname);
        if (!name) {
                errno = ENOMEM;
                return NULL;
        }
        for (p = name; *p != '\0'; p++)
                if (*p == '/')
                        *p = '!';

        /* Like sd_device_new_from_subsystem_sysname() of systemd: the special subsystems are looked up in
         * their directories first, then every subsystem in the directories of devices */
        if (streq(subsystem, "subsystem")) {
                r = device_new_from_path_join(udev, &device, subsystem, NULL, sysname, "/sys/bus/", name, NULL, NULL);
                if (r >= 0)
                        r = device_new_from_path_join(udev, &device, subsystem, NULL, sysname, "/sys/class/", name, NULL, NULL);
                if (r < 0)
                        goto fail;

        } else if (streq(subsystem, "module")) {
                r = device_new_from_path_join(udev, &device, subsystem, NULL, sysname, "/sys/module/", name, NULL, NULL);
                if (r < 0)
                        goto fail;

        } else if (streq(subsystem, "drivers")) {
                char *sep;

                /* require a ':' and something non-empty after it */
                sep = strchr(name, ':');
                if (sep && sep[1] != '\0') {
                        const char *subsys = name;

                        *(sep++) = '\0';

                        /* If the sysname is "drivers", then it's the drivers directory itself that is meant. */
                        if (streq(sep, "drivers"))
                                r = device_new_from_path_join(udev, &device, subsystem, subsys, "drivers",
                                                              "/sys/bus/", subsys, "/drivers", NULL);
                        else
                                r = device_new_from_path_join(udev, &device, subsystem, subsys, sysname + (sep - name),
                                                              "/sys/bus/", subsys, "/drivers/", sep);
                        sep[-1] = ':';
                        if (r < 0)
                                goto fail;
                }
        }

        r = device_new_from_path_join(udev, &device, subsystem, NULL, sysname, "/sys/bus/", subsystem, "/devices/", name);
        if (r < 0)
                goto fail;

        r = device_new_from_path_join(udev, &device, subsystem, NULL, sysname, "/sys/class/", subsystem, name, NULL);
        if (r < 0)
                goto fail;

        /* Note that devices under /sys/firmware/ (e.g. /sys/firmware/devicetree/base/) do not have
         * subsystem. Hence, pass NULL for subsystem. See issue #35861 of systemd. */
        r = device_new_from_path_join(udev, &device, NULL, NULL, sysname, "/sys/firmware/", subsystem, name, NULL);
        if (r < 0)
                goto fail;

        if (!device) {
                errno = ENODEV;
                return NULL;
        }

        return device;
fail:
        udev_device_unref(device);
        errno = -r;
        return NULL;
}

/**
 * udev_device_new_from_environment
 * @udev: udev library context
 *
 * Create new udev device, and fill in information from the
 * current process environment. This only works reliable if
 * the process is called from a udev rule. It is usually used
 * for tools executed from IMPORT= rules.
 *
 * The initial refcount is 1, and needs to be decremented to
 * release the resources of the udev device.
 *
 * Returns: a new udev device, or #NULL, if it does not exist
 **/
_public_ struct udev_device *udev_device_new_from_environment(struct udev *udev)
{
        int i;
        struct udev_device *udev_device;

        udev_device = udev_device_new(udev);
        if (udev_device == NULL)
                return NULL;
        udev_device_set_info_loaded(udev_device);

        /* the tags in the environment of an older udevd are all current */
        udev_device->database_version = 0;

        for (i = 0; environ[i] != NULL; i++)
                if (udev_device_add_property_from_string_parse(udev_device, environ[i]) < 0) {
                        log_debug("invalid property, invalid device");
                        return udev_device_unref(udev_device);
                }

        if (udev_device_add_property_from_string_parse_finish(udev_device) < 0) {
                log_debug("missing values, invalid device");
                udev_device_unref(udev_device);
                udev_device = NULL;
        }

        return udev_device;
}

/* Like device_new_from_child() of systemd: the parent is the first directory above the device, up to the
 * directories directly below /sys, that is a device itself, see udev_device_new_from_syspath(). The walk
 * stops with ENODEV when there is none, and with any other error of udev_device_new_from_syspath(), e.g.
 * EACCES or ENOMEM. */
static int device_new_from_parent(struct udev_device *udev_device, struct udev_device **ret)
{
        _cleanup_free_ char *path = NULL;

        path = strdup(udev_device->syspath);
        if (!path)
                return -ENOMEM;

        for (;;) {
                struct udev_device *parent;
                char *pos;

                pos = strrchr(path, '/');
                if (!pos || pos == path + strlen("/sys"))
                        return -ENODEV;
                *pos = '\0';

                parent = udev_device_new_from_syspath(udev_device->udev, path);
                if (parent) {
                        *ret = parent;
                        return 0;
                }
                if (errno != ENODEV)
                        return -errno;
        }
}

/**
 * udev_device_get_parent:
 * @udev_device: the device to start searching from
 *
 * Find the next parent device, and fill in information from the sys
 * device and the udev database entry.
 *
 * Returned device is not referenced. It is attached to the child
 * device, and will be cleaned up when the child device is cleaned up.
 *
 * It is not necessarily just the upper level directory, empty or not
 * recognized sys directories are ignored.
 *
 * It can be called as many times as needed, without caring about
 * references.
 *
 * Returns: a new udev device, or #NULL, if it no parent exist.
 **/
_public_ struct udev_device *udev_device_get_parent(struct udev_device *udev_device)
{
        if (udev_device == NULL) {
                errno = EINVAL;
                return NULL;
        }
        if (!udev_device->parent_set) {
                struct udev_device *parent = NULL;
                int r;

                /* like sd_device_get_parent() of systemd, an error is returned, but not cached, so that
                 * the next call tries again; that there is no parent is cached */
                r = device_new_from_parent(udev_device, &parent);
                if (r < 0 && r != -ENODEV) {
                        errno = -r;
                        return NULL;
                }
                udev_device->parent_device = parent;
                udev_device->parent_set = true;
        }
        /* the lookup of the parent is cached, also set errno on subsequent calls */
        if (udev_device->parent_device == NULL)
                errno = ENOENT;
        return udev_device->parent_device;
}

/**
 * udev_device_get_parent_with_subsystem_devtype:
 * @udev_device: udev device to start searching from
 * @subsystem: the subsystem of the device
 * @devtype: the type (DEVTYPE) of the device
 *
 * Find the next parent device, with a matching subsystem and devtype
 * value, and fill in information from the sys device and the udev
 * database entry.
 *
 * If devtype is #NULL, only subsystem is checked, and any devtype will
 * match.
 *
 * Returned device is not referenced. It is attached to the child
 * device, and will be cleaned up when the child device is cleaned up.
 *
 * It can be called as many times as needed, without caring about
 * references.
 *
 * Returns: a new udev device, or #NULL if no matching parent exists.
 **/
_public_ struct udev_device *udev_device_get_parent_with_subsystem_devtype(struct udev_device *udev_device, const char *subsystem, const char *devtype)
{
        struct udev_device *parent;

        if (subsystem == NULL) {
                errno = EINVAL;
                return NULL;
        }

        parent = udev_device_get_parent(udev_device);
        while (parent != NULL) {
                const char *parent_subsystem;
                const char *parent_devtype;

                parent_subsystem = udev_device_get_subsystem(parent);
                if (parent_subsystem != NULL && streq(parent_subsystem, subsystem)) {
                        if (devtype == NULL)
                                break;
                        parent_devtype = udev_device_get_devtype(parent);
                        if (parent_devtype != NULL && streq(parent_devtype, devtype))
                                break;
                }
                parent = udev_device_get_parent(parent);
        }

        /* without a matching parent, errno is the one of the last udev_device_get_parent(): ENOENT, or the
         * error that stopped the walk, like sd_device_get_parent_with_subsystem_devtype() of systemd */
        return parent;
}

/**
 * udev_device_get_udev:
 * @udev_device: udev device
 *
 * Retrieve the udev library context the device was created with.
 *
 * Returns: the udev library context
 **/
_public_ struct udev *udev_device_get_udev(struct udev_device *udev_device)
{
        if (udev_device == NULL)
                return NULL;
        return udev_device->udev;
}

/**
 * udev_device_ref:
 * @udev_device: udev device
 *
 * Take a reference of a udev device.
 *
 * Returns: the passed udev device
 **/
_public_ struct udev_device *udev_device_ref(struct udev_device *udev_device)
{
        if (udev_device == NULL)
                return NULL;
        udev_device->refcount++;
        return udev_device;
}

/**
 * udev_device_unref:
 * @udev_device: udev device
 *
 * Drop a reference of a udev device. If the refcount reaches zero,
 * the resources of the device will be released.
 *
 * Returns: #NULL
 **/
_public_ struct udev_device *udev_device_unref(struct udev_device *udev_device)
{
        if (udev_device == NULL)
                return NULL;
        udev_device->refcount--;
        if (udev_device->refcount > 0)
                return NULL;
        if (udev_device->parent_device != NULL)
                udev_device_unref(udev_device->parent_device);
        free(udev_device->syspath);
        free(udev_device->sysname);
        free(udev_device->devnode);
        free(udev_device->subsystem);
        free(udev_device->devtype);
        udev_list_cleanup(&udev_device->devlinks_list);
        udev_list_cleanup(&udev_device->properties_list);
        udev_list_cleanup(&udev_device->sysattr_value_list);
        udev_list_cleanup(&udev_device->sysattr_list);
        udev_list_cleanup(&udev_device->tags_list);
        udev_list_cleanup(&udev_device->current_tags_list);
        free(udev_device->action);
        free(udev_device->driver);
        free(udev_device->devpath_old);
        free(udev_device->parse_major);
        free(udev_device->parse_minor);
        free(udev_device->id_filename);
        free(udev_device->envp);
        free(udev_device->monitor_buf);
        free(udev_device);
        return NULL;
}

/**
 * udev_device_get_devpath:
 * @udev_device: udev device
 *
 * Retrieve the kernel devpath value of the udev device. The path
 * does not contain the sys mount point, and starts with a '/'.
 *
 * Returns: the devpath of the udev device
 **/
_public_ const char *udev_device_get_devpath(struct udev_device *udev_device)
{
        if (udev_device == NULL)
                return NULL;
        return udev_device->devpath;
}

/**
 * udev_device_get_syspath:
 * @udev_device: udev device
 *
 * Retrieve the sys path of the udev device. The path is an
 * absolute path and starts with the sys mount point.
 *
 * Returns: the sys path of the udev device
 **/
_public_ const char *udev_device_get_syspath(struct udev_device *udev_device)
{
        if (udev_device == NULL)
                return NULL;
        return udev_device->syspath;
}

/**
 * udev_device_get_sysname:
 * @udev_device: udev device
 *
 * Get the kernel device name in /sys.
 *
 * Returns: the name string of the device device
 **/
_public_ const char *udev_device_get_sysname(struct udev_device *udev_device)
{
        if (udev_device == NULL)
                return NULL;
        return udev_device->sysname;
}

/**
 * udev_device_get_sysnum:
 * @udev_device: udev device
 *
 * Get the instance number of the device.
 *
 * Returns: the trailing number string of the device name
 **/
_public_ const char *udev_device_get_sysnum(struct udev_device *udev_device)
{
        if (udev_device == NULL)
                return NULL;
        return udev_device->sysnum;
}

/**
 * udev_device_get_devnode:
 * @udev_device: udev device
 *
 * Retrieve the device node file name belonging to the udev device.
 * The path is an absolute path, and starts with the device directory.
 *
 * Returns: the device node file name of the udev device, or #NULL if no device node exists
 **/
_public_ const char *udev_device_get_devnode(struct udev_device *udev_device)
{
        if (udev_device == NULL)
                return NULL;
        if (udev_device->devnode != NULL)
                return udev_device->devnode;
        if (!udev_device->info_loaded)
                udev_device_read_uevent_file(udev_device);
        return udev_device->devnode;
}

/**
 * udev_device_get_devlinks_list_entry:
 * @udev_device: udev device
 *
 * Retrieve the list of device links pointing to the device file of
 * the udev device. The next list entry can be retrieved with
 * udev_list_entry_get_next(), which returns #NULL if no more entries exist.
 * The devlink path can be retrieved from the list entry by
 * udev_list_entry_get_name(). The path is an absolute path, and starts with
 * the device directory.
 *
 * Returns: the first entry of the device node link list
 **/
_public_ struct udev_list_entry *udev_device_get_devlinks_list_entry(struct udev_device *udev_device)
{
        if (udev_device == NULL)
                return NULL;
        if (!udev_device->info_loaded)
                udev_device_read_db(udev_device);
        return udev_list_get_entry(&udev_device->devlinks_list);
}

void udev_device_cleanup_devlinks_list(struct udev_device *udev_device)
{
        udev_device->devlinks_uptodate = false;
        udev_list_cleanup(&udev_device->devlinks_list);
}

/* Joins the names of the list entries, with the separator between them, and optionally also before the
 * first and after the last one, like systemd's set_strjoin(). */
static char *list_strjoin(struct udev_list_entry *first, const char *separator, bool wrap)
{
        struct udev_list_entry *list_entry;
        size_t len = 0, sep = strlen(separator);
        char *buf, *s;

        udev_list_entry_foreach(list_entry, first)
                len += strlen(udev_list_entry_get_name(list_entry)) + sep;
        if (wrap)
                len += sep;

        buf = malloc(len + 1);
        if (!buf)
                return NULL;

        s = buf;
        if (wrap)
                s = stpcpy(s, separator);
        udev_list_entry_foreach(list_entry, first) {
                if (list_entry != first)
                        s = stpcpy(s, separator);
                s = stpcpy(s, udev_list_entry_get_name(list_entry));
        }
        if (wrap && first)
                s = stpcpy(s, separator);
        *s = '\0';

        return buf;
}

/* Sets TAGS= or CURRENT_TAGS= to ":tag1:tag2:", or unsets it when there are no tags. */
static void udev_device_set_tags_property(struct udev_device *udev_device, const char *key, struct udev_list_entry *first)
{
        _cleanup_free_ char *tags = NULL;

        if (!first) {
                udev_device_add_property_internal(udev_device, key, NULL);
                return;
        }

        tags = list_strjoin(first, ":", true);
        if (!tags) {
                log_oom();
                return;
        }
        udev_device_add_property_internal(udev_device, key, tags);
}

/**
 * udev_device_get_properties_list_entry:
 * @udev_device: udev device
 *
 * Retrieve the list of key/value device properties of the udev
 * device. The next list entry can be retrieved with udev_list_entry_get_next(),
 * which returns #NULL if no more entries exist. The property name
 * can be retrieved from the list entry by udev_list_entry_get_name(),
 * the property value by udev_list_entry_get_value().
 *
 * Like the properties of sd-device of systemd, they are listed in the order in which
 * they were added, not sorted: e.g. for a device read from sys, DEVPATH, the properties
 * of the uevent file, SUBSYSTEM, then the ones of the udev database, and DEVLINKS, TAGS
 * and CURRENT_TAGS last; for a device received from a monitor, in the order of the
 * message.
 *
 * Returns: the first entry of the property list
 **/
_public_ struct udev_list_entry *udev_device_get_properties_list_entry(struct udev_device *udev_device)
{
        if (udev_device == NULL)
                return NULL;
        if (!udev_device->info_loaded) {
                udev_device_read_uevent_file(udev_device);
                udev_device_read_db(udev_device);
        }
        if (!udev_device->devlinks_uptodate) {
                struct udev_list_entry *list_entry;

                udev_device->devlinks_uptodate = true;
                list_entry = udev_device_get_devlinks_list_entry(udev_device);
                if (list_entry != NULL) {
                        _cleanup_free_ char *symlinks = NULL;

                        symlinks = list_strjoin(list_entry, " ", false);
                        if (symlinks)
                                udev_device_add_property_internal(udev_device, "DEVLINKS", symlinks);
                        else
                                log_oom();
                } else
                        udev_device_add_property_internal(udev_device, "DEVLINKS", NULL);
        }
        if (!udev_device->tags_uptodate) {
                udev_device->tags_uptodate = true;
                udev_device_set_tags_property(udev_device, "TAGS", udev_device_get_tags_list_entry(udev_device));
                udev_device_set_tags_property(udev_device, "CURRENT_TAGS", udev_list_get_entry(&udev_device->current_tags_list));
        }
        return udev_list_get_entry(&udev_device->properties_list);
}

/**
 * udev_device_get_action:
 * @udev_device: udev device
 *
 * This is only valid if the device was received through a monitor. Devices read from
 * sys do not have an action string. Usual actions are: add, remove, change, online,
 * offline.
 *
 * Returns: the kernel action value, or #NULL if there is no action value available.
 **/
_public_ const char *udev_device_get_action(struct udev_device *udev_device)
{
        if (udev_device == NULL)
                return NULL;
        return udev_device->action;
}

/**
 * udev_device_get_usec_since_initialized:
 * @udev_device: udev device
 *
 * Return the number of microseconds passed since udev set up the
 * device for the first time.
 *
 * This is only implemented for devices with need to store properties
 * in the udev database. All other devices return 0 here.
 *
 * Returns: the number of microseconds since the device was first seen.
 **/
_public_ unsigned long long int udev_device_get_usec_since_initialized(struct udev_device *udev_device)
{
        usec_t now_ts;

        if (udev_device == NULL)
                return 0;
        if (!udev_device->info_loaded)
                udev_device_read_db(udev_device);
        if (udev_device->usec_initialized == 0)
                return 0;
        now_ts = now(CLOCK_MONOTONIC);
        if (now_ts == 0)
                return 0;
        return now_ts - udev_device->usec_initialized;
}

usec_t udev_device_get_usec_initialized(struct udev_device *udev_device)
{
        return udev_device->usec_initialized;
}

/* Checks that the path of an attribute, i.e. the syspath and the name of the attribute, stays below
 * /sys when resolved, like device_chase() of systemd does before reading or writing an attribute: e.g.
 * a name like "../../../../etc/passwd", a symlink out of sysfs in the path, or a syspath that was taken
 * as it was, e.g. "/sys/../tmp" from DEVPATH= of udev_device_new_from_environment(), is refused.
 * Attributes of parent devices, like "../idVendor", stay below /sys and are fine. */
static int sysattr_check_path(const char *path, char **ret_resolved)
{
        _cleanup_free_ char *resolved = NULL;
        int r;

        r = sysfs_resolve(path, &resolved);
        if (r == -ENODEV)
                r = -EINVAL; /* like systemd, also without a message */
        if (r < 0)
                return r;

        if (ret_resolved)
                *ret_resolved = TAKE_PTR(resolved);
        return 0;
}

/* Like systemd, caches that the attribute cannot be read, with the error, except when out of memory,
 * which may be transient. Returns NULL with errno set. */
static const char *sysattr_cache_error(struct udev_device *udev_device, const char *sysattr, int error)
{
        struct udev_list_entry *list_entry;

        error = abs(error);
        if (error != ENOMEM) {
                list_entry = udev_list_entry_add(&udev_device->sysattr_value_list, sysattr, NULL);
                if (list_entry)
                        udev_list_entry_set_num(list_entry, error);
        }

        errno = error;
        return NULL;
}

/* Looks up the cached value or error of an attribute. Returns true when it is cached, with the value in
 * ret, or NULL and errno set. */
static bool sysattr_cache_get(struct udev_device *udev_device, const char *sysattr, const char **ret)
{
        struct udev_list_entry *list_entry;

        list_entry = udev_list_get_entry(&udev_device->sysattr_value_list);
        list_entry = udev_list_entry_get_by_name(list_entry, sysattr);
        if (!list_entry)
                return false;

        *ret = udev_list_entry_get_value(list_entry);
        if (!*ret)
                errno = udev_list_entry_get_num(list_entry) ?: ENOENT;
        return true;
}

/**
 * udev_device_get_sysattr_value:
 * @udev_device: udev device
 * @sysattr: attribute name
 *
 * The retrieved value is cached in the device. Repeated calls will return the same
 * value and not open the attribute again. So is the error, when it cannot be read.
 *
 * Like in systemd, symlinks are followed, also an attribute that is a symlink, as long as the
 * attribute stays below /sys, except "driver", "subsystem" and "module", whose value is the
 * last element of the target of the symlink.
 *
 * Returns: the content of a sys attribute file, or #NULL if there is no sys attribute value,
 * with errno set, e.g. to EACCES for an attribute that is not readable, EISDIR for a
 * directory, or EINVAL for an attribute outside of /sys.
 **/
_public_ const char *udev_device_get_sysattr_value(struct udev_device *udev_device, const char *sysattr)
{
        _cleanup_free_ char *buf = NULL, *path = NULL, *resolved = NULL, *relative = NULL;
        struct udev_list_entry *list_entry;
        char link_value[UTIL_PATH_SIZE];
        const char *value;
        struct stat statbuf;
        size_t size, len;
        int r;

        if (udev_device == NULL) {
                errno = EINVAL;
                return NULL;
        }
        if (sysattr == NULL) {
                errno = EINVAL;
                return NULL;
        }

        /* look for possibly already cached result, also a failure */
        if (sysattr_cache_get(udev_device, sysattr, &value))
                return value;

        path = strjoin(udev_device_get_syspath(udev_device), "/", sysattr, NULL);
        if (!path) {
                errno = ENOMEM;
                return NULL;
        }

        /*
         * Some core links return only the last element of the target path,
         * these are just values, the paths should not be exposed. Like in
         * systemd, they are read like other attributes when they are no
         * symlinks.
         */
        if (streq(sysattr, "driver") ||
            streq(sysattr, "subsystem") ||
            streq(sysattr, "module")) {
                if (lstat(path, &statbuf) != 0)
                        return sysattr_cache_error(udev_device, sysattr, errno);

                if (S_ISLNK(statbuf.st_mode)) {
                        if (util_get_sys_core_link_value(udev_device->udev, sysattr,
                                                         udev_device->syspath, link_value, sizeof(link_value)) < 0)
                                return sysattr_cache_error(udev_device, sysattr, ENOENT);
                        value = link_value;
                        goto cache;
                }
        }

        /* Like systemd, follow the symlinks of the path, also of its last component, but do not read
         * outside of sysfs. When the path cannot be resolved, the error is cached under the name as
         * given, else under the resolved path relative to the device. */
        r = sysattr_check_path(path, &resolved);
        if (r < 0)
                return sysattr_cache_error(udev_device, sysattr, r);

        r = path_make_relative(udev_device_get_syspath(udev_device), resolved, &relative);
        if (r < 0)
                return sysattr_cache_error(udev_device, sysattr, r);

        /* look for a cached result of the resolved path */
        if (sysattr_cache_get(udev_device, relative, &value))
                return value;

        /* Like systemd, read the whole value, of up to READ_VIRTUAL_BYTES_MAX (4 MiB). Some attributes contain
         * NUL bytes; the value ends at the first one, as it is a string. Unlike systemd, which says EBADF for
         * any file that is not a regular file, a directory fails with EISDIR, like before the attributes were
         * resolved, and like in systemd before v258. */
        r = read_virtual_file(resolved, SIZE_MAX, &buf, &size);
        if (r == -EBADF && stat(resolved, &statbuf) == 0 && S_ISDIR(statbuf.st_mode))
                r = -EISDIR;
        if (r < 0)
                return sysattr_cache_error(udev_device, relative, r);

        /* got a valid value, store it in cache and return it */
        /* drop trailing newlines, including carriage returns */
        len = strlen(buf);
        while (len > 0 && strchr(NEWLINE, buf[len - 1]))
                buf[--len] = '\0';
        value = buf;
        sysattr = relative;
cache:
        list_entry = udev_list_entry_add(&udev_device->sysattr_value_list, sysattr, value);
        if (!list_entry) {
                errno = ENOMEM;
                return NULL;
        }
        return udev_list_entry_get_value(list_entry);
}

/* Removes the cached value or error of an attribute. */
static void sysattr_cache_remove(struct udev_device *udev_device, const char *sysattr)
{
        struct udev_list_entry *list_entry;

        list_entry = udev_list_get_entry(&udev_device->sysattr_value_list);
        list_entry = udev_list_entry_get_by_name(list_entry, sysattr);
        if (list_entry != NULL)
                udev_list_entry_delete(list_entry);
}

/* Like chase() with CHASE_NONEXISTENT: resolves the part of the path that exists, see sysattr_check_path(),
 * and appends the rest. */
static int sysattr_check_path_nonexistent(const char *path, char **ret_resolved)
{
        _cleanup_free_ char *parent = NULL, *resolved = NULL;
        const char *base;
        int r;

        r = sysattr_check_path(path, ret_resolved);
        if (r != -ENOENT)
                return r;

        base = strrchr(path, '/');
        if (!base || base == path)
                return r;

        parent = strndup(path, base - path);
        if (!parent)
                return -ENOMEM;
        base++;

        r = sysattr_check_path_nonexistent(parent, &resolved);
        if (r < 0)
                return r;

        if (isempty(base) || streq(base, "."))
                *ret_resolved = TAKE_PTR(resolved);
        else if (streq(base, ".."))
                return path_get_parent(resolved, ret_resolved);
        else {
                *ret_resolved = strjoin(resolved, "/", base, NULL);
                if (!*ret_resolved)
                        return -ENOMEM;
        }
        return 0;
}

/* After the attribute with the resolved path relative relative to the device was written, forgets the
 * errors cached for it under any name. An error is cached under the name as given when the name cannot be
 * resolved, e.g. because the attribute does not exist yet, see udev_device_get_sysattr_value(), so a name
 * with a symlink or ".." in it kept the error after a successful write, as it does in systemd. */
static void sysattr_cache_forget_errors(struct udev_device *udev_device, const char *relative)
{
        struct udev_list_entry *entry, *tmp;

        udev_list_entry_foreach_safe(entry, tmp, udev_list_get_entry(&udev_device->sysattr_value_list)) {
                _cleanup_free_ char *path = NULL, *resolved = NULL, *r = NULL;
                const char *name = udev_list_entry_get_name(entry);

                if (udev_list_entry_get_value(entry))
                        continue;

                if (!streq(name, relative)) {
                        path = strjoin(udev_device_get_syspath(udev_device), "/", name, NULL);
                        if (!path ||
                            sysfs_resolve(path, &resolved) < 0 ||
                            path_make_relative(udev_device_get_syspath(udev_device), resolved, &r) < 0 ||
                            !streq(r, relative))
                                continue;
                }

                udev_list_entry_delete(entry);
        }
}

/* Like the cache of systemd, a value written into "uevent", also in a subdirectory, is not cached, as it is
 * an action, not the value. */
static bool sysattr_is_uevent(const char *sysattr)
{
        const char *p = strrchr(sysattr, '/');

        return streq(p ? p + 1 : sysattr, "uevent");
}

/**
 * udev_device_set_sysattr_value:
 * @udev_device: udev device
 * @sysattr: attribute name
 * @value: new value to be set
 *
 * Update the contents of the sys attribute and the cached value of the device.
 * When the value was written, the errors that were cached for the attribute, also
 * under other names of it, are forgotten.
 *
 * Returns: Negative error code on failure or 0 on success.
 **/
_public_ int udev_device_set_sysattr_value(struct udev_device *udev_device, const char *sysattr, char *value)
{
        _cleanup_free_ char *v = NULL, *path = NULL, *resolved = NULL, *relative = NULL;
        ssize_t size;
        size_t len;
        int fd, r;

        if (udev_device == NULL)
                return -EINVAL;
        if (sysattr == NULL)
                return -EINVAL;

        path = strjoin(udev_device_get_syspath(udev_device), "/", sysattr, NULL);
        if (!path)
                return -ENOMEM;

        if (value == NULL) {
                /* Like systemd, remove the cached value of the resolved path, also of a path that does not
                 * exist, without writing anything. */
                r = sysattr_check_path_nonexistent(path, &resolved);
                if (r < 0)
                        return r;
                r = path_make_relative(udev_device_get_syspath(udev_device), resolved, &relative);
                if (r < 0)
                        return r;
                sysattr_cache_remove(udev_device, relative);
                return 0;
        }

        /* Like systemd, follow the symlinks of the path, also of its last component, and do not write
         * outside of sysfs; a missing attribute fails with ENOENT. On failure, clear the cache entry of
         * the name as given, hoping that it is the normalized one, like systemd does. */
        r = sysattr_check_path(path, &resolved);
        if (r >= 0)
                r = path_make_relative(udev_device_get_syspath(udev_device), resolved, &relative);
        if (r < 0) {
                sysattr_cache_remove(udev_device, sysattr);
                return r;
        }

        /* Like systemd, the value length is limited to 4k: a longer value is truncated. Then trailing
         * newlines, including carriage returns, are dropped. */
        v = strndup(value, 4096);
        if (v == NULL)
                return -ENOMEM;

        len = strlen(v);
        while (len > 0 && strchr(NEWLINE, v[len - 1]))
                v[--len] = '\0';

        /* Do not check the permissions of the attribute, write-only attributes like "remove" are
         * fine. Let the kernel do it and propagate the error. */
        fd = open(resolved, O_WRONLY|O_CLOEXEC|O_NOFOLLOW);
        if (fd < 0)
                r = -errno;
        else {
                size = write(fd, v, len);
                if (size < 0)
                        r = -errno;
                else if ((size_t) size != len)
                        r = -EIO;
                else
                        r = 0;
                close(fd);
        }
        if (r < 0) {
                /* On failure, clear cache entry, as we do not know how it fails. */
                sysattr_cache_remove(udev_device, relative);
                return r;
        }

        sysattr_cache_forget_errors(udev_device, relative);

        /* Like systemd, cache the written value under the resolved path relative to the device, where
         * udev_device_get_sysattr_value() finds it, also for other names of the attribute. */
        if (sysattr_is_uevent(relative))
                return 0;

        if (udev_list_entry_add(&udev_device->sysattr_value_list, relative, v) == NULL) {
                /* The value has been written, hence do not fail. But do not leave a cache
                 * entry without a value behind, which would make the attribute look absent. */
                log_debug("failed to cache sysfs attribute value '%s', ignoring", relative);
                sysattr_cache_remove(udev_device, relative);
        }
        return 0;
}

/* Update the cached value of a sys attribute without writing it, e.g. when 'udevadm test' skips a write.
 * sysattr is the resolved path relative to the device, as udev_device_get_sysattr_value() caches it.
 * Returns 1 when cached, 0 when not (the "uevent" file is never cached). */
int udev_device_cache_sysattr_value(struct udev_device *udev_device, const char *sysattr, const char *value)
{
        _cleanup_free_ char *v = NULL;
        size_t len;

        if (udev_device == NULL || sysattr == NULL || value == NULL)
                return -EINVAL;

        sysattr_cache_forget_errors(udev_device, sysattr);

        /* like udev_device_set_sysattr_value(), do not cache the action string written into uevent */
        if (sysattr_is_uevent(sysattr))
                return 0;

        /* drop trailing newlines, including carriage returns */
        len = strlen(value);
        while (len > 0 && strchr(NEWLINE, value[len - 1]))
                len--;

        v = strndup(value, len);
        if (v == NULL)
                return -ENOMEM;

        if (udev_list_entry_add(&udev_device->sysattr_value_list, sysattr, v) == NULL) {
                /* do not leave a cache entry without a value behind */
                sysattr_cache_remove(udev_device, sysattr);
                return -ENOMEM;
        }

        return 1;
}

/* Adds the attributes in the directory subdir of the device, or in the device directory itself, to the
 * list of attributes, and its subdirectories to the stack. Like device_sysattrs_read_all_internal() of
 * systemd: a subdirectory with a uevent file is a child device, and is skipped. Returns the number of
 * added attributes. */
static int sysattr_list_read_dir(struct udev_device *udev_device, const char *subdir,
                                 char ***stack, size_t *n_stack, size_t *n_allocated)
{
        _cleanup_closedir_ DIR *dir = NULL;
        _cleanup_free_ char *path = NULL;
        struct dirent *dent;
        int num = 0;

        if (subdir) {
                path = strjoin(udev_device->syspath, "/", subdir, NULL);
                if (!path)
                        return -ENOMEM;
        }

        dir = opendir(path ?: udev_device->syspath);
        if (!dir) {
                if (subdir && errno == ENOENT)
                        return 0; /* maybe a child device, which is removed already */
                return -errno;
        }

        if (subdir) {
                if (faccessat(dirfd(dir), "uevent", F_OK, 0) >= 0)
                        return 0; /* a child device, skipping */
                if (errno != ENOENT) {
                        log_debug_errno(errno, "failed to access %s/uevent, ignoring sub-directory %s: %m",
                                        path, subdir);
                        return 0;
                }
        }

        for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
                _cleanup_free_ char *name = NULL;
                struct stat statbuf;

                if (streq(dent->d_name, ".") || streq(dent->d_name, ".."))
                        continue;

                /* only handle symlinks, regular files, and directories */
                if (!IN_SET(dent->d_type, DT_LNK, DT_REG, DT_DIR))
                        continue;

                name = subdir ? strjoin(subdir, "/", dent->d_name, NULL) : strdup(dent->d_name);
                if (!name)
                        return -ENOMEM;

                if (dent->d_type == DT_DIR) {
                        /* push the sub-directory onto the stack, and read it later */
                        if (!GREEDY_REALLOC(*stack, *n_allocated, *n_stack + 1))
                                return -ENOMEM;
                        (*stack)[(*n_stack)++] = TAKE_PTR(name);
                        continue;
                }

                if (fstatat(dirfd(dir), dent->d_name, &statbuf, AT_SYMLINK_NOFOLLOW) < 0)
                        continue;

                /* also attributes that are write-only, like "remove" */
                if ((statbuf.st_mode & (S_IRUSR | S_IWUSR)) == 0)
                        continue;

                if (!udev_list_entry_add(&udev_device->sysattr_list, name, NULL))
                        return -ENOMEM;
                num++;
        }

        return num;
}

/* Like device_sysattrs_read_all() of systemd: the attributes of the device, and of its subdirectories,
 * e.g. "power/control", but not of child devices. */
static int udev_device_sysattr_list_read(struct udev_device *udev_device)
{
        char **stack = NULL;
        size_t n_stack = 0, n_allocated = 0;
        int num = 0, r;

        if (udev_device == NULL)
                return -EINVAL;
        if (udev_device->sysattr_list_read)
                return 0;

        r = sysattr_list_read_dir(udev_device, NULL, &stack, &n_stack, &n_allocated);
        while (r >= 0) {
                num += r;

                if (n_stack == 0)
                        break;

                _cleanup_free_ char *subdir = stack[--n_stack];

                r = sysattr_list_read_dir(udev_device, subdir, &stack, &n_stack, &n_allocated);
        }

        while (n_stack > 0)
                free(stack[--n_stack]);
        free(stack);

        if (r < 0) {
                udev_list_cleanup(&udev_device->sysattr_list);
                return r;
        }

        udev_device->sysattr_list_read = true;

        return num;
}

/**
 * udev_device_get_sysattr_list_entry:
 * @udev_device: udev device
 *
 * Retrieve the list of available sysattrs, with value being empty;
 * This just return all available sysfs attributes for a particular
 * device without reading their values.
 *
 * Returns: the first entry of the property list
 **/
_public_ struct udev_list_entry *udev_device_get_sysattr_list_entry(struct udev_device *udev_device)
{
        if (udev_device == NULL) {
                errno = EINVAL;
                return NULL;
        }
        if (!udev_device->sysattr_list_read) {
                int ret;
                ret = udev_device_sysattr_list_read(udev_device);
                if (0 > ret)
                        return NULL;
        }

        return udev_list_get_entry(&udev_device->sysattr_list);
}

/* Like systemd's path_is_safe(): the path is not empty, shorter than PATH_MAX, has no component
 * longer than NAME_MAX, and no ".." component. */
static bool devname_is_safe(const char *p)
{
        if (isempty(p) || strlen(p) >= PATH_MAX)
                return false;

        for (;;) {
                size_t n;

                p += strspn(p, "/");
                if (*p == '\0')
                        return true;

                n = strcspn(p, "/");
                if (n > NAME_MAX)
                        return false;
                if (n == 2 && p[0] == '.' && p[1] == '.')
                        return false;
                p += n;
        }
}

/* Drops duplicated and trailing slashes and "." components of an absolute path, like systemd's
 * path_simplify(). */
static void devname_simplify(char *path)
{
        const char *f = path;
        char *t = path;

        for (;;) {
                f += strspn(f, "/");
                if (f[0] == '.' && IN_SET(f[1], '/', '\0')) {
                        f++;
                        continue;
                }
                if (*f == '\0')
                        break;

                *(t++) = '/';
                while (!IN_SET(*f, '/', '\0'))
                        *(t++) = *(f++);
        }

        if (t == path)
                *(t++) = '/';
        *t = '\0';
}

/* Returns the device node or symlink path prefixed with "/dev/" and simplified. The path must be
 * safe, an absolute path must be below /dev/, and neither may contain control characters, which
 * would break the database. */
static int mangle_devname(const char *p, char **ret)
{
        char *q;

        if (!devname_is_safe(p) || string_has_cc(p, NULL))
                return -EINVAL;

        /* When the path is absolute, it must start with "/dev/", but ignore "/dev/" itself. */
        if (p[0] == '/') {
                if (isempty(path_startswith(p, "/dev/")))
                        return -EINVAL;

                q = strdup(p);
        } else
                q = strjoin("/dev/", p, NULL);
        if (!q)
                return -ENOMEM;

        devname_simplify(q);

        /* "/dev/." and friends are simplified to "/dev" */
        if (isempty(path_startswith(q, "/dev/"))) {
                free(q);
                return -EINVAL;
        }

        *ret = q;
        return 0;
}

static int udev_device_set_devnode(struct udev_device *udev_device, const char *devnode)
{
        char *t;
        int r;

        r = mangle_devname(devnode, &t);
        if (r < 0)
                return r;

        free(udev_device->devnode);
        udev_device->devnode = t;
        udev_device_add_property_internal(udev_device, "DEVNAME", udev_device->devnode);
        return 0;
}

/* Like device_add_devlink() of systemd: returns 1 when the symlink was added, 0 when the device has it
 * already. */
int udev_device_add_devlink(struct udev_device *udev_device, const char *devlink)
{
        _cleanup_free_ char *p = NULL;
        struct udev_list_entry *list_entry;
        bool added;
        int r;

        r = mangle_devname(devlink, &p);
        if (r < 0)
                return r;

        added = !udev_list_entry_get_by_name(udev_list_get_entry(&udev_device->devlinks_list), p);

        udev_device->devlinks_uptodate = false;
        list_entry = udev_list_entry_add(&udev_device->devlinks_list, p, NULL);
        if (list_entry == NULL)
                return -ENOMEM;
        return added;
}

int udev_device_remove_devlink(struct udev_device *udev_device, const char *devlink)
{
        _cleanup_free_ char *p = NULL;
        struct udev_list_entry *list_entry;
        int r;

        r = mangle_devname(devlink, &p);
        if (r < 0)
                return r;

        list_entry = udev_list_get_entry(&udev_device->devlinks_list);
        list_entry = udev_list_entry_get_by_name(list_entry, p);
        if (list_entry == NULL)
                return 0;

        udev_device->devlinks_uptodate = false;
        udev_list_entry_delete(list_entry);
        return 1;
}

/* Like sd_device_get_driver_subsystem() of systemd: for the devices of the "drivers" pseudo-subsystem, i.e.
 * /sys/bus/SUBSYSTEM/drivers/DRIVER and the directory /sys/bus/SUBSYSTEM/drivers itself, the real subsystem:
 * the path component before "/drivers/" or "/drivers", in a new string. -ENOENT for the devices of other
 * subsystems, -EINVAL if the devpath has no such component. */
int device_get_driver_subsystem(struct udev_device *udev_device, char **ret)
{
        const char *devpath, *drivers, *p;
        char *s;

        assert(udev_device);
        assert(ret);

        if (!streq_ptr(udev_device_get_subsystem(udev_device), "drivers"))
                return -ENOENT;

        devpath = udev_device->devpath;
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

        s = strndup(p, drivers - p);
        if (!s)
                return -ENOMEM;

        *ret = s;
        return 0;
}

const char *udev_device_get_id_filename(struct udev_device *udev_device)
{
        if (udev_device->id_filename == NULL) {
                if (udev_device_get_subsystem(udev_device) == NULL)
                        return NULL;

                if (major(udev_device_get_devnum(udev_device)) > 0) {
                        /* use dev_t -- b259:131072, c254:0 */
                        if (asprintf(&udev_device->id_filename, "%c%u:%u",
                                     streq(udev_device_get_subsystem(udev_device), "block") ? 'b' : 'c',
                                     major(udev_device_get_devnum(udev_device)),
                                     minor(udev_device_get_devnum(udev_device))) < 0)
                                udev_device->id_filename = NULL;
                } else if (udev_device_get_ifindex(udev_device) > 0) {
                        /* use netdev ifindex -- n3 */
                        if (asprintf(&udev_device->id_filename, "n%i", udev_device_get_ifindex(udev_device)) < 0)
                                udev_device->id_filename = NULL;
                } else {
                        /*
                         * use $subsys:$syname -- pci:0000:00:1f.2
                         * sysname() has '!' translated, get it from devpath
                         */
                        const char *sysname;
                        sysname = strrchr(udev_device->devpath, '/');
                        if (sysname == NULL)
                                return NULL;
                        sysname = &sysname[1];

                        if (streq(udev_device_get_subsystem(udev_device), "drivers")) {
                                _cleanup_free_ char *subsystem = NULL;

                                /* the 'drivers' pseudo-subsystem is special, and needs the real subsystem
                                 * encoded as well */
                                if (device_get_driver_subsystem(udev_device, &subsystem) < 0)
                                        return NULL;
                                if (asprintf(&udev_device->id_filename, "+drivers:%s:%s", subsystem, sysname) < 0)
                                        udev_device->id_filename = NULL;
                        } else if (asprintf(&udev_device->id_filename, "+%s:%s", udev_device_get_subsystem(udev_device), sysname) < 0)
                                udev_device->id_filename = NULL;
                }
        }
        return udev_device->id_filename;
}

/**
 * udev_device_get_is_initialized:
 * @udev_device: udev device
 *
 * Check if udev has already handled the device and has set up
 * device node permissions and context, or has renamed a network
 * device.
 *
 * This is only implemented for devices with a device node
 * or network interfaces. All other devices return 1 here.
 *
 * Returns: 1 if the device is set up. 0 otherwise.
 **/
_public_ int udev_device_get_is_initialized(struct udev_device *udev_device)
{
        if (udev_device == NULL)
                return -EINVAL;
        if (!udev_device->info_loaded)
                udev_device_read_db(udev_device);
        return udev_device->is_initialized;
}

void udev_device_set_is_initialized(struct udev_device *udev_device)
{
        udev_device->is_initialized = true;
}

/* All tags are managed under /run/udev/tags, and the directories there are
 * named with tags. Hence, each tag must be a valid filename. */
static bool is_valid_tag(const char *tag)
{
        return tag[0] != '\0' &&
                tag[strspn(tag, "abcdefghijklmnopqrstuvwxyz"
                                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                "0123456789-_")] == '\0';
}

/* Adds the tag to all tags, which are sticky, and with both, also to the current tags. */
int udev_device_add_tag(struct udev_device *udev_device, const char *tag, bool both)
{
        struct udev_list_entry *e;
        bool added;

        if (!is_valid_tag(tag))
                return -EINVAL;

        /* Definitely add to the "all" list of tags (i.e. the sticky list) */
        added = !udev_list_entry_get_by_name(udev_list_get_entry(&udev_device->tags_list), tag);
        e = udev_list_entry_add(&udev_device->tags_list, tag, NULL);
        if (!e)
                return -ENOMEM;

        /* And optionally, also add it to the current list of tags */
        if (both && !udev_list_entry_add(&udev_device->current_tags_list, tag, NULL)) {
                if (added)
                        udev_list_entry_delete(e);
                return -ENOMEM;
        }

        udev_device->tags_uptodate = false;
        return 0;
}

/* Removes the tag from the current tags. It stays in all tags. */
void udev_device_remove_tag(struct udev_device *udev_device, const char *tag)
{
        struct udev_list_entry *e;

        if (!is_valid_tag(tag))
                return;
        e = udev_list_get_entry(&udev_device->current_tags_list);
        e = udev_list_entry_get_by_name(e, tag);
        if (e) {
                udev_device->tags_uptodate = false;
                udev_list_entry_delete(e);
        }
}

/* Clears the current tags, and resets all tags to those of the original device, i.e. of the database
 * entry of the device, dropping the tags added by this event, but keeping the sticky ones. */
int udev_device_cleanup_tags(struct udev_device *udev_device, struct udev_device *original)
{
        struct udev_list_entry *e, *tmp, *original_tags = NULL;

        udev_device->tags_uptodate = false;
        udev_list_cleanup(&udev_device->current_tags_list);

        if (original)
                original_tags = udev_device_get_tags_list_entry(original);

        udev_list_entry_foreach_safe(e, tmp, udev_list_get_entry(&udev_device->tags_list))
                if (!udev_list_entry_get_by_name(original_tags, udev_list_entry_get_name(e)))
                        udev_list_entry_delete(e);

        udev_list_entry_foreach(e, original_tags) {
                int r;

                r = udev_device_add_tag(udev_device, udev_list_entry_get_name(e), false);
                if (r < 0)
                        return r;
        }

        return 0;
}

/**
 * udev_device_get_tags_list_entry:
 * @udev_device: udev device
 *
 * Retrieve the list of tags attached to the udev device. Tags are "sticky":
 * once set by a uevent, they remain attached to the device until it is
 * removed, see udev_device_get_current_tags_list_entry() for the tags of the
 * most recent uevent. The next list entry can be retrieved with
 * udev_list_entry_get_next(), which returns #NULL if no more entries exist.
 * The tag string can be retrieved from the list entry by
 * udev_list_entry_get_name().
 *
 * Returns: the first entry of the tag list
 **/
_public_ struct udev_list_entry *udev_device_get_tags_list_entry(struct udev_device *udev_device)
{
        if (udev_device == NULL)
                return NULL;
        if (!udev_device->info_loaded)
                udev_device_read_db(udev_device);
        return udev_list_get_entry(&udev_device->tags_list);
}

/* The tags assigned by the latest event, as stored in the Q: lines of the database. */
struct udev_list_entry *udev_device_get_current_tags_list_entry_raw(struct udev_device *udev_device)
{
        if (!udev_device->info_loaded)
                udev_device_read_db(udev_device);
        return udev_list_get_entry(&udev_device->current_tags_list);
}

/**
 * udev_device_get_current_tags_list_entry:
 * @udev_device: udev device
 *
 * Retrieve the list of tags attached to the udev device by the most recent
 * uevent. Tags are "sticky": once set, they remain attached to the device
 * until it is removed, see udev_device_get_tags_list_entry(). The next list
 * entry can be retrieved with udev_list_entry_get_next(), which returns #NULL
 * if no more entries exist. The tag string can be retrieved from the list
 * entry by udev_list_entry_get_name().
 *
 * Returns: the first entry of the current tag list
 **/
static bool device_database_supports_current_tags(struct udev_device *udev_device)
{
        if (!udev_device->info_loaded)
                udev_device_read_db(udev_device);

        /* The current tags (saved in Q field) feature is implemented in database version 1.
         * If the database version is 0, then the tags (NOT current tags, saved in G field) are not
         * sticky. Thus, we can safely bypass the operations for the current tags (Q) to tags (G). */

        return udev_device->database_version >= 1;
}

_public_ struct udev_list_entry *udev_device_get_current_tags_list_entry(struct udev_device *udev_device)
{
        if (udev_device == NULL)
                return NULL;
        if (!device_database_supports_current_tags(udev_device))
                return udev_device_get_tags_list_entry(udev_device);
        return udev_device_get_current_tags_list_entry_raw(udev_device);
}

/**
 * udev_device_has_tag:
 * @udev_device: udev device
 * @tag: tag name
 *
 * Check if a given device has a certain tag associated, by the most
 * recent or an earlier uevent, as tags are "sticky".
 *
 * Returns: 1 if the tag is found. 0 otherwise.
 **/
_public_ int udev_device_has_tag(struct udev_device *udev_device, const char *tag)
{
        struct udev_list_entry *list_entry;

        if (udev_device == NULL || tag == NULL)
                return false;
        if (!udev_device->info_loaded)
                udev_device_read_db(udev_device);
        list_entry = udev_device_get_tags_list_entry(udev_device);
        if (udev_list_entry_get_by_name(list_entry, tag) != NULL)
                return true;
        return false;
}

/**
 * udev_device_has_current_tag:
 * @udev_device: udev device
 * @tag: tag name
 *
 * Check if a given device has a certain tag associated by the most recent
 * uevent.
 *
 * Returns: 1 if the tag is found. 0 otherwise.
 **/
_public_ int udev_device_has_current_tag(struct udev_device *udev_device, const char *tag)
{
        struct udev_list_entry *list_entry;

        if (udev_device == NULL || tag == NULL)
                return false;
        /* for database version 0, udev_device_get_current_tags_list_entry() returns all tags */
        list_entry = udev_device_get_current_tags_list_entry(udev_device);
        if (udev_list_entry_get_by_name(list_entry, tag) != NULL)
                return true;
        return false;
}

/* Builds the buffer of "KEY=VALUE" strings of the properties, which is sent to udevd workers and
 * libudev monitors, and the environment of the programs udevd runs, which points into the buffer.
 * Like systemd's device_update_properties_bufs(), without a fixed limit of their size. Like there,
 * private properties, with a leading ".", are included; they are only not stored in the database. */
/* Like device_update_properties_bufs() of systemd: the properties as "KEY=VALUE" strings, after the database
 * version, one after the other in a buffer for monitor messages, and as an array for the environment of
 * programs. The properties are walked only once, so that the buffer always fits them, also when getting them
 * reads the database, which may add properties. */
static int update_envp_monitor_buf(struct udev_device *udev_device)
{
        char version[STRLEN("UDEV_DATABASE_VERSION=") + DECIMAL_STR_MAX(unsigned) + 1];
        struct udev_list_entry *list_entry;
        _cleanup_free_ char *buf = NULL;
        size_t allocated = 0, len, n = 1, i;
        char **envp, *s;

        snprintf(version, sizeof(version), "UDEV_DATABASE_VERSION=%u", LATEST_UDEV_DATABASE_VERSION);
        len = strlen(version) + 1;
        if (!GREEDY_REALLOC(buf, allocated, len))
                return -ENOMEM;
        memcpy(buf, version, len);

        udev_list_entry_foreach(list_entry, udev_device_get_properties_list_entry(udev_device)) {
                const char *key = udev_list_entry_get_name(list_entry);
                const char *value = udev_list_entry_get_value(list_entry);
                size_t l = strlen(key) + 1 + strlen(value) + 1;

                if (!GREEDY_REALLOC(buf, allocated, len + l))
                        return -ENOMEM;
                stpcpy(stpcpy(stpcpy(buf + len, key), "="), value);
                len += l;
                n++;
        }

        envp = new(char *, n + 1);
        if (!envp)
                return -ENOMEM;
        for (i = 0, s = buf; i < n; i++, s += strlen(s) + 1)
                envp[i] = s;
        envp[n] = NULL;
        assert((size_t) (s - buf) == len);

        free(udev_device->monitor_buf);
        free(udev_device->envp);
        udev_device->monitor_buf = TAKE_PTR(buf);
        udev_device->monitor_buf_len = len;
        udev_device->envp = envp;
        udev_device->envp_uptodate = true;
        return 0;
}

char **udev_device_get_properties_envp(struct udev_device *udev_device)
{
        if (!udev_device->envp_uptodate)
                if (update_envp_monitor_buf(udev_device) != 0)
                        return NULL;
        return udev_device->envp;
}

ssize_t udev_device_get_properties_monitor_buf(struct udev_device *udev_device, const char **buf)
{
        if (!udev_device->envp_uptodate)
                if (update_envp_monitor_buf(udev_device) != 0)
                        return -EINVAL;
        *buf = udev_device->monitor_buf;
        return udev_device->monitor_buf_len;
}

int udev_device_get_devlink_priority(struct udev_device *udev_device)
{
        if (!udev_device->info_loaded)
                udev_device_read_db(udev_device);
        return udev_device->devlink_priority;
}

int udev_device_set_devlink_priority(struct udev_device *udev_device, int prio)
{
         udev_device->devlink_priority = prio;
        return 0;
}

int udev_device_get_watch_handle(struct udev_device *udev_device)
{
        if (!udev_device->info_loaded)
                udev_device_read_db(udev_device);
        return udev_device->watch_handle;
}

int udev_device_set_watch_handle(struct udev_device *udev_device, int handle)
{
        udev_device->watch_handle = handle;
        return 0;
}

bool udev_device_get_db_persist(struct udev_device *udev_device)
{
        return udev_device->db_persist;
}

void udev_device_set_db_persist(struct udev_device *udev_device)
{
        udev_device->db_persist = true;
}

int udev_device_rename(struct udev_device *udev_device, const char *name)
{
        _cleanup_free_ char *dirname = NULL;
        const char *interface;
        char *new_syspath;
        int r;

        if (udev_device == NULL || name == NULL)
                return -EINVAL;

        dirname = dirname_malloc(udev_device->syspath);
        if (!dirname)
                return -ENOMEM;

        new_syspath = strjoina(dirname, "/", name);

        r = udev_device_set_syspath(udev_device, new_syspath);
        if (r < 0)
                return r;

        interface = udev_device_get_property_value(udev_device, "INTERFACE");
        if (interface) {
                /* like DEVPATH_OLD, INTERFACE_OLD is not saved to the db, but only stays around for the current event */
                udev_device_add_property_internal(udev_device, "INTERFACE_OLD", interface);
                udev_device_add_property_internal(udev_device, "INTERFACE", name);
        }

        return 0;
}

struct udev_device *udev_device_shallow_clone(struct udev_device *old_device)
{
        struct udev_device *device;

        if (old_device == NULL)
                return NULL;

        device = udev_device_new(old_device->udev);
        if (!device) {
                errno = ENOMEM;

                return NULL;
        }

        udev_device_set_syspath(device, udev_device_get_syspath(old_device));
        udev_device_set_subsystem(device, udev_device_get_subsystem(old_device));
        udev_device_set_devnum(device, udev_device_get_devnum(old_device));

        return device;
}

struct udev_device *udev_device_clone_with_db(struct udev_device *old_device)
{
        struct udev_device *device;

        device = udev_device_shallow_clone(old_device);
        if (!device)
                return NULL;

        udev_device_read_db(device);
        udev_device_set_info_loaded(device);

        return device;
}

struct udev_device *udev_device_new_from_nulstr(struct udev *udev, char *nulstr, ssize_t buflen) {
        struct udev_device *device;
        ssize_t bufpos = 0;

        if (nulstr == NULL || buflen <= 0) {
                errno = EINVAL;

                return NULL;
        }

        device = udev_device_new(udev);
        if (!device) {
                errno = ENOMEM;

                return NULL;
        }

        udev_device_set_info_loaded(device);

        /* the tags in a message of an older udevd are all current */
        device->database_version = 0;

        while (bufpos < buflen) {
                char *key;
                size_t keylen;

                key = nulstr + bufpos;
                keylen = strnlen(key, buflen - bufpos);
                if ((ssize_t) keylen == buflen - bufpos) {
                        /* the last string is not NUL terminated */
                        log_debug("failed to parse nulstr, invalid device");

                        udev_device_unref(device);

                        errno = EINVAL;

                        return NULL;
                }

                bufpos += keylen + 1;

                /* netlink messages for some devices contain an unwanted newline at the end of value.
                 * Let's drop the newline and remaining characters after the newline. */
                key[strcspn(key, NEWLINE)] = '\0';

                if (udev_device_add_property_from_string_parse(device, key) < 0) {
                        log_debug("invalid property, invalid device");

                        udev_device_unref(device);

                        errno = EINVAL;

                        return NULL;
                }
        }

        if (udev_device_add_property_from_string_parse_finish(device) < 0) {
                log_debug("missing values, invalid device");

                udev_device_unref(device);

                errno = EINVAL;

                return NULL;
        }

        return device;
}

struct udev_device *udev_device_new_from_synthetic_event(struct udev *udev, const char *syspath, const char *action) {
        struct udev_device *ret;
        int r;

        if (!action) {
                errno = EINVAL;
                return NULL;
        }

        ret = udev_device_new_from_syspath(udev, syspath);
        if (!ret)
                return NULL;

        r = udev_device_read_uevent_file(ret);
        if (r < 0) {
                udev_device_unref(ret);
                errno = -r;
                return NULL;
        }

        r = udev_device_set_action(ret, action);
        if (r < 0) {
                udev_device_unref(ret);
                errno = -r;
                return NULL;
        }

        return ret;
}

int udev_device_copy_properties(struct udev_device *dst, struct udev_device *src) {
        struct udev_list_entry *entry;

        for ((entry = udev_device_get_properties_list_entry(src)); entry; entry = udev_list_entry_get_next(entry)) {
                const char *key, *value;

                /* Only the properties stored in the database, like the properties_db of systemd's
                 * sd-device. The others, like DEVPATH, DEVLINKS or TAGS, are set by libudev from the
                 * device itself, and must not become properties of the database. */
                if (!udev_list_entry_get_num(entry))
                        continue;

                key = udev_list_entry_get_name(entry);
                value = udev_list_entry_get_value(entry);

                udev_device_add_property(dst, key, value);
        }

        return 0;
}
