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

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <fcntl.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <sys/param.h>

#include "device-nodes.h"
#include "libudev.h"
#include "libudev-private.h"
#include "utf8.h"
#include "MurmurHash2.h"

/**
 * SECTION:libudev-util
 * @short_description: utils
 *
 * Utilities useful when dealing with devices and device node names.
 */

/* Like udev_resolve_subsys_kernel() of systemd: splits "[<SUBSYSTEM>/<KERNEL>]<attribute>", and looks up the
 * device. Returns the device, and a copy of the attribute, NULL if there is none. Returns -EINVAL if the string
 * does not have the format, or no attribute when need_attr, and the error of the lookup if the device does not
 * exist. */
static int resolve_subsys_kernel(struct udev *udev, const char *string, bool need_attr,
                                 struct udev_device **ret_device, char **ret_attr)
{
        _cleanup_free_ char *temp = NULL;
        char *subsys, *sysname, *attr, *a = NULL;
        struct udev_device *dev;

        if (string[0] != '[')
                return -EINVAL;

        temp = strdup(string);
        if (!temp)
                return -ENOMEM;

        subsys = &temp[1];

        sysname = strchr(subsys, '/');
        if (sysname == NULL)
                return -EINVAL;
        sysname[0] = '\0';
        sysname = &sysname[1];

        attr = strchr(sysname, ']');
        if (attr == NULL)
                return -EINVAL;
        attr[0] = '\0';
        attr = &attr[1];
        if (attr[0] == '/')
                attr = &attr[1];
        if (attr[0] != '\0') {
                a = strdup(attr);
                if (!a)
                        return -ENOMEM;
        } else if (need_attr)
                return -EINVAL;

        dev = udev_device_new_from_subsystem_sysname(udev, subsys, sysname);
        if (dev == NULL) {
                free(a);
                return -errno;
        }

        *ret_device = dev;
        *ret_attr = a;
        return 0;
}

/* handle "[<SUBSYSTEM>/<KERNEL>]<attribute>" format: the path of the attribute, or of the device when there is
 * no attribute, in result. Returns 0, or a negative errno, see resolve_subsys_kernel(). Unlike systemd, which
 * cuts it silently, a path that does not fit into result is refused with -ENAMETOOLONG, like the other
 * truncations of the rules; result may be cut then. */
int util_resolve_subsys_kernel(struct udev *udev, const char *string, char *result, size_t maxsize)
{
        _cleanup_free_ char *attr = NULL;
        struct udev_device *dev;
        bool truncated;
        int r;

        r = resolve_subsys_kernel(udev, string, false, &dev, &attr);
        if (r < 0)
                return r;

        /* result may be string, which resolve_subsys_kernel() does not use any more */
        strscpyl_full(result, maxsize, &truncated, udev_device_get_syspath(dev), attr ? "/" : NULL, attr, NULL);
        if (truncated) {
                log_debug("path '[%s/%s]%s' is too long, refusing.", strna(udev_device_get_subsystem(dev)),
                          udev_device_get_sysname(dev), attr ?: "");
                udev_device_unref(dev);
                return -ENAMETOOLONG;
        }
        log_debug("path '[%s/%s]%s' is '%s'", strna(udev_device_get_subsystem(dev)), udev_device_get_sysname(dev),
                  attr ?: "", result);
        udev_device_unref(dev);
        return 0;
}

/* handle "[<SUBSYSTEM>/<KERNEL>]<attribute>" format: the whole value of the attribute, which may be longer than
 * any buffer, in a new string. Like in systemd, an attribute that does not exist or cannot be read for lack of
 * privileges has an empty value. Returns 0, -EINVAL if there is no attribute, another error of reading the
 * attribute, or one of resolve_subsys_kernel(). */
int util_resolve_subsys_kernel_value(struct udev *udev, const char *string, char **ret_value)
{
        _cleanup_free_ char *attr = NULL;
        struct udev_device *dev;
        const char *val;
        char *v;
        int r;

        r = resolve_subsys_kernel(udev, string, true, &dev, &attr);
        if (r < 0)
                return r;

        val = udev_device_get_sysattr_value(dev, attr);
        if (val == NULL && !IN_SET(errno, EPERM, EACCES, ENOENT)) {
                r = -errno;
                udev_device_unref(dev);
                return r;
        }

        /* the value belongs to the device */
        v = strdup(val ?: "");
        udev_device_unref(dev);
        if (!v)
                return -ENOMEM;

        log_debug("value '%s' is '%s'", string, v);
        *ret_value = v;
        return 0;
}

ssize_t util_get_sys_core_link_value(struct udev *udev __attribute__((unused)), const char *slink, const char *syspath, char *value, size_t size)
{
        char path[UTIL_PATH_SIZE];
        char target[UTIL_PATH_SIZE];
        ssize_t len;
        const char *pos;

        strscpyl(path, sizeof(path), syspath, "/", slink, NULL);
        len = readlink(path, target, sizeof(target));
        if (len <= 0 || len == (ssize_t)sizeof(target))
                return -1;
        target[len] = '\0';
        pos = strrchr(target, '/');
        if (pos == NULL)
                return -1;
        pos = &pos[1];
        return strscpy(value, size, pos);
}

/* Like log_level_from_string() of systemd: a log level by name, e.g. "debug", or as a number from 0 to 7,
 * parsed with safe_atou(), which also takes a "0x", "0o" or "0b" prefix, e.g. "0x7". Returns -EINVAL for
 * anything else. */
int util_log_priority(const char *priority)
{
        int prio;

        prio = log_level_from_string(priority);
        if (prio < 0)
                return -EINVAL;

        return prio;
}

void util_remove_trailing_chars(char *path, char c)
{
        size_t len;

        if (path == NULL)
                return;
        len = strlen(path);
        while (len > 0 && path[len-1] == c)
                path[--len] = '\0';
}

int util_replace_whitespace(const char *str, char *to, size_t len)
{
        size_t i, j;

        /* strip trailing whitespace */
        len = strnlen(str, len);
        while (len && isspace((unsigned char) str[len-1]))
                len--;

        /* strip leading whitespace */
        i = 0;
        while ((i < len) && isspace((unsigned char) str[i]))
                i++;

        j = 0;
        while (i < len) {
                /* substitute multiple whitespace with a single '_' */
                if (isspace((unsigned char) str[i])) {
                        while (isspace((unsigned char) str[i]))
                                i++;
                        to[j++] = '_';
                }
                to[j++] = str[i++];
        }
        to[j] = '\0';
        return j;
}

/* allow chars in whitelist, plain ascii, hex-escaping and valid utf8 */
int util_replace_chars(char *str, const char *white)
{
        size_t i = 0;
        int replaced = 0;

        while (str[i] != '\0') {
                int len;

                if (whitelisted_char_for_devnode(str[i], white)) {
                        i++;
                        continue;
                }

                /* accept hex encoding */
                if (str[i] == '\\' && str[i+1] == 'x') {
                        i += 2;
                        continue;
                }

                /* accept valid utf8 */
                len = utf8_encoded_valid_unichar(&str[i]);
                if (len > 1) {
                        i += len;
                        continue;
                }

                /* if space is allowed, replace whitespace with ordinary space */
                if (isspace((unsigned char) str[i]) && white != NULL && strchr(white, ' ') != NULL) {
                        str[i] = ' ';
                        i++;
                        replaced++;
                        continue;
                }

                /* everything else is replaced with '_' */
                str[i] = '_';
                i++;
                replaced++;
        }
        return replaced;
}

/**
 * udev_util_encode_string:
 * @str: input string to be encoded
 * @str_enc: output string to store the encoded input string
 * @len: maximum size of the output string, which may be
 *       four times as long as the input string
 *
 * Encode all potentially unsafe characters of a string to the
 * corresponding 2 char hex value prefixed by '\x'.
 *
 * Returns: 0 if the entire string was copied, non-zero otherwise.
 **/
_public_ int udev_util_encode_string(const char *str, char *str_enc, size_t len)
{
        return encode_devnode_name(str, str_enc, len);
}

unsigned int util_string_hash32(const char *str)
{
        return MurmurHash2(str, strlen(str), 0);
}

/* get a bunch of bit numbers out of the hash, and set the bits in our bit field */
uint64_t util_string_bloom64(const char *str)
{
        uint64_t bits = 0;
        unsigned int hash = util_string_hash32(str);

        bits |= 1LLU << (hash & 63);
        bits |= 1LLU << ((hash >> 6) & 63);
        bits |= 1LLU << ((hash >> 12) & 63);
        bits |= 1LLU << ((hash >> 18) & 63);
        return bits;
}
