/***
  This file is part of systemd.

  Copyright 2008-2014 Kay Sievers <kay@vrfy.org>

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
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#include "libudev.h"
#include "libudev-private.h"
#include "missing.h"

/**
 * SECTION:libudev
 * @short_description: libudev context
 *
 * The context contains the default values read from the udev config file,
 * and is passed to all library operations.
 */

/**
 * udev:
 *
 * Opaque object representing the library context.
 */
struct udev {
        int refcount;
        /* format of hwdb.bin created by 'udevadm hwdb', hwdb_format= in udev.conf, negative if invalid */
        int hwdb_format;
        void (*log_fn)(struct udev *udev,
                       int priority, const char *file, int line, const char *fn,
                       const char *format, va_list args);
        void *userdata;
        bool sas_legacy_path;
};

static int parse_boolean(const char *v) {
        if (streq(v, "1") || strcaseeq(v, "yes") || strcaseeq(v, "y") ||
            strcaseeq(v, "true") || strcaseeq(v, "t") || strcaseeq(v, "on"))
                return 1;
        if (streq(v, "0") || strcaseeq(v, "no") || strcaseeq(v, "n") ||
            strcaseeq(v, "false") || strcaseeq(v, "f") || strcaseeq(v, "off"))
                return 0;
        return -EINVAL;
}

/**
 * udev_get_userdata:
 * @udev: udev library context
 *
 * Retrieve stored data pointer from library context. This might be useful
 * to access from callbacks.
 *
 * Returns: stored userdata
 **/
_public_ void *udev_get_userdata(struct udev *udev) {
        if (udev == NULL)
                return NULL;
        return udev->userdata;
}

/**
 * udev_set_userdata:
 * @udev: udev library context
 * @userdata: data pointer
 *
 * Store custom @userdata in the library context.
 **/
_public_ void udev_set_userdata(struct udev *udev, void *userdata) {
        if (udev == NULL)
                return;
        udev->userdata = userdata;
}

int udev_parse_hwdb_format(const char *s) {
        if (streq(s, "1"))
                return 1;
        if (streq(s, "2"))
                return 2;
        return -EINVAL;
}

static void udev_read_conf(struct udev *udev, const char *filename) {
        _cleanup_fclose_ FILE *f = NULL;

        f = fopen(filename, "re");
        if (f != NULL) {
                char line[UTIL_LINE_SIZE];
                unsigned line_nr = 0;

                while (fgets(line, sizeof(line), f)) {
                        size_t len;
                        char *key;
                        char *val;

                        line_nr++;

                        /* find key */
                        key = line;
                        while (isspace(key[0]))
                                key++;

                        /* comment or empty line */
                        if (key[0] == '#' || key[0] == '\0')
                                continue;

                        /* split key/value */
                        val = strchr(key, '=');
                        if (val == NULL) {
                                log_debug(UDEV_CONF_FILE ":%u: missing assignment,  skipping line.", line_nr);
                                continue;
                        }
                        val[0] = '\0';
                        val++;

                        /* find value */
                        while (isspace(val[0]))
                                val++;

                        /* terminate key */
                        len = strlen(key);
                        if (len == 0)
                                continue;
                        while (isspace(key[len-1]))
                                len--;
                        key[len] = '\0';

                        /* terminate value */
                        len = strlen(val);
                        if (len == 0)
                                continue;
                        while (isspace(val[len-1]))
                                len--;
                        val[len] = '\0';

                        if (len == 0)
                                continue;

                        /* unquote */
                        if (val[0] == '"' || val[0] == '\'') {
                                if (len == 1 || val[len-1] != val[0]) {
                                        log_debug(UDEV_CONF_FILE ":%u: inconsistent quoting, skipping line.", line_nr);
                                        continue;
                                }
                                val[len-1] = '\0';
                                val++;
                        }

                        if (streq(key, "hwdb_format")) {
                                udev->hwdb_format = udev_parse_hwdb_format(val);
                                if (udev->hwdb_format < 0)
                                        log_debug("%s:%u: invalid hwdb_format '%s'.", filename, line_nr, val);
                                continue;
                        }

                        if (streq(key, "udev_log")) {
                                int prio;

                                prio = util_log_priority(val);
                                if (prio < 0)
                                        log_debug("/etc/udev/udev.conf:%u: invalid log level '%s', ignoring.", line_nr, val);
                                else
                                        log_set_max_level(prio);
                                continue;
                        }

                        if (streq(key, "sas_legacy_path")) {
                                int b;

                                b = parse_boolean(val);
                                if (b < 0)
                                        log_debug("%s:%u: invalid boolean '%s' for sas_legacy_path, ignoring.", filename, line_nr, val);
                                else
                                        udev->sas_legacy_path = b;
                                continue;
                        }
                }
        }
}

/**
 * udev_new:
 *
 * Create udev library context. This reads the udev configuration
 * file, and fills in the default values.
 *
 * The initial refcount is 1, and needs to be decremented to
 * release the resources of the udev library context.
 *
 * Returns: a new udev library context
 **/
_public_ struct udev *udev_new(void) {
        struct udev *udev;

        udev = new0(struct udev, 1);
        if (udev == NULL)
                return NULL;
        udev->refcount = 1;
        udev->hwdb_format = 1;

        udev_read_conf(udev, UDEV_CONF_FILE);

        return udev;
}

/* Returns the format of hwdb.bin configured with hwdb_format= in udev.conf, 1 or 2, or
 * -EINVAL if the configured value is invalid. */
int udev_get_hwdb_format(struct udev *udev) {
        if (udev == NULL)
                return 1;
        return udev->hwdb_format;
}

/* Like udev_get_hwdb_format(), but reads the udev.conf below the specified root directory,
 * e.g. when creating hwdb.bin for an offline image. */
int udev_read_hwdb_format(const char *root) {
        struct udev tmp = {
                .refcount = 1,
                .hwdb_format = 1,
        };
        _cleanup_free_ char *filename = NULL;
        int level;

        filename = strjoin(root, "/", UDEV_CONF_FILE, NULL);
        if (filename == NULL)
                return -ENOMEM;

        /* do not apply udev_log= of the configuration below the root */
        level = log_get_max_level();
        udev_read_conf(&tmp, filename);
        log_set_max_level(level);

        return tmp.hwdb_format;
}

/* Not part of the public API, used by the path_id builtin. */
bool udev_get_sas_legacy_path(struct udev *udev) {
        if (udev == NULL)
                return false;
        return udev->sas_legacy_path;
}

/**
 * udev_ref:
 * @udev: udev library context
 *
 * Take a reference of the udev library context.
 *
 * Returns: the passed udev library context
 **/
_public_ struct udev *udev_ref(struct udev *udev) {
        if (udev == NULL)
                return NULL;
        udev->refcount++;
        return udev;
}

/**
 * udev_unref:
 * @udev: udev library context
 *
 * Drop a reference of the udev library context. If the refcount
 * reaches zero, the resources of the context will be released.
 *
 * Returns: the passed udev library context if it has still an active reference, or #NULL otherwise.
 **/
_public_ struct udev *udev_unref(struct udev *udev) {
        if (udev == NULL)
                return NULL;
        udev->refcount--;
        if (udev->refcount > 0)
                return udev;
        free(udev);
        return NULL;
}

/**
 * udev_set_log_fn:
 * @udev: udev library context
 * @log_fn: function to be called for log messages
 *
 * This function is deprecated.
 *
 **/
_public_ void udev_set_log_fn(struct udev *udev __attribute__((unused)),
                     void (*log_fn)(struct udev *udev,
                                    int priority, const char *file, int line, const char *fn,
                                    const char *format, va_list args) __attribute__((unused))) {
        return;
}

/**
 * udev_get_log_priority:
 * @udev: udev library context
 *
 * This function is deprecated.
 *
 **/
_public_ int udev_get_log_priority(struct udev *udev __attribute__((unused))) {
        return log_get_max_level();
}

/**
 * udev_set_log_priority:
 * @udev: udev library context
 * @priority: the new log priority
 *
 * This function is deprecated.
 *
 **/
_public_ void udev_set_log_priority(struct udev *udev __attribute__((unused)), int priority) {
        log_set_max_level(priority);
}
