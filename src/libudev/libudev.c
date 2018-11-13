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
#include "strv.h"

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
        /* timeout_signal= in udev.conf for udevd, 0 if it is not set; an invalid value is ignored, and
         * remembered, so that udevd warns about it */
        int timeout_signal;
        bool timeout_signal_invalid;
        /* children_max=, exec_delay= and event_timeout= in udev.conf for udevd, 0 if they are not set; an
         * invalid value is ignored, and a message about it is added to conf_warnings */
        unsigned children_max;
        usec_t exec_delay_usec;
        usec_t event_timeout_usec;
        /* the messages about invalid settings of udevd in udev.conf, which udevd logs as warnings */
        char **conf_warnings;
        void (*log_fn)(struct udev *udev,
                       int priority, const char *file, int line, const char *fn,
                       const char *format, va_list args);
        void *userdata;
        bool sas_legacy_path;
        char *net_naming_scheme;
        int net_altnames;
        char *net_altnames_invalid; /* the invalid value of net_altnames=, "" if it is empty */
};

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

/* Like log_syntax_parse_error() of systemd, but the message is only logged at debug level here, and
 * remembered, so that udevd can warn about it, while the other users of libudev do not complain about the
 * settings of udevd. */
static void udev_conf_parse_error(struct udev *udev, const char *filename, unsigned line,
                                  const char *key, const char *value, int error) {
        _cleanup_free_ char *escaped = NULL;
        char *m;

        escaped = cescape(value);
        errno = abs(error);
        if (asprintf(&m, "%s:%u: Failed to parse %s=%s, ignoring: %m", filename, line, key, escaped ?: value) < 0)
                return;

        log_debug("%s", m);
        (void) strv_consume(&udev->conf_warnings, m);
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
                        while (isspace((unsigned char) key[0]))
                                key++;

                        /* comment or empty line */
                        if (key[0] == '#' || key[0] == '\0')
                                continue;

                        /* split key/value */
                        val = strchr(key, '=');
                        if (val == NULL) {
                                log_debug("%s:%u: missing assignment, skipping line.", filename, line_nr);
                                continue;
                        }
                        val[0] = '\0';
                        val++;

                        /* find value */
                        while (isspace((unsigned char) val[0]))
                                val++;

                        /* terminate key */
                        len = strlen(key);
                        if (len == 0)
                                continue;
                        while (isspace((unsigned char) key[len-1]))
                                len--;
                        key[len] = '\0';

                        /* terminate value */
                        len = strlen(val);
                        if (len == 0) {
                                /* an empty value is invalid, which udevd warns about, see below */
                                if (streq(key, "net_altnames")) {
                                        log_debug("%s:%u: empty net_altnames=, ignoring.", filename, line_nr);
                                        udev->net_altnames = -EINVAL;
                                        free(udev->net_altnames_invalid);
                                        udev->net_altnames_invalid = strdup("");
                                } else if (streq(key, "children_max") || streq(key, "exec_delay") ||
                                           streq(key, "event_timeout"))
                                        /* like systemd's parsers of these values */
                                        udev_conf_parse_error(udev, filename, line_nr, key, val, -EINVAL);
                                continue;
                        }
                        while (isspace((unsigned char) val[len-1]))
                                len--;
                        val[len] = '\0';

                        if (len == 0)
                                continue;

                        /* unquote */
                        if (val[0] == '"' || val[0] == '\'') {
                                if (len == 1 || val[len-1] != val[0]) {
                                        log_debug("%s:%u: inconsistent quoting, skipping line.", filename, line_nr);
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
                                        log_debug("%s:%u: invalid log level '%s', ignoring.", filename, line_nr, val);
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

                        if (streq(key, "net_altnames")) {
                                int b;

                                /* an invalid value is kept as -EINVAL, which udevd warns about */
                                b = parse_boolean(val);
                                if (b < 0)
                                        log_debug("%s:%u: invalid boolean '%s' for net_altnames, ignoring.", filename, line_nr, val);
                                udev->net_altnames = b < 0 ? -EINVAL : b;
                                free(udev->net_altnames_invalid);
                                udev->net_altnames_invalid = b < 0 ? strdup(val) : NULL;
                                continue;
                        }

                        if (streq(key, "net_naming_scheme")) {
                                /* validated by the net_id builtin, which knows the schemes; an
                                 * empty value, e.g. "", resets it */
                                free(udev->net_naming_scheme);
                                udev->net_naming_scheme = val[0] != '\0' ? strdup(val) : NULL;
                                continue;
                        }

                        if (streq(key, "children_max")) {
                                unsigned n;
                                int r;

                                r = safe_atou(val, &n);
                                if (r < 0)
                                        udev_conf_parse_error(udev, filename, line_nr, key, val, r);
                                else
                                        udev->children_max = n;
                                continue;
                        }

                        if (streq(key, "exec_delay") || streq(key, "event_timeout")) {
                                usec_t t;
                                int r;

                                r = parse_sec(val, &t);
                                if (r < 0)
                                        udev_conf_parse_error(udev, filename, line_nr, key, val, r);
                                else if (streq(key, "exec_delay"))
                                        udev->exec_delay_usec = t;
                                else
                                        udev->event_timeout_usec = t;
                                continue;
                        }

                        if (streq(key, "timeout_signal")) {
                                int sig;

                                sig = signal_from_string(val);
                                if (sig < 0) {
                                        log_debug("%s:%u: invalid signal '%s' for timeout_signal, ignoring.", filename, line_nr, val);
                                        udev->timeout_signal_invalid = true;
                                } else
                                        udev->timeout_signal = sig;
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
        udev->net_altnames = 1;

        udev_read_conf(udev, UDEV_CONF_FILE);

        return udev;
}

/* Not part of the public API, used by udevd. Return children_max=, exec_delay= and event_timeout= in udev.conf,
 * or 0 if they are not set. */
unsigned udev_get_children_max(struct udev *udev) {
        if (udev == NULL)
                return 0;
        return udev->children_max;
}

usec_t udev_get_exec_delay_usec(struct udev *udev) {
        if (udev == NULL)
                return 0;
        return udev->exec_delay_usec;
}

usec_t udev_get_event_timeout_usec(struct udev *udev) {
        if (udev == NULL)
                return 0;
        return udev->event_timeout_usec;
}

/* Not part of the public API, used by udevd. Returns the messages about the invalid settings of udevd in
 * udev.conf, which udevd logs as warnings, or NULL if there are none. */
char **udev_get_conf_warnings(struct udev *udev) {
        if (udev == NULL)
                return NULL;
        return udev->conf_warnings;
}

/* Not part of the public API, used by udevd. Returns the signal of timeout_signal= in udev.conf, or 0 if it is
 * not set, and whether an invalid value was ignored. */
int udev_get_timeout_signal(struct udev *udev, bool *ret_invalid) {
        if (ret_invalid)
                *ret_invalid = udev && udev->timeout_signal_invalid;
        if (udev == NULL)
                return 0;
        return udev->timeout_signal;
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
        free(tmp.net_naming_scheme);
        free(tmp.net_altnames_invalid);
        strv_free(tmp.conf_warnings);

        return tmp.hwdb_format;
}

/* Not part of the public API, used by the path_id builtin. */
bool udev_get_sas_legacy_path(struct udev *udev) {
        if (udev == NULL)
                return false;
        return udev->sas_legacy_path;
}

/* Not part of the public API, used by the net_id builtin. Returns the value of
 * net_naming_scheme= in udev.conf, or NULL if it is not set. */
const char *udev_get_net_naming_scheme(struct udev *udev) {
        if (udev == NULL)
                return NULL;
        return udev->net_naming_scheme;
}

/* Not part of the public API, used by udevd. Returns the value of net_altnames= in udev.conf: 1 if it is not
 * set, or -EINVAL if it is invalid or empty, which is to be treated like 1. */
int udev_get_net_altnames(struct udev *udev) {
        if (udev == NULL)
                return 1;
        return udev->net_altnames;
}

/* Not part of the public API, used by udevd. Returns the value of net_altnames= in udev.conf if it is
 * invalid, "" if it is empty, and NULL if it is valid or not set. */
const char *udev_get_net_altnames_invalid(struct udev *udev) {
        if (udev == NULL)
                return NULL;
        return udev->net_altnames_invalid;
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
        free(udev->net_naming_scheme);
        free(udev->net_altnames_invalid);
        strv_free(udev->conf_warnings);
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
