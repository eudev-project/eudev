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

#include <sys/stat.h>

#include "libudev.h"
#include "libudev-private.h"
#include "conf-files.h"
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
        /* timeout_signal=, children_max=, exec_delay= and event_timeout= in udev.conf for udevd, 0 if they
         * are not set; an invalid value is ignored, and a message about it is added to conf_warnings */
        int timeout_signal;
        unsigned children_max;
        usec_t exec_delay_usec;
        usec_t event_timeout_usec;
        /* resolve_names= in udev.conf for udevd, see udev_parse_resolve_names(), if resolve_names_set */
        int resolve_names;
        bool resolve_names_set;
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
 * settings of udevd. With error 0, the reason is that the signal of timeout_signal= cannot terminate a
 * process. */
static void udev_conf_parse_error(struct udev *udev, const char *filename, unsigned line,
                                  const char *key, const char *value, int error) {
        _cleanup_free_ char *escaped = NULL;
        char *m;
        int r;

        escaped = cescape(value);
        errno = abs(error);
        if (error == 0)
                r = asprintf(&m, "%s:%u: %s=%s cannot terminate a process, ignoring.", filename, line, key, escaped ?: value);
        else
                r = asprintf(&m, "%s:%u: Failed to parse %s=%s, ignoring: %m", filename, line, key, escaped ?: value);
        if (r < 0)
                return;

        log_debug("%s", m);
        (void) strv_consume(&udev->conf_warnings, m);
}

/* Not part of the public API, used by udevd. Parses the value of resolve_names= in udev.conf and of
 * --resolve-names=: 1 for "early", 0 for "late" and -1 for "never", as udev_rules_new() takes it. */
int udev_parse_resolve_names(const char *s, int *ret) {
        if (streq(s, "early"))
                *ret = 1;
        else if (streq(s, "late"))
                *ret = 0;
        else if (streq(s, "never"))
                *ret = -1;
        else
                return -EINVAL;

        return 0;
}

/* Reads the configuration file path; the messages name it filename. */
static void udev_read_conf(struct udev *udev, const char *path, const char *filename) {
        _cleanup_fclose_ FILE *f = NULL;

        f = fopen(path, "re");
        if (f != NULL) {
                /* on the heap, to keep the stack small for the programs that call udev_new() */
                _cleanup_free_ char *line = NULL;
                unsigned line_nr = 0;

                line = malloc(UTIL_LINE_SIZE);
                if (!line) {
                        log_oom_debug();
                        return;
                }

                while (fgets(line, UTIL_LINE_SIZE, f)) {
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
                                           streq(key, "event_timeout") || streq(key, "resolve_names") ||
                                           streq(key, "timeout_signal"))
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

                        if (streq(key, "resolve_names")) {
                                int r;

                                r = udev_parse_resolve_names(val, &udev->resolve_names);
                                if (r < 0)
                                        udev_conf_parse_error(udev, filename, line_nr, key, val, r);
                                else
                                        udev->resolve_names_set = true;
                                continue;
                        }

                        if (streq(key, "timeout_signal")) {
                                int sig;

                                /* refuse signals like SIGCHLD, with which the timeout would not stop
                                 * anything */
                                sig = signal_from_string(val);
                                if (sig < 0)
                                        udev_conf_parse_error(udev, filename, line_nr, key, val, sig);
                                else if (!signal_terminates(sig))
                                        udev_conf_parse_error(udev, filename, line_nr, key, val, 0);
                                else
                                        udev->timeout_signal = sig;
                                continue;
                        }
                }
        }
}

/* The directories of udev.conf and its drop-ins, in the order of precedence, like CONF_PATHS("udev") of systemd:
 * the drop-ins are the files ending with ".conf" in their subdirectories udev.conf.d, sorted by their names,
 * where a file overrides the files with the same name in the later directories. UDEV_LIBEXEC_DIR is systemd's
 * /usr/lib/udev, see also the directories of the rules files in udev-rules.c. */
static const char* const udev_conf_dirs[] = {
        UDEV_CONF_DIR,
        UDEV_ROOT_RUN "/udev",
        "/usr/local/lib/udev",
        UDEV_LIBEXEC_DIR,
#ifdef HAVE_SPLIT_USR
        "/lib/udev",
        "/usr/lib/udev",
#endif
        NULL
};

/* Not part of the public API, also used by udevadm cat. Returns the configuration files of udevd below root, like
 * config_parse_standard_file_with_dropins() of systemd for "udev/udev.conf": the main configuration file, the
 * first udev.conf in the directories of udev_conf_dirs, or NULL, and the drop-ins in their subdirectories
 * udev.conf.d. Like for the rules files, and like systemd's "udevadm cat --config", a mask, i.e. an empty file or
 * a symlink to /dev/null, and a file that is not a regular file are left out; a masked udev.conf hides the ones
 * in the later directories, others do not. flags may add CONF_FILES_WARN, for udevadm cat. */
int udev_conf_files(const char *root, ConfFilesFlags flags,
                    ConfFile **ret_main, ConfFile ***ret_dropins, size_t *ret_n_dropins) {
        _cleanup_strv_free_ char **dirs = NULL;
        ConfFile *main_file = NULL;
        size_t i;
        int r;

        assert(ret_main);
        assert(ret_dropins);
        assert(ret_n_dropins);

        for (i = 0; udev_conf_dirs[i]; i++) {
                r = conf_file_new(strjoina(udev_conf_dirs[i], "/udev.conf"), root,
                                  CONF_FILES_REGULAR | CONF_FILES_FILTER_MASKED, &main_file);
                if (r >= 0 || r == -ERFKILL)
                        break;
                if (r == -ENOMEM)
                        return r;
        }

        for (i = 0; udev_conf_dirs[i]; i++)
                if (strv_extend(&dirs, strjoina(udev_conf_dirs[i], "/udev.conf.d")) < 0) {
                        conf_file_free(main_file);
                        return -ENOMEM;
                }

        r = conf_files_list_strv_full(".conf", root, flags | CONF_FILES_REGULAR | CONF_FILES_FILTER_MASKED,
                                      (const char * const *) dirs, ret_dropins, ret_n_dropins);
        if (r < 0) {
                conf_file_free(main_file);
                return r;
        }

        *ret_main = main_file;
        return 0;
}

/* Like config_parse_many_files() of systemd: reads the main configuration file, and then the drop-ins, see
 * udev_conf_files(); the main file is skipped when it is one of the drop-ins, e.g. a symlink to it, which is read
 * as such. The files are read with their symlinks resolved below root, the messages name them as found. */
static void udev_read_conf_files(struct udev *udev, const char *root) {
        ConfFile *main_file = NULL, **dropins = NULL;
        size_t n_dropins = 0, i;
        int r;

        r = udev_conf_files(root, 0, &main_file, &dropins, &n_dropins);
        if (r < 0) {
                log_debug_errno(r, "Failed to find the udev.conf files, ignoring: %m");
                return;
        }

        if (main_file) {
                struct stat st, st_dropin;

                if (stat(main_file->resolved_path, &st) >= 0)
                        for (i = 0; i < n_dropins; i++)
                                if (stat(dropins[i]->resolved_path, &st_dropin) >= 0 &&
                                    st.st_dev == st_dropin.st_dev && st.st_ino == st_dropin.st_ino) {
                                        log_debug("%s: symlink to/symlinked as drop-in, will be read later.",
                                                  main_file->original_path);
                                        main_file = conf_file_free(main_file);
                                        break;
                                }

                if (main_file)
                        udev_read_conf(udev, main_file->resolved_path, main_file->original_path);
        }

        for (i = 0; i < n_dropins; i++)
                udev_read_conf(udev, dropins[i]->resolved_path, dropins[i]->original_path);

        conf_file_free(main_file);
        conf_file_free_array(dropins, n_dropins);
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

        udev_read_conf_files(udev, NULL);

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

/* Not part of the public API, used by udevd. Returns true and resolve_names= in udev.conf, see
 * udev_parse_resolve_names(), if it is set. */
bool udev_get_resolve_names(struct udev *udev, int *ret) {
        if (udev == NULL || !udev->resolve_names_set)
                return false;
        *ret = udev->resolve_names;
        return true;
}

/* Not part of the public API, used by udevd. Returns the messages about the invalid settings of udevd in
 * udev.conf, which udevd logs as warnings, or NULL if there are none. */
char **udev_get_conf_warnings(struct udev *udev) {
        if (udev == NULL)
                return NULL;
        return udev->conf_warnings;
}

/* Not part of the public API, used by udevd. Returns the signal of timeout_signal= in udev.conf, or 0 if it is
 * not set. */
int udev_get_timeout_signal(struct udev *udev) {
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
        int level;

        /* do not apply udev_log= of the configuration below the root */
        level = log_get_max_level();
        udev_read_conf_files(&tmp, root);
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
