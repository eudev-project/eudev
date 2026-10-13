/*
 * Copyright (C) 2008-2009 Kay Sievers <kay@vrfy.org>
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

#include <dirent.h>
#include <limits.h>
#include <poll.h>
#include <sys/stat.h>

#include "conf-files.h"
#include "path-util.h"
#include "strv.h"
#include "udev-rules-check.h"
#include "udev-util.h"
#include "udevadm-util.h"

struct udev_device *find_device(struct udev *udev,
                                const char *id,
                                const char *prefix) {
        struct udev_device *dev;
        int r;

        assert(udev);
        assert(id);

        dev = udev_device_new_from_device_id(udev, id);
        if (dev)
                return dev;

        r = device_new_from_path(udev, id, &dev);
        if (r >= 0)
                return dev;

        if (prefix && !path_startswith(id, prefix)) {
                _cleanup_free_ char *path = NULL;

                path = path_join(prefix, id);
                if (!path) {
                        errno = ENOMEM;
                        return NULL;
                }

                r = device_new_from_path(udev, path, &dev);
                if (r >= 0)
                        return dev;
        }

        /* Like systemd, a path, i.e. an argument with a slash, is no device, whatever the lookups failed
         * with, e.g. ENOTDIR for a path below a device node, ELOOP, EACCES or ENAMETOOLONG. systemd tries
         * a device unit name if the argument is not a path, eudev has none. */
        errno = strchr(id, '/') ? ENODEV : EINVAL;
        return NULL;
}

struct udev_device *find_device_with_action(struct udev *udev, const char *id, const char *action) {
        _cleanup_udev_device_unref_ struct udev_device *dev = NULL;

        assert(udev);
        assert(id);
        assert(action);

        dev = find_device(udev, id, "/sys");
        if (!dev)
                return NULL;

        /* A new device with the properties of the uevent file and the action. */
        return udev_device_new_from_synthetic_event(udev, udev_device_get_syspath(dev), action);
}

int device_is_processed(struct udev_device *dev) {
        const char *value;
        int r;

        assert(dev);

        /* udev_device_get_is_initialized() only checks if the udev database file exists. However, even if the
         * database file exist, udevd may be still processing the device, e.g. when the udev rules
         * for the device have RUN tokens. See issue #30056. Hence, to check if the device is really
         * processed by udevd, we also need to read ID_PROCESSING property. */

        r = udev_device_get_is_initialized(dev);
        if (r <= 0)
                return r;

        value = udev_device_get_property_value(dev, "ID_PROCESSING");
        if (!value)
                return true; /* If the property does not exist, then it means that the device is processed. */

        r = parse_boolean(value);
        if (r < 0)
                return r;

        return !r;
}

/* Like systemd's device_wait_for_initialization(): waits until udevd processed the device, i.e.
 * until it has an entry in the udev database, without ID_PROCESSING=1. Returns a new reference
 * to a device object with the current state of the device. */
int device_wait_for_initialization(struct udev_device *device, usec_t timeout_usec, struct udev_device **ret) {
        _cleanup_udev_monitor_unref_ struct udev_monitor *monitor = NULL;
        _cleanup_udev_device_unref_ struct udev_device *again = NULL;
        struct udev *udev = udev_device_get_udev(device);
        const char *subsystem, *sysname;
        usec_t deadline;
        int r;

        assert(device);
        assert(ret);

        if (device_is_processed(device) > 0) {
                *ret = udev_device_ref(device);
                return 0;
        }

        sysname = udev_device_get_sysname(device);
        subsystem = udev_device_get_subsystem(device);

        monitor = udev_monitor_new_from_netlink(udev, "udev");
        if (!monitor)
                return log_error_errno(errno > 0 ? errno : ENOMEM, "Failed to acquire monitor: %m");

        if (subsystem) {
                r = udev_monitor_filter_add_match_subsystem_devtype(monitor, subsystem, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to add %s subsystem match to monitor: %m", subsystem);
        }

        r = udev_monitor_enable_receiving(monitor);
        if (r < 0)
                return log_error_errno(r, "Failed to start device monitor: %m");

        /* Check again, maybe things changed. Read the device again, as libudev does not read the
         * database again when it was read already, e.g. with ID_PROCESSING=1. */
        again = udev_device_new_from_syspath(udev, udev_device_get_syspath(device));
        if (device_is_processed(again ?: device) > 0) {
                *ret = udev_device_ref(again ?: device);
                return 0;
        }

        deadline = usec_add(now(CLOCK_MONOTONIC), timeout_usec);

        for (;;) {
                _cleanup_udev_device_unref_ struct udev_device *d = NULL;
                struct pollfd pfd = {
                        .fd = udev_monitor_get_fd(monitor),
                        .events = POLLIN,
                };
                int timeout_msec = -1;

                if (deadline != USEC_INFINITY) {
                        usec_t n = now(CLOCK_MONOTONIC), left;

                        if (n >= deadline)
                                return log_error_errno(ETIMEDOUT, "Failed to wait for device to be initialized: %m");

                        left = (deadline - n + USEC_PER_MSEC - 1) / USEC_PER_MSEC;
                        timeout_msec = left > INT_MAX ? INT_MAX : (int) left;
                }

                r = poll(&pfd, 1, timeout_msec);
                if (r < 0) {
                        if (errno == EINTR)
                                continue;
                        return log_error_errno(errno, "Failed to wait for device to be initialized: %m");
                }
                if (r == 0)
                        continue;

                d = udev_monitor_receive_device(monitor);
                if (!d)
                        continue;

                /* Ignore REMOVE events here. We are waiting for initialization after all, not
                 * de-initialization. We might see a REMOVE event from an earlier use of the device
                 * (devices by the same name are recycled by the kernel after all), which we should
                 * not get confused by. All other event types are "positive": the device exists and
                 * is registered in the udev database, thus whenever we see the event, we can
                 * consider it initialized. */
                if (streq_ptr(udev_device_get_action(d), "remove"))
                        continue;

                if (!streq_ptr(udev_device_get_sysname(d), sysname))
                        continue;

                /* Read the device again, to get the state stored in the udev database. */
                *ret = udev_device_new_from_syspath(udev, udev_device_get_syspath(d));
                if (!*ret)
                        *ret = udev_device_ref(d);
                return 0;
        }
}

int parse_root_argument(const char *s, char **ret) {
        char *p;

        assert(s);
        assert(ret);

        /* Like systemd, an empty path is no root either, and the path is simplified once here, so that
         * the paths joined to it later have no "//" or "/./". */
        if (isempty(s)) {
                free(*ret);
                *ret = NULL;
                return 0;
        }

        p = path_make_absolute_cwd(s);
        if (!p)
                return log_oom();

        path_simplify(p);

        free(*ret);
        if (empty_or_root(p)) {
                free(p);
                *ret = NULL;
        } else
                *ret = p;

        return 0;
}

static int add_rules_file(char ***names, char ***paths, const ConfFile *c) {
        int r;

        /* like cat_file() of systemd, the path as found, and the one with symlinks resolved */
        r = strv_extend(names, c->original_path);
        if (r < 0)
                return r;

        return strv_extend(paths, c->resolved_path);
}

static const char *root_prefix(const char *root) {
        return isempty(root) || path_equal(root, "/") ? "" : root;
}

/* The name of a rules file in the messages, like the original_path of the ConfFile of systemd: the path as
 * given or found, without resolving symlinks, with the root prefixed or else made absolute, and
 * simplified. */
static char *rules_file_name(const char *root, const char *path) {
        char *name;

        if (!isempty(root_prefix(root)))
                name = strjoin(root_prefix(root), "/", path, NULL);
        else
                name = path_make_absolute_cwd(path);
        if (!name)
                return NULL;

        return path_simplify(name);
}

/* The names of the rules files in the messages of udevadm verify are escaped like in the messages about their
 * rules, see parse_file(). */
static int log_chase_error(int r, const char *name) {
        _cleanup_free_ char *escaped = log_escape(LOG_ERR, name);

        /* systemd logs the text of EBADFD, "File descriptor in bad state", for e.g. a FIFO */
        if (r == -EBADFD)
                return log_error_errno(r, "Failed to chase '%s': not a regular file", escaped ?: name);

        return log_error_errno(r, "Failed to chase '%s': %m", escaped ?: name);
}

static void log_masked(const char *name) {
        _cleanup_free_ char *escaped = log_escape(LOG_WARNING, name);

        log_warning("File '%s' is a mask, ignoring.", escaped ?: name);
}

static int search_rules_file_in_dirs(const char *s, const char *root, char ***names, char ***paths) {
        _cleanup_free_ char *with_suffix = NULL;
        _cleanup_strv_free_ char **dirs = NULL;
        char **dir;
        int r;

        if (isempty(s) || strchr(s, '/'))
                return 0;

        if (!endswith(s, ".rules")) {
                with_suffix = strjoin(s, ".rules", NULL);
                if (!with_suffix)
                        return log_oom();

                s = with_suffix;
        }

        if (!filename_is_valid(s))
                return 0;

        dirs = udev_rules_get_dirs();
        if (!dirs)
                return log_oom();

        STRV_FOREACH(dir, dirs) {
                _cleanup_free_ char *name = NULL, *p = NULL;
                ConfFile *c = NULL;

                p = strjoin(*dir, "/", s, NULL);
                if (!p)
                        return log_oom();
                name = rules_file_name(root, p);
                if (!name)
                        return log_oom();

                /* Like systemd, a missing file, also a dangling symlink, is searched in the next
                 * directory. */
                r = conf_file_new(p, root, CONF_FILES_REGULAR | CONF_FILES_FILTER_MASKED, &c);
                if (r == -ERFKILL) {
                        log_masked(name);
                        return 1; /* Found masked file. */
                }
                if (r == -ENOENT)
                        continue;
                if (r < 0)
                        return log_chase_error(r, name);

                r = add_rules_file(names, paths, c);
                conf_file_free(c);
                if (r < 0)
                        return log_oom();

                return 1; /* found */
        }

        return 0;
}

static int search_rules_file(const char *s, const char *root, char ***names, char ***paths) {
        _cleanup_free_ char *name = NULL, *dir = NULL;
        ConfFile *c = NULL, **files = NULL;
        size_t n_files = 0, i;
        int r;

        /* If the input is a file name (e.g. 99-systemd.rules), then try to find it in udev/rules.d directories. */
        r = search_rules_file_in_dirs(s, root, names, paths);
        if (r != 0)
                return r < 0 ? r : 0;

        /* If not found, or if it is a path, then chase it. */
        name = rules_file_name(root, s);
        if (!name)
                return log_oom();

        r = conf_file_new(s, root, CONF_FILES_REGULAR | CONF_FILES_FILTER_MASKED, &c);
        if (r == -ERFKILL) {
                log_masked(name);
                return 0; /* Found masked file. */
        }
        if (r >= 0) {
                r = add_rules_file(names, paths, c);
                conf_file_free(c);
                return r < 0 ? log_oom() : 0;
        }
        if (r != -EISDIR)
                return log_chase_error(r, name);

        /* If a directory is specified, then find all rules file in the directory. Like systemd, without
         * masks, and relative to the current directory or to root. */
        dir = isempty(root_prefix(root)) ? path_make_absolute_cwd(s) : strjoin("/", s, NULL);
        if (!dir)
                return log_oom();

        r = conf_files_list_strv_full(".rules", root, CONF_FILES_REGULAR | CONF_FILES_WARN,
                                      (const char * const *) STRV_MAKE(dir), &files, &n_files);
        if (r < 0) {
                _cleanup_free_ char *escaped = log_escape(LOG_ERR, name);

                return log_error_errno(r, "Failed to enumerate rules files in '%s': %m", escaped ?: name);
        }

        for (i = 0; i < n_files; i++) {
                r = add_rules_file(names, paths, files[i]);
                if (r < 0)
                        break;
        }
        conf_file_free_array(files, n_files);

        return r < 0 ? log_oom() : 0;
}

int search_rules_files(char * const *args, const char *root, char ***ret_names, char ***ret_paths) {
        _cleanup_strv_free_ char **names = NULL, **paths = NULL;
        char * const *s;
        int r;

        assert(ret_names);
        assert(ret_paths);

        if (strv_isempty(args)) {
                _cleanup_strv_free_ char **dirs = NULL;
                ConfFile **files = NULL;
                size_t n_files = 0, i;

                dirs = udev_rules_get_dirs();
                if (!dirs)
                        return log_oom();

                /* Like systemd, a dangling symlink is skipped with a warning, and a file that is not a
                 * regular file, e.g. a directory, too, and then the file in the next directory is used. */
                r = conf_files_list_strv_full(".rules", root,
                                              CONF_FILES_REGULAR | CONF_FILES_FILTER_MASKED | CONF_FILES_WARN,
                                              (const char * const *) dirs, &files, &n_files);
                if (r < 0)
                        return log_error_errno(r, "Failed to enumerate rules files: %m");

                for (i = 0; i < n_files; i++) {
                        r = add_rules_file(&names, &paths, files[i]);
                        if (r < 0)
                                break;
                }
                conf_file_free_array(files, n_files);
                if (r < 0)
                        return log_oom();

                if (!isempty(root_prefix(root)) && strv_isempty(names)) {
                        _cleanup_free_ char *escaped = log_escape(LOG_ERR, root);

                        log_error("No rules files found in '%s'.", escaped ?: root);
                        return -ENOENT;
                }
        } else
                for (s = args; *s; s++) {
                        r = search_rules_file(*s, root, &names, &paths);
                        if (r < 0)
                                return r;
                }

        *ret_names = names;
        *ret_paths = paths;
        names = paths = NULL;
        return 0;
}

int parse_json_argument(const char *s, JsonFormatFlags *ret) {
        int r;

        r = json_parse_format(s, ret);
        if (r == -EINVAL)
                log_error("Unknown argument to --json= switch: %s", s);

        return r;
}

/* The actions of kernel uevents, in the order of systemd's sd_device_action_t. */
static const char* const device_action_table[] = {
        "add",
        "remove",
        "change",
        "move",
        "online",
        "offline",
        "bind",
        "unbind",
};

int device_action_from_string(const char *s) {
        size_t i;

        assert(s);

        for (i = 0; i < ELEMENTSOF(device_action_table); i++)
                if (streq(device_action_table[i], s))
                        return i;

        return -EINVAL;
}

int parse_device_action(const char *str, const char **ret) {
        int a;

        assert(str);
        assert(ret);

        if (streq(str, "help")) {
                size_t i;

                for (i = 0; i < ELEMENTSOF(device_action_table); i++)
                        puts(device_action_table[i]);
                return 0;
        }

        a = device_action_from_string(str);
        if (a < 0) {
                log_error("Invalid action '%s'.", str);
                return a;
        }

        *ret = device_action_table[a];
        return 1;
}

int parse_resolve_name_timing(const char *str, int *ret) {
        assert(str);
        assert(ret);

        if (streq(str, "help")) {
                puts("never\n"
                     "late\n"
                     "early");
                return 0;
        }

        if (udev_parse_resolve_names(str, ret) < 0) {
                log_error("--resolve-names= must be 'early', 'late', or 'never'.");
                return -EINVAL;
        }

        return 1;
}

void print_man_page_link(void) {
        _cleanup_free_ char *link = NULL;

        if (terminal_urlify_man("udevadm", "8", &link) < 0)
                link = NULL;

        printf("\nSee the %s man page for details.\n", link ?: "udevadm(8)");
}

void log_command_call(const struct udevadm_cmd *cmd) {
        assert(cmd);

        log_debug("calling: %s", cmd->name);
}
