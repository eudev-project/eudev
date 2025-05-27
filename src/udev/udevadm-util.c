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

/* Like systemd's sd_device_new_from_path(): the path of a device node in /dev or of a symlink to
 * one, or a sysfs path, also a relative one or a symlink to one. Sets errno on failure, like systemd
 * ENODEV if the path does not exist, or is neither a device node in /dev nor a path in /sys. */
static struct udev_device *device_new_from_path(struct udev *udev, const char *path) {
        _cleanup_free_ char *resolved = NULL;
        struct stat st;

        assert(udev);
        assert(path);

        resolved = realpath(path, NULL);
        if (!resolved) {
                if (errno == ENOENT)
                        errno = ENODEV;
                return NULL;
        }

        if (!isempty(path_startswith(resolved, "/dev/")) && stat(resolved, &st) >= 0) {
                if (S_ISBLK(st.st_mode))
                        return udev_device_new_from_devnum(udev, 'b', st.st_rdev);
                if (S_ISCHR(st.st_mode))
                        return udev_device_new_from_devnum(udev, 'c', st.st_rdev);
        }

        if (isempty(path_startswith(resolved, "/sys/"))) {
                errno = ENODEV;
                return NULL;
        }

        return udev_device_new_from_syspath(udev, resolved);
}

struct udev_device *find_device(struct udev *udev,
                                const char *id,
                                const char *prefix) {
        struct udev_device *dev;

        assert(udev);
        assert(id);

        dev = udev_device_new_from_device_id(udev, id);
        if (dev)
                return dev;

        dev = device_new_from_path(udev, id);
        if (dev)
                return dev;

        if (prefix && !path_startswith(id, prefix)) {
                _cleanup_free_ char *path = NULL;

                path = path_join(prefix, id);
                if (!path) {
                        errno = ENOMEM;
                        return NULL;
                }

                dev = device_new_from_path(udev, path);
                if (dev)
                        return dev;
        }

        /* systemd tries a device unit name if the argument is not a path, eudev has none. */
        if (!strchr(id, '/'))
                errno = EINVAL;

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

        p = path_make_absolute_cwd(s);
        if (!p)
                return log_oom();

        path_kill_slashes(p);

        free(*ret);
        if (path_equal(p, "/")) {
                free(p);
                *ret = NULL;
        } else
                *ret = p;

        return 0;
}

int chase_below_root(const char *root, const char *path, char **ret) {
        _cleanup_free_ char *done = NULL, *todo = NULL;
        unsigned max_follow = 32;
        char *p;

        assert(path);
        assert(ret);

        if (isempty(root) || path_equal(root, "/")) {
                p = realpath(path, NULL);
                if (!p)
                        return -errno;
                *ret = p;
                return 0;
        }

        /* the part of the path that is resolved, below root, empty for the root directory */
        done = strdup("");
        todo = strdup(path);
        if (!done || !todo)
                return -ENOMEM;

        p = todo;
        for (;;) {
                _cleanup_free_ char *full = NULL, *target = NULL, *rest = NULL;
                struct stat st;
                size_t n;
                char *c;

                p += strspn(p, "/");
                if (*p == '\0')
                        break;

                n = strcspn(p, "/");
                c = strndup(p, n);
                if (!c)
                        return -ENOMEM;
                p += n;

                if (streq(c, ".")) {
                        free(c);
                        continue;
                }

                if (streq(c, "..")) {
                        /* never above root */
                        char *slash = strrchr(done, '/');

                        if (slash)
                                *slash = '\0';
                        free(c);
                        continue;
                }

                full = strjoin(root, done, "/", c, NULL);
                if (!full) {
                        free(c);
                        return -ENOMEM;
                }

                if (lstat(full, &st) < 0) {
                        free(c);
                        return -errno;
                }

                if (S_ISLNK(st.st_mode)) {
                        int r;

                        free(c);

                        if (--max_follow == 0)
                                return -ELOOP;

                        r = readlink_malloc(full, &target);
                        if (r < 0)
                                return r;

                        /* continue with the target, followed by the rest of the path */
                        rest = strjoin(target, "/", p, NULL);
                        if (!rest)
                                return -ENOMEM;

                        if (path_is_absolute(target))
                                done[0] = '\0';

                        free(todo);
                        todo = rest;
                        rest = NULL;
                        p = todo;
                        continue;
                }

                {
                        char *d = strjoin(done, "/", c, NULL);

                        free(c);
                        if (!d)
                                return -ENOMEM;
                        free(done);
                        done = d;
                }
        }

        p = strjoin(root, isempty(done) ? "/" : done, NULL);
        if (!p)
                return -ENOMEM;

        *ret = path_kill_slashes(p);
        return 0;
}

static bool path_is_masked(const char *path) {
        _cleanup_free_ char *target = NULL;
        struct stat st;

        /* Like systemd, empty files and symlinks to /dev/null mask a file. */
        if (lstat(path, &st) < 0)
                return false;

        if (S_ISLNK(st.st_mode))
                return readlink_malloc(path, &target) >= 0 && path_equal(target, "/dev/null");

        return S_ISREG(st.st_mode) && st.st_size == 0;
}

static int add_rules_file(char ***names, char ***paths, const char *name, const char *path) {
        int r;

        r = strv_extend(names, name);
        if (r < 0)
                return r;

        return strv_extend(paths, path);
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

static int search_rules_file_in_dirs(const char *s, const char *root, char ***names, char ***paths) {
        _cleanup_free_ char *with_suffix = NULL;
        const char* const* dir;
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

        for (dir = udev_rules_get_dirs(); *dir; dir++) {
                _cleanup_free_ char *name = NULL, *path = NULL, *p = NULL;

                p = strjoin(*dir, "/", s, NULL);
                if (!p)
                        return log_oom();
                name = rules_file_name(root, p);
                if (!name)
                        return log_oom();

                if (access(name, F_OK) < 0)
                        continue;

                if (path_is_masked(name)) {
                        log_warning("File '%s' is a mask, ignoring.", name);
                        return 1; /* Found masked file. */
                }

                r = chase_below_root(root, p, &path);
                if (r < 0)
                        return log_error_errno(r, "Failed to chase '%s': %m", name);

                r = add_rules_file(names, paths, name, path);
                if (r < 0)
                        return log_oom();

                return 1;
        }

        return 0;
}

static int search_rules_file(const char *s, const char *root, char ***names, char ***paths) {
        _cleanup_free_ char *name = NULL, *path = NULL;
        struct stat st;
        int r;

        /* If the input is a file name (e.g. 99-systemd.rules), then try to find it in udev/rules.d directories. */
        r = search_rules_file_in_dirs(s, root, names, paths);
        if (r != 0)
                return r < 0 ? r : 0;

        /* If not found, or if it is a path, then chase it. */
        name = rules_file_name(root, s);
        if (!name)
                return log_oom();

        r = chase_below_root(root, s, &path);
        if (r < 0)
                return log_error_errno(r, "Failed to chase '%s': %m", name);

        if (stat(path, &st) < 0)
                return log_error_errno(errno, "Failed to chase '%s': %m", name);

        if (!S_ISDIR(st.st_mode)) {
                if (path_is_masked(name)) {
                        log_warning("File '%s' is a mask, ignoring.", name);
                        return 0; /* Found masked file. */
                }

                if (!S_ISREG(st.st_mode))
                        return log_error_errno(EBADF, "Failed to chase '%s': %s", name, "not a regular file");

                r = add_rules_file(names, paths, name, path);
                if (r < 0)
                        return log_oom();

                return 0;
        }

        /* If a directory is specified, then find all rules file in the directory. */
        {
                _cleanup_strv_free_ char **files = NULL;
                const char *dirs[] = { path, NULL };
                char **f;

                r = conf_files_list_strv(&files, ".rules", NULL, dirs);
                if (r < 0)
                        return log_error_errno(r, "Failed to enumerate rules files in '%s': %m", name);

                STRV_FOREACH(f, files) {
                        _cleanup_free_ char *resolved = NULL, *file_name = NULL;

                        /* named in the directory as given, like systemd */
                        file_name = strjoin(name, "/", eudev_basename(*f), NULL);
                        if (!file_name)
                                return log_oom();

                        r = chase_below_root(root, *f + strlen(root_prefix(root)), &resolved);
                        if (r < 0) {
                                log_warning_errno(r, "Failed to chase '%s': %m", file_name);
                                continue;
                        }

                        /* only regular files, like CONF_FILES_REGULAR */
                        if (stat(resolved, &st) < 0 || !S_ISREG(st.st_mode))
                                continue;

                        r = add_rules_file(names, paths, file_name, resolved);
                        if (r < 0)
                                return log_oom();
                }
        }

        return 0;
}

int search_rules_files(char * const *args, const char *root, char ***ret_names, char ***ret_paths) {
        _cleanup_strv_free_ char **names = NULL, **paths = NULL;
        char * const *s;
        int r;

        assert(ret_names);
        assert(ret_paths);

        if (strv_isempty(args)) {
                _cleanup_strv_free_ char **files = NULL;
                char **f;

                r = conf_files_list_strv(&files, ".rules", isempty(root_prefix(root)) ? NULL : root, udev_rules_get_dirs());
                if (r < 0)
                        return log_error_errno(r, "Failed to enumerate rules files: %m");

                STRV_FOREACH(f, files) {
                        _cleanup_free_ char *resolved = NULL;

                        if (path_is_masked(*f))
                                continue;

                        r = chase_below_root(root, *f + strlen(root_prefix(root)), &resolved);
                        if (r < 0) {
                                log_warning_errno(r, "Failed to chase '%s', ignoring: %m", *f);
                                continue;
                        }

                        r = add_rules_file(&names, &paths, *f, resolved);
                        if (r < 0)
                                return log_oom();
                }

                if (!isempty(root_prefix(root)) && strv_isempty(names)) {
                        log_error("No rules files found in '%s'.", root);
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
        if (a < 0)
                return a;

        *ret = device_action_table[a];
        return 1;
}
