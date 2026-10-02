/*
 * Copyright (C) 2003-2013 Kay Sievers <kay@vrfy.org>
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

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/signalfd.h>
#include <linux/sockios.h>
#include <sys/sysmacros.h>

#include "udev.h"
#include "netif-naming-scheme.h"
#include "path-util.h"
#include "socket-util.h"
#include "udev-netlink.h"

struct udev_event *udev_event_new(struct udev_device *dev, enum udev_event_mode mode) {
        struct udev *udev = udev_device_get_udev(dev);
        struct udev_event *event;

        event = new0(struct udev_event, 1);
        if (event == NULL)
                return NULL;
        event->dev = dev;
        event->udev = udev;
        udev_list_init(udev, &event->run_list, false);
        udev_list_init(udev, &event->seclabel_list, false);
        udev_list_init(udev, &event->written_sysattr_list, true);
        udev_list_init(udev, &event->written_sysctl_list, true);
        event->fd_signal = -1;
        event->rtnl_fd = -1;
        event->birth_usec = now(CLOCK_MONOTONIC);
        event->timeout_signal = SIGKILL;
        event->event_mode = mode;
        /* OPTIONS="log_level=reset" goes back to this */
        event->default_log_level = log_get_max_level();
        event->log_level_was_debug = event->default_log_level == LOG_DEBUG;
        return event;
}

void udev_event_unref(struct udev_event *event) {
        if (event == NULL)
                return;
        udev_list_cleanup(&event->run_list);
        udev_list_cleanup(&event->seclabel_list);
        udev_list_cleanup(&event->written_sysattr_list);
        udev_list_cleanup(&event->written_sysctl_list);
        safe_close(event->rtnl_fd);
        strv_free(event->ifaltnames);
        strv_free(event->altnames);
        free(event->program_result);
        free(event->name);
        free(event);
}

static void event_cache_written_value(struct udev_list *values, const char *attr, const char *value) {
        /* The list is unique, this replaces an earlier value. */
        if (udev_list_entry_add(values, attr, value) == NULL)
                log_debug("Failed to remember the value written to '%s', ignoring.", attr);
}

void event_cache_written_sysattr(struct udev_event *event, const char *attr, const char *value) {
        event_cache_written_value(&event->written_sysattr_list, attr, value);
}

void event_cache_written_sysctl(struct udev_event *event, const char *attr, const char *value) {
        event_cache_written_value(&event->written_sysctl_list, attr, value);
}

/* Returns the value of the property of the device, or when the device does not have it, of the global
 * property set with 'udevadm control --property', like systemd's device_get_property_value_with_fallback(). */
const char *udev_event_get_property_value_with_fallback(struct udev_device *dev, const char *key,
                                                        struct udev_list *global_props) {
        struct udev_list_entry *entry;
        const char *value;

        value = udev_device_get_property_value(dev, key);
        if (value || !global_props)
                return value;

        entry = udev_list_entry_get_by_name(udev_list_get_entry(global_props), key);
        return udev_list_entry_get_value(entry);
}

enum subst_type {
        SUBST_DEVNODE,
        SUBST_ATTR,
        SUBST_ENV,
        SUBST_KERNEL,
        SUBST_KERNEL_NUMBER,
        SUBST_DRIVER,
        SUBST_DEVPATH,
        SUBST_ID,
        SUBST_MAJOR,
        SUBST_MINOR,
        SUBST_RESULT,
        SUBST_PARENT,
        SUBST_NAME,
        SUBST_LINKS,
        SUBST_ROOT,
        SUBST_SYS,
};

static const struct subst_map {
        const char *name;
        const char fmt;
        enum subst_type type;
} map[] = {
        { .name = "devnode",  .fmt = 'N', .type = SUBST_DEVNODE },
        { .name = "tempnode", .fmt = 'N', .type = SUBST_DEVNODE },
        { .name = "attr",     .fmt = 's', .type = SUBST_ATTR },
        { .name = "sysfs",    .fmt = 's', .type = SUBST_ATTR },
        { .name = "env",      .fmt = 'E', .type = SUBST_ENV },
        { .name = "kernel",   .fmt = 'k', .type = SUBST_KERNEL },
        { .name = "number",   .fmt = 'n', .type = SUBST_KERNEL_NUMBER },
        { .name = "driver",   .fmt = 'd', .type = SUBST_DRIVER },
        { .name = "devpath",  .fmt = 'p', .type = SUBST_DEVPATH },
        { .name = "id",       .fmt = 'b', .type = SUBST_ID },
        { .name = "major",    .fmt = 'M', .type = SUBST_MAJOR },
        { .name = "minor",    .fmt = 'm', .type = SUBST_MINOR },
        { .name = "result",   .fmt = 'c', .type = SUBST_RESULT },
        { .name = "parent",   .fmt = 'P', .type = SUBST_PARENT },
        { .name = "name",     .fmt = 'D', .type = SUBST_NAME },
        { .name = "links",    .fmt = 'L', .type = SUBST_LINKS },
        { .name = "root",     .fmt = 'r', .type = SUBST_ROOT },
        { .name = "sys",      .fmt = 'S', .type = SUBST_SYS },
};

static const char *format_type_to_string(enum subst_type t) {
        unsigned int i;

        for (i = 0; i < ELEMENTSOF(map); i++)
                if (map[i].type == t)
                        return map[i].name;
        return NULL;
}

static char format_type_to_char(enum subst_type t) {
        unsigned int i;

        for (i = 0; i < ELEMENTSOF(map); i++)
                if (map[i].type == t)
                        return map[i].fmt;
        return '\0';
}

/* Like get_subst_type() of systemd, without its strict mode: returns 0 when *str does not start a
 * substitution, "$$" or "%%" (then *str is moved to the second character, which is copied), 1 for a
 * substitution, with *str moved behind it, and -EINVAL for a substitution with a missing closing brace or
 * an empty or too long attribute. */
static int get_subst_type(const char **str, enum subst_type *ret_type, char ret_attr[static UTIL_PATH_SIZE]) {
        const char *p = *str, *q = NULL;
        size_t i = 0;

        if (*p == '$') {
                p++;
                if (*p == '$') {
                        *str = p;
                        return 0;
                }
                for (i = 0; i < ELEMENTSOF(map); i++)
                        if ((q = startswith(p, map[i].name)))
                                break;
        } else if (*p == '%') {
                p++;
                if (*p == '%') {
                        *str = p;
                        return 0;
                }

                for (i = 0; i < ELEMENTSOF(map); i++)
                        if (*p == map[i].fmt) {
                                q = p + 1;
                                break;
                        }
        } else
                return 0;
        if (!q)
                return 0;

        if (*q == '{') {
                const char *start, *end;
                size_t len;

                start = q + 1;
                end = strchr(start, '}');
                if (!end)
                        return -EINVAL;

                len = end - start;
                if (len == 0 || len >= UTIL_PATH_SIZE)
                        return -EINVAL;

                strnscpy(ret_attr, UTIL_PATH_SIZE, start, len);
                q = end + 1;
        } else
                *ret_attr = '\0';

        *str = q;
        *ret_type = map[i].type;
        return 1;
}

/* Like safe_atou_optional_plus() of systemd: parses the index of $result{N} and %c{N}, which may be followed
 * by '+'. Returns 1 with '+', 0 without, and a negative error for an invalid index. */
int safe_atou_optional_plus(const char *s, unsigned *ret) {
        const char *p;
        int r;

        assert(s);
        assert(ret);

        p = endswith(s, "+");
        if (p)
                s = strndupa_safe(s, p - s);

        r = safe_atou(s, ret);
        if (r < 0)
                return r;

        return !!p;
}

/* Like udev_event_subst_format() of systemd: writes the value of the substitution to dest, of size l, and
 * returns its length, or a negative error. ret_truncated says whether the value was truncated. */
static ssize_t udev_event_subst_format(struct udev_event *event, enum subst_type type, const char *attr,
                                       char *dest, size_t l, bool *ret_truncated,
                                       struct udev_list *global_props) {
        struct udev_device *dev = event->dev;
        const char *val = NULL;
        bool truncated = false;
        char *s = dest;
        int r;

        switch (type) {
        case SUBST_DEVPATH:
                val = udev_device_get_devpath(dev);
                if (!val)
                        return -ENOENT;
                strpcpy_full(&s, l, val, &truncated);
                break;
        case SUBST_KERNEL:
                val = udev_device_get_sysname(dev);
                if (!val)
                        return -ENOENT;
                strpcpy_full(&s, l, val, &truncated);
                break;
        case SUBST_KERNEL_NUMBER:
                val = udev_device_get_sysnum(dev);
                if (!val)
                        goto null_terminate;
                strpcpy_full(&s, l, val, &truncated);
                break;
        case SUBST_ID:
                if (!event->dev_parent)
                        goto null_terminate;
                val = udev_device_get_sysname(event->dev_parent);
                if (!val)
                        return -ENOENT;
                strpcpy_full(&s, l, val, &truncated);
                break;
        case SUBST_DRIVER:
                if (!event->dev_parent)
                        goto null_terminate;
                val = udev_device_get_driver(event->dev_parent);
                if (!val)
                        goto null_terminate;
                strpcpy_full(&s, l, val, &truncated);
                break;
        case SUBST_MAJOR:
        case SUBST_MINOR: {
                dev_t devnum = udev_device_get_devnum(dev);

                strpcpyf_full(&s, l, &truncated, "%u", type == SUBST_MAJOR ? major(devnum) : minor(devnum));
                break;
        }
        case SUBST_RESULT: {
                unsigned index = 0; /* 0 means whole string */
                bool has_plus = false;

                if (!event->program_result)
                        goto null_terminate;

                if (!isempty(attr)) {
                        r = safe_atou_optional_plus(attr, &index);
                        if (r < 0)
                                return r;

                        has_plus = r;
                }

                if (index == 0)
                        strpcpy_full(&s, l, event->program_result, &truncated);
                else {
                        const char *start, *p;
                        unsigned i;

                        p = event->program_result + strspn(event->program_result, WHITESPACE);

                        for (i = 1; i < index; i++) {
                                while (*p && !strchr(WHITESPACE, *p))
                                        p++;
                                p += strspn(p, WHITESPACE);
                                if (*p == '\0')
                                        break;
                        }
                        if (i != index) {
                                log_debug("%s: requested part of result string not found",
                                          udev_device_get_sysname(dev) ?: "n/a");
                                goto null_terminate;
                        }

                        start = p;
                        /* %c{2+} copies the whole string from the second part on */
                        if (has_plus)
                                strpcpy_full(&s, l, start, &truncated);
                        else {
                                while (*p && !strchr(WHITESPACE, *p))
                                        p++;
                                strnpcpy_full(&s, l, start, p - start, &truncated);
                        }
                }
                break;
        }
        case SUBST_ATTR: {
                char vbuf[UTIL_NAME_SIZE];
                size_t len;
                int count;
                bool t;

                if (isempty(attr))
                        return -EINVAL;

                /* try to read the value specified by "[dmi/id]product_name" */
                if (util_resolve_subsys_kernel(event->udev, attr, vbuf, sizeof(vbuf), 1) == 0)
                        val = vbuf;

                /* try to read the attribute the device */
                if (!val)
                        val = udev_device_get_sysattr_value(dev, attr);

                /* try to read the attribute of the parent device, other matches have selected */
                if (!val && event->dev_parent && event->dev_parent != dev)
                        val = udev_device_get_sysattr_value(event->dev_parent, attr);

                if (!val)
                        goto null_terminate;

                /* strip trailing whitespace, and replace unwanted characters */
                if (val != vbuf)
                        strscpy_full(vbuf, sizeof(vbuf), val, &truncated);
                len = strlen(vbuf);
                while (len > 0 && isspace((unsigned char) vbuf[--len]))
                        vbuf[len] = '\0';
                count = util_replace_chars(vbuf, UDEV_ALLOWED_CHARS_INPUT);
                if (count > 0)
                        log_debug("%i character(s) replaced" , count);
                strpcpy_full(&s, l, vbuf, &t);
                truncated = truncated || t;
                break;
        }
        case SUBST_PARENT: {
                struct udev_device *dev_parent;

                dev_parent = udev_device_get_parent(dev);
                if (!dev_parent)
                        goto null_terminate;
                val = udev_device_get_devnode(dev_parent);
                if (!val)
                        goto null_terminate;
                strpcpy_full(&s, l, val + strlen("/dev/"), &truncated);
                break;
        }
        case SUBST_DEVNODE:
                val = udev_device_get_devnode(dev);
                if (!val)
                        goto null_terminate;
                strpcpy_full(&s, l, val, &truncated);
                break;
        case SUBST_NAME:
                if (event->name)
                        strpcpy_full(&s, l, event->name, &truncated);
                else if ((val = udev_device_get_devnode(dev)))
                        strpcpy_full(&s, l, val + strlen("/dev/"), &truncated);
                else {
                        val = udev_device_get_sysname(dev);
                        if (!val)
                                return -ENOENT;
                        strpcpy_full(&s, l, val, &truncated);
                }
                break;
        case SUBST_LINKS: {
                struct udev_list_entry *list_entry;

                udev_list_entry_foreach(list_entry, udev_device_get_devlinks_list_entry(dev)) {
                        const char *link = udev_list_entry_get_name(list_entry);

                        if (s == dest)
                                l = strpcpy_full(&s, l, link + strlen("/dev/"), &truncated);
                        else
                                l = strpcpyl_full(&s, l, &truncated, " ", link + strlen("/dev/"), NULL);
                        if (truncated)
                                break;
                }
                if (s == dest)
                        goto null_terminate;
                break;
        }
        case SUBST_ROOT:
                strpcpy_full(&s, l, "/dev", &truncated);
                break;
        case SUBST_SYS:
                strpcpy_full(&s, l, "/sys", &truncated);
                break;
        case SUBST_ENV:
                if (isempty(attr))
                        return -EINVAL;
                val = udev_event_get_property_value_with_fallback(dev, attr, global_props);
                if (!val)
                        goto null_terminate;
                strpcpy_full(&s, l, val, &truncated);
                break;
        default:
                assert_not_reached("Unknown format substitution type");
        }

        if (ret_truncated)
                *ret_truncated = truncated;

        return s - dest;

null_terminate:
        if (ret_truncated)
                *ret_truncated = truncated;

        *s = '\0';
        return 0;
}

/* Like udev_event_apply_format() of systemd: substitutes the $name, $name{attr}, %c and %c{attr} of src into
 * dest of size, and returns the remaining size. When a value does not fit, ret_truncated says so; the rules
 * then do not use the result. An invalid substitution stops it, with a warning. */
size_t udev_event_apply_format(struct udev_event *event,
                               const char *src, char *dest, size_t size,
                               bool replace_whitespace, struct udev_list *global_props,
                               bool *ret_truncated) {
        bool truncated = false;
        const char *s = src;
        int r;

        assert(event);
        assert(event->dev);
        assert(src);
        assert(dest);
        assert(size > 0);

        while (*s) {
                enum subst_type type;
                char attr[UTIL_PATH_SIZE];
                ssize_t subst_len;
                bool t;

                r = get_subst_type(&s, &type, attr);
                if (r < 0) {
                        log_warning_errno(r, "%s: Invalid format string, ignoring: %s",
                                          udev_device_get_sysname(event->dev) ?: "n/a", src);
                        break;
                } else if (r == 0) {
                        if (size < 2) {
                                /* need space for this char and the terminating NUL */
                                truncated = true;
                                break;
                        }
                        *dest++ = *s++;
                        size--;
                        continue;
                }

                subst_len = udev_event_subst_format(event, type, attr, dest, size, &t, global_props);
                if (subst_len < 0) {
                        log_warning_errno(subst_len,
                                          "%s: Failed to substitute variable '$%s' or apply format '%%%c', ignoring: %m",
                                          udev_device_get_sysname(event->dev) ?: "n/a",
                                          format_type_to_string(type), format_type_to_char(type));
                        break;
                }

                truncated = truncated || t;

                /* SUBST_RESULT handles spaces itself */
                if (replace_whitespace && type != SUBST_RESULT)
                        /* util_replace_whitespace() can replace in-place,
                         * and does nothing if subst_len == 0 */
                        subst_len = util_replace_whitespace(dest, dest, subst_len);

                dest += subst_len;
                size -= subst_len;
        }

        assert(size >= 1);

        if (ret_truncated)
                *ret_truncated = truncated;

        *dest = '\0';
        return size;
}

static int spawn_exec(struct udev_event *event __attribute__((unused)),
                      const char *cmd, char *const argv[], char **envp, const sigset_t *sigmask,
                      int fd_stdout, int fd_stderr) {
        _cleanup_close_ int fd = -1;

        /* discard child output or connect to pipe */
        fd = open("/dev/null", O_RDWR);
        if (fd >= 0) {
                dup2(fd, STDIN_FILENO);
                if (fd_stdout < 0)
                        dup2(fd, STDOUT_FILENO);
                if (fd_stderr < 0)
                        dup2(fd, STDERR_FILENO);
        } else
                log_error_errno(errno, "open /dev/null failed: %m");

        /* connect pipes to std{out,err} */
        if (fd_stdout >= 0) {
                dup2(fd_stdout, STDOUT_FILENO);
                safe_close(fd_stdout);
        }
        if (fd_stderr >= 0) {
                dup2(fd_stderr, STDERR_FILENO);
                safe_close(fd_stderr);
        }

        /* terminate child in case parent goes away */
        prctl(PR_SET_PDEATHSIG, SIGTERM);

        /* restore original udev sigmask before exec */
        if (sigmask)
                sigprocmask(SIG_SETMASK, sigmask, NULL);

        execve(argv[0], argv, envp);

        /* exec failed */
        log_error_errno(errno, "failed to execute '%s' '%s': %m", argv[0], cmd);

        return -errno;
}

/* Returns the timeout in milliseconds for poll() and epoll_wait() for the given time, plus a second, or -1
 * (no timeout) if it does not fit into their int. */
static int poll_timeout(usec_t usec) {
        usec_t msec = usec / USEC_PER_MSEC + MSEC_PER_SEC;

        return msec > INT_MAX ? -1 : (int) msec;
}

/* Like the timeout warning timer of systemd's spawn_wait(): warns about a slow program once, when the event is
 * older than its warning time. Returns the timeout for poll() and epoll_wait() until the warning, or after
 * it, until the timeout of the event, which must not have passed yet. */
static int spawn_warn(usec_t age_usec, usec_t timeout_usec, usec_t timeout_warn_usec,
                      const char *cmd, pid_t pid, bool *warned) {
        assert(age_usec < timeout_usec);

        if (!*warned && timeout_warn_usec < timeout_usec && age_usec >= timeout_warn_usec) {
                log_warning("slow: '%s' ["PID_FMT"]", cmd, pid);
                *warned = true;
        }

        /* wait until the warning is due, then until the timeout */
        if (!*warned && timeout_warn_usec < timeout_usec)
                return poll_timeout(timeout_warn_usec - age_usec);

        return poll_timeout(timeout_usec - age_usec);
}

static void spawn_read(struct udev_event *event,
                       usec_t timeout_usec,
                       usec_t timeout_warn_usec,
                       const char *cmd, pid_t pid, bool *warned,
                       int fd_stdout, int fd_stderr,
                       char *result, size_t ressize, bool *ret_truncated) {
        _cleanup_close_ int fd_ep = -1;
        struct epoll_event ep_outpipe = {
                .events = EPOLLIN,
                .data.ptr = &fd_stdout,
        };
        struct epoll_event ep_errpipe = {
                .events = EPOLLIN,
                .data.ptr = &fd_stderr,
        };
        size_t respos = 0;
        bool truncated = false;
        int r;

        /* read from child if requested */
        if (fd_stdout < 0 && fd_stderr < 0)
                return;

        fd_ep = epoll_create1(EPOLL_CLOEXEC);
        if (fd_ep < 0) {
                log_error_errno(errno, "error creating epoll fd: %m");
                return;
        }

        if (fd_stdout >= 0) {
                r = epoll_ctl(fd_ep, EPOLL_CTL_ADD, fd_stdout, &ep_outpipe);
                if (r < 0) {
                        log_error_errno(errno, "fail to add stdout fd to epoll: %m");
                        return;
                }
        }

        if (fd_stderr >= 0) {
                r = epoll_ctl(fd_ep, EPOLL_CTL_ADD, fd_stderr, &ep_errpipe);
                if (r < 0) {
                        log_error_errno(errno, "fail to add stderr fd to epoll: %m");
                        return;
                }
        }

        /* read child output */
        while (fd_stdout >= 0 || fd_stderr >= 0) {
                int timeout;
                int fdcount;
                struct epoll_event ev[4];
                int i;

                if (timeout_usec > 0) {
                        usec_t age_usec;

                        age_usec = now(CLOCK_MONOTONIC) - event->birth_usec;
                        if (age_usec >= timeout_usec) {
                                log_error("timeout '%s'", cmd);
                                return;
                        }
                        timeout = spawn_warn(age_usec, timeout_usec, timeout_warn_usec, cmd, pid, warned);
                } else {
                        timeout = -1;
                }

                fdcount = epoll_wait(fd_ep, ev, ELEMENTSOF(ev), timeout);
                if (fdcount < 0) {
                        if (errno == EINTR)
                                continue;
                        log_error_errno(errno, "failed to poll: %m");
                        return;
                } else if (fdcount == 0)
                        /* the warning or the timeout is due, see above */
                        continue;

                for (i = 0; i < fdcount; i++) {
                        int *fd = (int *)ev[i].data.ptr;

                        if (*fd < 0)
                                continue;

                        if (ev[i].events & EPOLLIN) {
                                ssize_t count;
                                char buf[4096];

                                count = read(*fd, buf, sizeof(buf)-1);
                                if (count <= 0)
                                        continue;
                                buf[count] = '\0';

                                /* store stdout result */
                                if (result != NULL && *fd == fd_stdout) {
                                        size_t len = count;

                                        if (len > ressize - 1 - respos) {
                                                len = ressize - 1 - respos;
                                                if (!truncated)
                                                        log_warning("Truncating stdout of '%s' up to %zu byte.", cmd, ressize - 1);
                                                truncated = true;
                                        }
                                        memcpy(&result[respos], buf, len);
                                        respos += len;
                                }

                                /* log debug output only if we watch stderr */
                                if (fd_stderr >= 0) {
                                        char *pos;
                                        char *line;

                                        pos = buf;
                                        while ((line = strsep(&pos, "\n"))) {
                                                if (pos != NULL || line[0] != '\0')
                                                        log_debug("'%s'(%s) '%s'", cmd, *fd == fd_stdout ? "out" : "err" , line);
                                        }
                                }
                        } else if (ev[i].events & EPOLLHUP) {
                                r = epoll_ctl(fd_ep, EPOLL_CTL_DEL, *fd, NULL);
                                if (r < 0) {
                                        log_error_errno(errno, "failed to remove fd from epoll: %m");
                                        return;
                                }
                                *fd = -1;
                        }
                }
        }

        /* return the child's stdout string */
        if (result != NULL)
                result[respos] = '\0';

        if (ret_truncated)
                *ret_truncated = truncated;
}

static int spawn_wait(struct udev_event *event,
                      usec_t timeout_usec,
                      usec_t timeout_warn_usec,
                      const char *cmd, pid_t pid, bool *warned) {
        struct pollfd pfd[1];
        bool killed = false;
        int err = 0;

        pfd[0].events = POLLIN;
        pfd[0].fd = event->fd_signal;

        while (pid > 0) {
                int timeout = -1;
                int fdcount;

                /* Like the timers of systemd's spawn_wait(), warn about a slow program once, and send it the
                 * timeout signal once, then wait for it to exit. */
                if (timeout_usec > 0 && !killed) {
                        usec_t age_usec;

                        age_usec = now(CLOCK_MONOTONIC) - event->birth_usec;
                        if (age_usec >= timeout_usec) {
                                log_error("timeout: killing '%s' ["PID_FMT"]", cmd, pid);
                                (void) kill_and_sigcont(pid, event->timeout_signal);
                                killed = true;
                        } else
                                timeout = spawn_warn(age_usec, timeout_usec, timeout_warn_usec, cmd, pid, warned);
                }

                fdcount = poll(pfd, 1, timeout);
                if (fdcount < 0) {
                        if (errno == EINTR)
                                continue;
                        err = -errno;
                        log_error_errno(errno, "failed to poll: %m");
                        goto out;
                }
                if (fdcount == 0)
                        continue;

                if (pfd[0].revents & POLLIN) {
                        struct signalfd_siginfo fdsi;
                        int status;
                        ssize_t size;

                        size = read(event->fd_signal, &fdsi, sizeof(struct signalfd_siginfo));
                        if (size != sizeof(struct signalfd_siginfo))
                                continue;

                        switch (fdsi.ssi_signo) {
                        case SIGTERM:
                                event->sigterm = true;
                                break;
                        case SIGCHLD:
                                /* 0: the program has not exited, the signal was about something else, e.g.
                                 * sent with kill(), so keep waiting, instead of reading an unset status */
                                if (waitpid(pid, &status, WNOHANG) <= 0)
                                        break;
                                if (WIFEXITED(status)) {
                                        log_debug("'%s' ["PID_FMT"] exit with return code %i", cmd, pid, WEXITSTATUS(status));
                                        if (WEXITSTATUS(status) != 0)
                                                err = -1;
                                } else if (WIFSIGNALED(status)) {
                                        log_error("'%s' ["PID_FMT"] terminated by signal %i (%s)", cmd, pid, WTERMSIG(status), strsignal(WTERMSIG(status)));
                                        err = -1;
                                } else if (WIFSTOPPED(status)) {
                                        log_error("'%s' ["PID_FMT"] stopped", cmd, pid);
                                        err = -1;
                                } else if (WIFCONTINUED(status)) {
                                        log_error("'%s' ["PID_FMT"] continued", cmd, pid);
                                        err = -1;
                                } else {
                                        log_error("'%s' ["PID_FMT"] exit with status 0x%04x", cmd, pid, status);
                                        err = -1;
                                }
                                pid = 0;
                                break;
                        }
                }
        }
out:
        return err;
}

/* Splits cmd in place into words, like systemd's strv_split_full() with
 * EXTRACT_UNQUOTE|EXTRACT_RELAX|EXTRACT_RETAIN_ESCAPE, which systemd-udevd uses for the programs of RUN,
 * PROGRAM and IMPORT{program}, and for the commands of the builtins: words are separated by any
 * whitespace; single and double quotes, also in the middle of a word, group characters including
 * whitespace and are removed; a missing closing quote is accepted; backslashes have no special meaning.
 * A word is never longer than its source, hence the words can be written over cmd. The callers provide
 * an array of UDEV_ARGV_MAX entries, which is terminated with NULL. */
int udev_build_argv(struct udev *udev __attribute__((unused)), char *cmd, int *ret_argc, char *argv[]) {
        char *r = cmd, *w = cmd;
        int argc = 0;

        for (;;) {
                char quote = 0;
                bool end;

                r += strspn(r, WHITESPACE);
                if (*r == '\0')
                        break;

                /* leave room for the terminating NULL */
                if (argc >= UDEV_ARGV_MAX - 1) {
                        log_error("too many arguments in command, ignoring the rest: '%s'", r);
                        break;
                }

                argv[argc++] = w;
                for (; *r != '\0'; r++) {
                        if (quote != 0) {
                                if (*r == quote)
                                        quote = 0;
                                else
                                        *w++ = *r;
                        } else if (IN_SET(*r, '\'', '"'))
                                quote = *r;
                        else if (strchr(WHITESPACE, *r))
                                break;
                        else
                                *w++ = *r;
                }

                /* Skip the separator before terminating the word, which may overwrite it. */
                end = *r == '\0';
                if (!end)
                        r++;
                *w++ = '\0';
                if (end)
                        break;
        }

        argv[argc] = NULL;
        if (ret_argc)
                *ret_argc = argc;
        return 0;
}

/* the directories udev_event_spawn() runs a program given without a path from */
static const char test_mode_helper_dirs[] =
        UDEV_LIBEXEC_DIR "\0"
#ifdef HAVE_SPLIT_USR
        "/usr/lib/udev\0"
        "/lib/udev\0"
#endif
        ;

/* Return the name of the udev helper that "udevadm test" runs, or NULL if the program must not be run
 * in test mode. The program must be the helper's name, or its absolute path in one of the directories
 * above: a prefix match would also let e.g. "cdrom_idX" or "scsi_id_wrapper" run. The paths are
 * compared simplified, i.e. "/usr/lib/udev//ata_id" and "/usr/lib/udev/./ata_id" are the helper too. */
static const char *test_mode_helper(const char *program) {
        _cleanup_free_ char *p = NULL;
        const char *h, *d;

        if (isempty(program))
                return NULL;

        p = strdup(program);
        if (!p) {
                log_oom();
                return NULL;
        }
        path_simplify(p);

        NULSTR_FOREACH(h, "ata_id\0" "cdrom_id\0" "dmi_memory_id\0" "fido_id\0" "mtd_probe\0" "scsi_id\0") {
                if (streq(p, h))
                        return h;

                NULSTR_FOREACH(d, test_mode_helper_dirs) {
                        _cleanup_free_ char *path = NULL;

                        path = strjoin(d, "/", h, NULL);
                        if (!path) {
                                log_oom();
                                return NULL;
                        }
                        if (streq(p, path_simplify(path)))
                                return h;
                }
        }

        return NULL;
}

int udev_event_spawn(struct udev_event *event,
                     usec_t timeout_usec,
                     usec_t timeout_warn_usec,
                     const char *cmd, char **envp, const sigset_t *sigmask,
                     char *result, size_t ressize, bool *ret_truncated) {
        int outpipe[2] = {-1, -1};
        int errpipe[2] = {-1, -1};
        pid_t pid;
        _cleanup_free_ char *arg = NULL;
        char *argv[UDEV_ARGV_MAX];
        char program[UTIL_PATH_SIZE];
        const char *helper = NULL;
        bool warned = false;
        int argc, err = 0;

        assert(event);
        assert(cmd);
        assert(result || ressize == 0);

        /* The words are written over a copy of the command, on the heap, like the argv of systemd, to keep
         * the stack small. The commands come from buffers of UTIL_LINE_SIZE, which the copy was before. */
        arg = strndup(cmd, UTIL_LINE_SIZE - 1);
        if (!arg)
                return log_oom();
        udev_build_argv(event->udev, arg, &argc, argv);

        if (event->event_mode == EVENT_UDEVADM_TEST)
                helper = test_mode_helper(argv[0]);

        if (event->event_mode == EVENT_UDEVADM_TEST && !helper) {
                log_debug("Running in test mode, skipping execution of '%s'.", cmd);
                if (ressize > 0)
                        result[0] = '\0';
                if (ret_truncated)
                        *ret_truncated = false;
                return 0;
        }

        /* The helpers run in test mode must not change the device either: tell cdrom_id not to
         * lock, unlock or eject the media, which the rules ask for with --lock-media. */
        if (helper && streq(helper, "cdrom_id")) {
                if (argc + 1 >= UDEV_ARGV_MAX) {
                        log_error("Too many arguments, not running '%s' in test mode.", cmd);
                        return -E2BIG;
                }

                /* insert --dry-run right after the program name, so that it is not taken for an
                 * argument after "--"; also move the terminating NULL */
                memmove(argv + 2, argv + 1, argc * sizeof(char *));
                argv[1] = (char *) "--dry-run";
                argc++;
        }

        if (isempty(argv[0])) {
                log_error("Invalid command '%s'", cmd);
                return -EINVAL;
        }

        /* The callers get the environment with udev_device_get_properties_envp(), which fails only when
         * out of memory. Like systemd, fail then, instead of running the program with an empty
         * environment. */
        if (!envp)
                return log_error_errno(ENOMEM, "%s: Failed to get device properties: %m",
                                       udev_device_get_sysname(event->dev) ?: "n/a");

        /* pipes from child to parent */
        if (result != NULL || log_get_max_level() >= LOG_INFO) {
                if (pipe2(outpipe, O_NONBLOCK) != 0) {
                        err = -errno;
                        log_error_errno(errno, "pipe failed: %m");
                        goto out;
                }
        }
        if (log_get_max_level() >= LOG_INFO) {
                if (pipe2(errpipe, O_NONBLOCK) != 0) {
                        err = -errno;
                        log_error_errno(errno, "pipe failed: %m");
                        goto out;
                }
        }

        /* allow programs in /usr/lib/udev/ to be called without the path */
        if (argv[0][0] != '/') {
                strscpyl(program, sizeof(program), UDEV_LIBEXEC_DIR "/", argv[0], NULL);
#ifdef HAVE_SPLIT_USR
                if(access(program, X_OK))
                        strscpyl(program, sizeof(program), "/usr/lib/udev/", argv[0], NULL);
                if(access(program, X_OK))
                        strscpyl(program, sizeof(program), "/lib/udev/", argv[0], NULL);
#endif
                argv[0] = program;
        }

        pid = fork();
        switch(pid) {
        case 0:
                /* child closes parent's ends of pipes */
                if (outpipe[READ_END] >= 0) {
                        close(outpipe[READ_END]);
                        outpipe[READ_END] = -1;
                }
                if (errpipe[READ_END] >= 0) {
                        close(errpipe[READ_END]);
                        errpipe[READ_END] = -1;
                }

                log_debug("starting '%s'", cmd);

                spawn_exec(event, cmd, argv, envp, sigmask,
                           outpipe[WRITE_END], errpipe[WRITE_END]);

                _exit(2 );
        case -1:
                log_error_errno(errno, "fork of '%s' failed: %m", cmd);
                err = -1;
                goto out;
        default:
                /* parent closed child's ends of pipes */
                if (outpipe[WRITE_END] >= 0) {
                        close(outpipe[WRITE_END]);
                        outpipe[WRITE_END] = -1;
                }
                if (errpipe[WRITE_END] >= 0) {
                        close(errpipe[WRITE_END]);
                        errpipe[WRITE_END] = -1;
                }

                spawn_read(event,
                           timeout_usec, timeout_warn_usec,
                           cmd, pid, &warned,
                           outpipe[READ_END], errpipe[READ_END],
                           result, ressize, ret_truncated);

                err = spawn_wait(event, timeout_usec, timeout_warn_usec, cmd, pid, &warned);
        }

out:
        if (outpipe[READ_END] >= 0)
                close(outpipe[READ_END]);
        if (outpipe[WRITE_END] >= 0)
                close(outpipe[WRITE_END]);
        if (errpipe[READ_END] >= 0)
                close(errpipe[READ_END]);
        if (errpipe[WRITE_END] >= 0)
                close(errpipe[WRITE_END]);
        return err;
}

#ifdef ENABLE_RULE_GENERATOR
/* function to return the count of rules that assign NAME= to a value matching arg#2 , defined in udev-rules.c */
int udev_rules_assigning_name_to(struct udev_rules *rules,const char *match_name);
#endif

/* Returns the alternative names the network interface has. Like rtnl_set_link_name() of systemd, they are read
 * once, before renaming the interface, and used both to drop the new name from them and to leave out the names
 * the interface has already when assigning alternative names, see event_assign_altnames(). NULL, if there are
 * none or they could not be read. */
static char **event_get_ifaltnames(struct udev_event *event) {
        int ifindex = udev_device_get_ifindex(event->dev);
        int r;

        if (event->ifaltnames_read || ifindex <= 0)
                return event->ifaltnames;

        event->ifaltnames_read = true;
        r = rtnl_get_link_alternative_names(&event->rtnl_fd, ifindex, &event->ifaltnames);
        if (r < 0)
                log_debug_errno(r, "Failed to get alternative names on network interface %i, ignoring: %m", ifindex);

        return event->ifaltnames;
}

/* Like rtnl_set_link_name() of systemd: if the requested name is already assigned as an alternative name of the
 * interface, then first drop it, as the kernel refuses to rename an interface to a name that is in use. Returns 1
 * if it was dropped, 0 if not, or a negative errno if it could not be dropped. */
static int netif_drop_altname(struct udev_event *event, const char *name) {
        int ifindex = udev_device_get_ifindex(event->dev);
        char *drop[2] = { (char *) name, NULL };
        int r;

        if (!strv_contains(event_get_ifaltnames(event), name))
                return 0;

        r = rtnl_delete_link_alternative_names(&event->rtnl_fd, ifindex, drop);
        if (r < 0)
                return log_debug_errno(r, "Failed to remove '%s' from alternative names on network interface %i: %m",
                                       name, ifindex);

        strv_remove(event->ifaltnames, name);
        return 1;
}

static void netif_restore_altname(struct udev_event *event, const char *name) {
        int ifindex = udev_device_get_ifindex(event->dev);
        char *restore[2] = { (char *) name, NULL };
        int r;

        r = rtnl_set_link_alternative_names(&event->rtnl_fd, ifindex, restore);
        if (r < 0)
                log_debug_errno(r, "Failed to restore '%s' as an alternative name on network interface %i, ignoring: %m",
                                name, ifindex);
        else if (strv_extend(&event->ifaltnames, name) < 0)
                log_oom();
}

/* Renames the network interface oldname to name. If ret_name is not NULL, it is set to the name the interface
 * has afterwards: name on success, otherwise oldname, or the temporary name of the rule generator, when the
 * interface was renamed to it, but not to name. ret_name may point to oldname. */
static int rename_netif_dev_fromname_toname(struct udev_event *event, const char *oldname, const char *name,
                                            char ret_name[IFNAMSIZ]) {
        int r;
        int sk;
        int altname_dropped;
        struct ifreq ifr;

        log_debug("changing net interface name from '%s' to '%s'\n",oldname,name);

        if (ret_name && ret_name != oldname)
                strscpy(ret_name, IFNAMSIZ, oldname);

        /* Like rtnl_set_link_name() of systemd, refuse invalid names, also so that strscpy() below does not
         * silently truncate the requested name. */
        if (!ifname_valid(name)) {
                if (strlen(name) >= IFNAMSIZ)
                        return log_error_errno(EINVAL, "Error changing net interface name %s to %s, the name is longer than %i characters: %m",
                                               oldname, name, IFNAMSIZ - 1);
                return log_error_errno(EINVAL, "Error changing net interface name %s to %s, the name is not a valid interface name: %m",
                                       oldname, name);
        }

        sk = socket(PF_INET, SOCK_DGRAM, 0);
        if (sk < 0)
                return log_error_errno(-errno, "error opening socket: %m");

        altname_dropped = netif_drop_altname(event, name);
        if (altname_dropped < 0) {
                close(sk);
                return log_error_errno(altname_dropped, "Error changing net interface name %s to %s: %m\n", oldname, name);
        }

        memzero(&ifr, sizeof(struct ifreq));
        strscpy(ifr.ifr_name, IFNAMSIZ, oldname);
        strscpy(ifr.ifr_newname, IFNAMSIZ, name);
        r = ioctl(sk, SIOCSIFNAME, &ifr);
        if (r < 0)
                r = -errno;

#ifdef ENABLE_RULE_GENERATOR
        int loop;
    struct ifreq ifr_tmp;

        if (r == 0) {
                log_info("renamed network interface %s to %s\n", ifr.ifr_name, ifr.ifr_newname);
                goto out;
        }
        /* keep trying if the destination interface name already exists */
        if (r != -EEXIST)
                goto out;
        log_debug("collision on rename of network interface %s to %s , retrying until timeout\n",
                ifr.ifr_name, ifr.ifr_newname);

        /* there has been a collision so rename my name to a temporal name, letting other one to rename to my name, freeying its name... */
        memzero(&ifr_tmp, sizeof(struct ifreq));
        strscpy(ifr_tmp.ifr_name, IFNAMSIZ, oldname);
        snprintf(ifr_tmp.ifr_newname, IFNAMSIZ, "rename_%s", oldname);
        if (ioctl(sk, SIOCSIFNAME, &ifr_tmp) < 0) {
                r = -errno;
                log_debug_errno(r, "could not temporarily rename network interface %s to %s: %m",
                                ifr_tmp.ifr_name, ifr_tmp.ifr_newname);
                goto out;
        }
        log_info("Temporarily renamed network interface %s to %s\n", ifr_tmp.ifr_name, ifr_tmp.ifr_newname);

        /* we have changed our name so in subsequent tries i should rename my temporal name to the wanted one */
        strscpy(ifr.ifr_name, IFNAMSIZ, ifr_tmp.ifr_newname);

        /* wait a maximum of 90 seconds for our target to become available */
        loop = 90 * 20;
        while (loop--) {
                const struct timespec duration = { 0, 1000 * 1000 * 1000 / 20 };

                nanosleep(&duration, NULL);

                r = ioctl(sk, SIOCSIFNAME, &ifr);
                if (r == 0) {
                        log_info("renamed network interface %s to %s\n", ifr.ifr_name, ifr.ifr_newname);
                        break;
                }
                r = -errno;
                if (r != -EEXIST)
                        break;
        }

out:
#endif
        if (r < 0 && altname_dropped > 0)
                netif_restore_altname(event, name);

        if (r == -EBUSY)
                /* like systemd, this is not an error */
                log_info("Network interface '%s' is already up, cannot rename to '%s'.", ifr.ifr_name, ifr.ifr_newname);
        else if (r < 0)
                log_error_errno(r, "Error changing net interface name %s to %s: %m\n", ifr.ifr_name, ifr.ifr_newname);
        else
                log_debug("renamed network interface '%s' to '%s'", oldname, name);

        /* ifr.ifr_name is the current name of the interface, unless the renaming succeeded */
        if (ret_name)
                strscpy(ret_name, IFNAMSIZ, r < 0 ? ifr.ifr_name : name);

        close(sk);
        return r;
}

/* Returns the name the network interface is to be renamed to, NULL if none. Like rename_netif() of systemd, with the
 * naming schemes that have NAMING_REPLACE_STRICTLY, an invalid name is ignored with a warning, otherwise renaming
 * the interface to it fails. */
static const char *netif_new_name(struct udev_event *event) {
        if (event->name == NULL)
                return NULL;

        if (FLAGS_SET(naming_scheme_init(event->udev)->flags, NAMING_REPLACE_STRICTLY) &&
            !ifname_valid(event->name)) {
                log_warning("Invalid network interface name, ignoring: %s", event->name);
                return NULL;
        }

        return event->name;
}

/* After the network interface was renamed, updates the device and the event to the new name. */
static void netif_update_device(struct udev_device *dev, const char *name) {
        char oldname[IFNAMSIZ];
        int r;

        strscpy(oldname, sizeof(oldname), udev_device_get_sysname(dev));

        log_debug("renamed netif to '%s'\n", name);
        r = udev_device_rename(dev, name);
        if (r < 0)
                log_warning_errno(r, "renamed interface '%d' from '%s' to '%s', but could not update udev_device: %m",
                                  udev_device_get_ifindex(dev), oldname, name);
        else
                log_debug("changed devpath to '%s'", udev_device_get_devpath(dev));
}

#ifdef ENABLE_RULE_GENERATOR
/* build the temporary iface name, used when the current name is assigned to another device */
static void netif_tmp_name(struct udev_device *dev, char newifname[IFNAMSIZ]) {
        char *pos, *newpos;

        strscpy(newifname, IFNAMSIZ, udev_device_get_sysname(dev));
        newpos=pos=&newifname[strcspn(newifname,"0123456789")];
        (void) strtol(pos,&newpos,10);
        *pos='\0';
        if (newpos > pos && *newpos == '\0') /* append new iface num to name */
                /* use udev_device_get_ifindex(dev) as it is unique to every iface */
                snprintf(pos,IFNAMSIZ+(newifname-pos), "%d", 128 - udev_device_get_ifindex(dev));
}
#endif

static int copy_all_tags(struct udev_device *d, struct udev_device *s) {
        struct udev_list_entry *list_entry;
        int r;

        assert(d);

        if (!s)
                return 0;

        udev_list_entry_foreach(list_entry, udev_device_get_tags_list_entry(s)) {
                r = udev_device_add_tag(d, udev_list_entry_get_name(list_entry), false);
                if (r < 0)
                        return r;
        }

        return 0;
}

/* Warns about an invalid net_altnames= in udev.conf, when udevd or udevadm test start. */
void udev_event_check_config(struct udev *udev) {
        _cleanup_free_ char *escaped = NULL;
        const char *value;

        if (udev_get_net_altnames(udev) >= 0)
                return;

        value = udev_get_net_altnames_invalid(udev);
        if (isempty(value)) {
                log_warning("Empty net_altnames= in udev.conf, using the default: yes.");
                return;
        }

        escaped = cescape(value);
        log_warning("Invalid net_altnames=\"%s\" in udev.conf, using the default: yes.", escaped ?: value);
}

/* The ID_NET_NAME_* properties that are assigned as alternative names with OPTIONS+="net_altnames", in
 * this order, like AlternativeNamesPolicy=database onboard slot path mac of 99-default.link of systemd. */
static const char * const net_altnames_properties[] = {
        "ID_NET_NAME_FROM_DATABASE",
        "ID_NET_NAME_ONBOARD",
        "ID_NET_NAME_SLOT",
        "ID_NET_NAME_PATH",
        "ID_NET_NAME_MAC",
};

/* Like link_generate_alternative_names() of systemd: collects the alternative names requested with
 * OPTIONS+="net_altnames" in event->altnames, in the order of the properties, unfiltered, as systemd does. */
static void event_generate_altnames(struct udev_event *event) {
        struct udev_device *dev = event->dev;
        const char *action = udev_device_get_action(dev);
        size_t i;

        if (!event->net_altnames)
                return;

        if (udev_device_get_ifindex(dev) <= 0)
                return;

        if (!streq_ptr(action, "add")) {
                log_debug("Not applying alternative names on '%s' uevent.", action ?: "n/a");
                return;
        }

        if (udev_get_net_altnames(event->udev) == 0) {
                log_debug("Not applying alternative names, disabled by net_altnames= in udev.conf.");
                return;
        }

        for (i = 0; i < ELEMENTSOF(net_altnames_properties); i++) {
                const char *n;

                n = udev_device_get_property_value(dev, net_altnames_properties[i]);
                if (!ifname_valid_full(n, IFNAME_VALID_ALTERNATIVE))
                        continue;

                if (strv_extend(&event->altnames, n) < 0) {
                        log_oom();
                        return;
                }
        }
}

/* Like assign_altnames() of systemd: assigns the alternative names, after the interface was renamed, except
 * its name and the names it has already. */
static void event_assign_altnames(struct udev_event *event) {
        struct udev_device *dev = event->dev;
        const char *ifname = udev_device_get_sysname(dev);
        int r;

        if (strv_isempty(event->altnames))
                return;

        if (!EVENT_MODE_NETIF_DESTRUCTIVE(event)) {
                /* systemd shows the names unfiltered, see udevadm test; here the ones that would be requested */
                const char *newname = event->name ?: ifname;
                _cleanup_free_ char *names = NULL;
                char **a;

                /* on the heap, to keep the stack small */
                STRV_FOREACH(a, event->altnames) {
                        char *n;

                        if (streq(*a, newname))
                                continue;

                        n = strjoin(names ?: "", isempty(names) ? "" : " ", *a, NULL);
                        if (!n) {
                                log_oom();
                                return;
                        }
                        free_and_replace(names, n);
                }

                if (!isempty(names))
                        log_debug("Running in test mode, skipping assigning alternative names '%s' to network interface '%s'.",
                                  names, newname);
                return;
        }

        /* Filter out the current interface name. */
        strv_remove(event->altnames, ifname);

        r = rtnl_append_link_alternative_names(&event->rtnl_fd, udev_device_get_ifindex(dev),
                                               event_get_ifaltnames(event), event->altnames);
        if (r < 0)
                log_full_errno(r == -EOPNOTSUPP ? LOG_DEBUG : LOG_WARNING, r,
                               "Could not assign alternative names to network interface '%s', ignoring: %m", ifname);
}

/* The event failed after the database entry of the device was written again with ID_PROCESSING=1 before
 * the rules were applied. Unlike systemd, which leaves the property behind until the next event of the
 * device, write the previous entry back; when that fails, udev_device_update_db() removes the entry. So
 * a failed event never leaves a device that looks like it is still being processed. Also unlike systemd,
 * restore the tag index when it was updated: remove the tags that the failed event added, which systemd
 * leaves behind too, and add the tags of the previous entry again, if there was one. */
static void event_restore_db(struct udev_event *event) {
        int r;

        if (event->tags_indexed) {
                event->tags_indexed = false;

                r = udev_device_tag_index_restore(event->dev, event->dev_db);
                if (r < 0)
                        log_debug_errno(r, "%s: Failed to restore tags under " UDEV_ROOT_RUN "/udev/tags/, ignoring: %m",
                                        udev_device_get_sysname(event->dev));
        }

        if (!event->dev_db_written)
                return;
        event->dev_db_written = false;

        if (udev_device_add_property(event->dev_db, "ID_PROCESSING", NULL) < 0 ||
            udev_device_update_db(event->dev_db) < 0)
                (void) udev_device_delete_db(event->dev_db);
}

/* Applies the rules to the event, and creates or removes the device node and its symlinks, renames a
 * network interface and writes the database. Like systemd, when the rules fail, e.g. on an error of
 * IMPORT{}, the rest of it is skipped, and the error is returned; the caller does not run RUN either. */
int udev_event_execute_rules(struct udev_event *event,
                             usec_t timeout_usec, usec_t timeout_warn_usec,
                             struct udev_list *properties_list,
                             struct udev_rules *rules,
                             const sigset_t *sigmask) {
        struct udev_device *dev = event->dev;
        int r;

        if (udev_device_get_subsystem(dev) == NULL)
                return 0;

        if (streq(udev_device_get_action(dev), "remove")) {
                udev_device_read_db(dev);

                if (EVENT_MODE_DESTRUCTIVE(event)) {
                        r = udev_device_tag_index(dev, false);
                        if (r < 0)
                                log_debug_errno(r, "%s: Failed to remove corresponding tag files under " UDEV_ROOT_RUN "/udev/tags/, ignoring: %m",
                                                udev_device_get_sysname(dev));
                        r = udev_device_delete_db(dev);
                        if (r < 0)
                                log_debug_errno(r, "%s: Failed to delete database under " UDEV_ROOT_RUN "/udev/data/, ignoring: %m",
                                                udev_device_get_sysname(dev));

                        if (major(udev_device_get_devnum(dev)) != 0)
                                udev_watch_end(event->udev, dev);
                }

                r = udev_rules_apply_to_event(rules, event,
                                              timeout_usec, timeout_warn_usec,
                                              properties_list,
                                              sigmask);
                if (r < 0)
                        log_debug_errno(r, "%s: Failed to apply udev rules: %m", udev_device_get_sysname(dev));

                if (EVENT_MODE_DESTRUCTIVE(event)) {
                        if (major(udev_device_get_devnum(dev)) != 0)
                                udev_node_remove(dev);
                }

                return r < 0 ? r : 0;
        } else {
                /* disable watch during event processing */
                if (EVENT_MODE_DESTRUCTIVE(event) && major(udev_device_get_devnum(dev)) != 0)
                        udev_watch_end(event->udev, dev);

                event->dev_db = udev_device_clone_with_db(dev);

                if (copy_all_tags(dev, event->dev_db) < 0)
                        log_warning("%s: Failed to copy all tags from old database entry, ignoring",
                                    udev_device_get_sysname(dev));

                if (major(udev_device_get_devnum(dev)) == 0 &&
                    streq(udev_device_get_action(dev), "move"))
                        udev_device_copy_properties(dev, event->dev_db);

                /* If the database file already exists, append ID_PROCESSING property to the existing database,
                 * to indicate that the device is being processed by udevd. */
                if (EVENT_MODE_DESTRUCTIVE(event) && event->dev_db && udev_device_has_db(event->dev_db) > 0) {
                        /* eudev: keep the sticky bit of OPTIONS="db_persist" of the existing database file,
                         * which the device read from the database does not know about; the final write
                         * follows the rules of this event. */
                        if (udev_device_db_is_persistent(event->dev_db) > 0)
                                udev_device_set_db_persist(event->dev_db);

                        r = udev_device_add_property(event->dev_db, "ID_PROCESSING", "1");
                        if (r < 0) {
                                log_warning_errno(r, "%s: Failed to add 'ID_PROCESSING' property: %m",
                                                  udev_device_get_sysname(dev));
                                event->dev_db = udev_device_unref(event->dev_db);
                                return r;
                        }

                        r = udev_device_update_db(event->dev_db);
                        if (r < 0) {
                                log_warning_errno(r, "%s: Failed to update database under " UDEV_ROOT_RUN "/udev/data/: %m",
                                                  udev_device_get_sysname(dev));
                                event->dev_db = udev_device_unref(event->dev_db);
                                return r;
                        }

                        event->dev_db_written = true;
                }

                r = udev_rules_apply_to_event(rules, event,
                                              timeout_usec, timeout_warn_usec,
                                              properties_list,
                                              sigmask);
                if (r < 0) {
                        log_debug_errno(r, "%s: Failed to apply udev rules: %m", udev_device_get_sysname(dev));
                        event_restore_db(event);
                        event->dev_db = udev_device_unref(event->dev_db);
                        return r;
                }

                event_generate_altnames(event);

                /* rename a new network interface, if needed; like systemd, assign the alternative names unless
                 * that failed, but also when the interface is up (EBUSY) or the name is ignored */
                int rename_r = 0;
                if (!EVENT_MODE_NETIF_DESTRUCTIVE(event) &&
                    udev_device_get_ifindex(dev) > 0 && streq(udev_device_get_action(dev), "add")) {
                        const char *sysname = udev_device_get_sysname(dev);
#ifdef ENABLE_RULE_GENERATOR
                        char tmpname[IFNAMSIZ];

                        if ((event->name == NULL || !streq(event->name, sysname)) &&
                            udev_rules_assigning_name_to(rules, sysname) > 0) {
                                netif_tmp_name(dev, tmpname);
                                if (!streq(tmpname, sysname))
                                        log_debug("Running in test mode, skipping temporary rename of network interface '%s' to '%s'.",
                                                  sysname, tmpname);
                        }
#endif
                        if (event->name != NULL && !streq(event->name, sysname))
                                log_debug("Running in test mode, skipping renaming network interface '%s' to '%s'.",
                                          sysname, event->name);
                }

                /* ENABLE_RULE_GENERATOR conditional:
                 * if this is a net iface, and it is an add event,
                 * and as long as all of the following are FALSE:
                 *  - no NAME target and the current name is not being used
                 *  - there is a NAME target and it is the same as the current name
                 *  - the rules can successfully be searched for the current name (not really part of the conditional)
                 * the run the rename.
                 *
                 * note - udev_rules_assigning_name_to is run when event->name is NULL to ensure renames happen,
                 * but also on its own to check if a temp-rename is necessary when event->name exists.
                 *
                 * A temp-rename is necessary when:
                 * - there is no rule renaming the current iface but the current name IS used in some other rule
                 * - there is a rule renaming the current iface,
                 *   the current name IS used AND the target name != the current name
                 */

#ifdef ENABLE_RULE_GENERATOR
                if (EVENT_MODE_NETIF_DESTRUCTIVE(event) &&
                    udev_device_get_ifindex(dev) > 0 && streq(udev_device_get_action(dev), "add")) {
                        const char *name = netif_new_name(event);
                        int r = 0;

                        if ((name == NULL && (r=udev_rules_assigning_name_to(rules,udev_device_get_sysname(dev))) > 0) ||
                            (name != NULL && !streq(name, udev_device_get_sysname(dev)))) {
                                /* the name of the interface, as renamed so far */
                                char curname[IFNAMSIZ];
                                char newifname[IFNAMSIZ];

                                strscpy(curname, sizeof(curname), udev_device_get_sysname(dev));

                                /* r is the number of rules that assign a device with NAME= this sysname */
                                if (r > 0 || udev_rules_assigning_name_to(rules, curname) > 0) {
                                        /* have a conflict, rename to a temp name */
                                        netif_tmp_name(dev, newifname);

                                        /* if sysname isn't already the tmpname (ie there is no numeric component), do the rename */
                                        if (!streq(newifname, curname)) {
                                                r = rename_netif_dev_fromname_toname(event, curname, newifname, curname);
                                                rename_r = r;
                                                if (r == 0)
                                                        log_debug("renamed netif to '%s' for collision avoidance\n", newifname);
                                                else if (r != -EBUSY)
                                                        log_error("could not rename netif to '%s' for collision avoidance\n", newifname);
                                        }
                                }

                                /* rename it now to its final target if it is not already there, from the name it has
                                 * now, also when it could not be renamed to the temporary name */
                                if (name != NULL && !streq(name, curname))
                                        rename_r = rename_netif_dev_fromname_toname(event, curname, name, curname);

                                /* also when only the temporary renaming succeeded, the device has to follow the interface */
                                if (!streq(curname, udev_device_get_sysname(dev)))
                                        netif_update_device(dev, curname);
                        }
                }
#else
                if (EVENT_MODE_NETIF_DESTRUCTIVE(event) &&
                    udev_device_get_ifindex(dev) > 0 && streq(udev_device_get_action(dev), "add") &&
                    event->name != NULL && !streq(event->name, udev_device_get_sysname(dev))) {
                        const char *name = netif_new_name(event);
                        int r;

                        if (name != NULL) {
                                r = rename_netif_dev_fromname_toname(event, udev_device_get_sysname(dev), name, NULL);
                                rename_r = r;
                                if (r >= 0)
                                        netif_update_device(dev, name);
                                else if (r != -EBUSY)
                                        log_warning_errno(r, "could not rename interface '%d' from '%s' to '%s': %m", udev_device_get_ifindex(dev),
                                                          udev_device_get_sysname(dev), name);
                        }
                }
#endif

                /* assign alternative names to a new network interface, after renaming it */
                if (udev_device_get_ifindex(dev) > 0 && streq(udev_device_get_action(dev), "add")) {
                        if (rename_r < 0 && rename_r != -EBUSY) {
                                if (!strv_isempty(event->altnames))
                                        log_debug("Not assigning alternative names, as network interface '%s' could not be renamed.",
                                                  udev_device_get_sysname(dev));
                        } else
                                event_assign_altnames(event);
                }

                if (major(udev_device_get_devnum(dev)) > 0) {
                        bool apply;

                        if (!event->owner_set)
                                event->uid = udev_device_get_devnode_uid(dev);

                        if (!event->group_set)
                                event->gid = udev_device_get_devnode_gid(dev);

                        if (!event->mode_set) {
                                if (udev_device_get_devnode_mode(dev) > 0) {
                                        /* kernel supplied value */
                                        event->mode = udev_device_get_devnode_mode(dev);
                                } else if (event->gid > 0) {
                                        /* default 0660 if a group is assigned */
                                        event->mode = 0660;
                                } else {
                                        /* default 0600 */
                                        event->mode = 0600;
                                }
                        }

                        apply = streq(udev_device_get_action(dev), "add") || event->owner_set || event->group_set || event->mode_set;
                        if (EVENT_MODE_DESTRUCTIVE(event)) {
                                int r;

                                /* Unless applying them, leave the owner, the group and the mode of the
                                 * device node alone. */
                                r = udev_node_apply_permissions(dev, apply,
                                                                apply ? event->mode : MODE_INVALID,
                                                                apply ? event->uid : UID_INVALID,
                                                                apply ? event->gid : GID_INVALID,
                                                                &event->seclabel_list);
                                if (r < 0)
                                        log_error_errno(r, "Failed to apply devnode permissions: %m");
                                else
                                        (void) udev_node_update(dev, event->dev_db);
                        } else
                                log_debug("Running in test mode, skipping handling device node '%s', devnum=%s, "
                                          "mode=%#o, uid="UID_FMT", gid="GID_FMT".",
                                          udev_device_get_devnode(dev), udev_device_get_id_filename(dev),
                                          event->mode, event->uid, event->gid);
                }

                /* preserve old, or get new initialization timestamp */
                udev_device_ensure_usec_initialized(event->dev, event->dev_db);

                if (EVENT_MODE_DESTRUCTIVE(event)) {
                        /* (re)write database file */
                        event->tags_indexed = true;
                        r = udev_device_tag_index(dev, true);
                        if (r < 0) {
                                log_debug_errno(r, "%s: Failed to update tags under " UDEV_ROOT_RUN "/udev/tags/: %m",
                                                udev_device_get_sysname(dev));
                                event_restore_db(event);
                                event->dev_db = udev_device_unref(event->dev_db);
                                return r;
                        }
                }

                /* If the database file for the device will be created below, add ID_PROCESSING=1 to indicate that
                 * the device is still being processed by udevd, as commands specified in RUN are invoked after
                 * the database is created. See issue #30056. */
                if (udev_device_should_have_db(dev) && udev_list_get_entry(&event->run_list)) {
                        r = udev_device_add_property(dev, "ID_PROCESSING", "1");
                        if (r < 0) {
                                log_warning_errno(r, "%s: Failed to add 'ID_PROCESSING' property: %m",
                                                  udev_device_get_sysname(dev));
                                event_restore_db(event);
                                event->dev_db = udev_device_unref(event->dev_db);
                                return r;
                        }
                }

                if (EVENT_MODE_DESTRUCTIVE(event)) {
                        r = udev_device_update_db(dev);
                        if (r < 0) {
                                log_debug_errno(r, "%s: Failed to update database under " UDEV_ROOT_RUN "/udev/data/: %m",
                                                udev_device_get_sysname(dev));
                                event_restore_db(event);
                                event->dev_db = udev_device_unref(event->dev_db);
                                return r;
                        }
                }
                udev_device_set_is_initialized(dev);

                event->dev_db = udev_device_unref(event->dev_db);
        }

        return 0;
}

void udev_event_execute_run(struct udev_event *event, usec_t timeout_usec, usec_t timeout_warn_usec, const sigset_t *sigmask) {
        struct udev_list_entry *list_entry;

        udev_list_entry_foreach(list_entry, udev_list_get_entry(&event->run_list)) {
                const char *command = udev_list_entry_get_name(list_entry);
                enum udev_builtin_cmd builtin_cmd = udev_list_entry_get_num(list_entry);

                if (builtin_cmd < UDEV_BUILTIN_MAX) {
                        udev_builtin_run(event->dev, builtin_cmd, command, event->event_mode);
                } else {
                        char **envp;

                        if (event->exec_delay_usec > 0) {
                                struct timespec ts;

                                log_debug("delay execution of '%s'", command);
                                (void) nanosleep(timespec_store(&ts, event->exec_delay_usec), NULL);
                        }

                        envp = udev_device_get_properties_envp(event->dev);
                        udev_event_spawn(event, timeout_usec, timeout_warn_usec, command, envp, sigmask, NULL, 0, NULL);
                }
        }
}
