/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include <unistd.h>

#include "pager.h"
#include "path-util.h"
#include "strv.h"
#include "udev.h"
#include "udev-util.h"
#include "udevadm-util.h"

typedef enum WaitUntil {
        WAIT_UNTIL_INITIALIZED,
        WAIT_UNTIL_ADDED,
        WAIT_UNTIL_REMOVED,
        _WAIT_UNTIL_MAX,
} WaitUntil;

static WaitUntil arg_wait_until = WAIT_UNTIL_INITIALIZED;
static usec_t arg_timeout_usec = USEC_INFINITY;
static bool arg_removed = false;
static bool arg_settle = false;
static char **arg_devices = NULL;

static const char * const wait_until_table[_WAIT_UNTIL_MAX] = {
        [WAIT_UNTIL_INITIALIZED] = "initialized",
        [WAIT_UNTIL_ADDED]       = "added",
        [WAIT_UNTIL_REMOVED]     = "removed",
};

static int check_device(struct udev *udev, const char *path) {
        _cleanup_udev_device_unref_ struct udev_device *dev = NULL;

        assert(path);

        if (arg_wait_until == WAIT_UNTIL_REMOVED) {
                if (faccessat(AT_FDCWD, path, F_OK, AT_SYMLINK_NOFOLLOW) >= 0)
                        return false;
                if (errno == ENOENT)
                        return true;
                return -errno;
        }

        /* Like sd_device_new_from_path(): a sysfs path, or a device node or a symlink to it. */
        errno = 0;
        dev = find_device(udev, path, NULL);
        if (!dev) {
                if (IN_SET(errno, 0, ENOENT, ENODEV, ENXIO, ENOTDIR))
                        return false;
                return -errno;
        }

        if (arg_wait_until == WAIT_UNTIL_INITIALIZED)
                return device_is_processed(dev);

        return true;
}

static bool check(struct udev *udev) {
        char **p;
        int r;

        if (arg_settle && access(UDEV_ROOT_RUN "/udev/queue", F_OK) >= 0)
                return false;

        STRV_FOREACH(p, arg_devices) {
                r = check_device(udev, *p);
                if (r <= 0) {
                        if (r < 0)
                                log_warning_errno(r, "Failed to check if device \"%s\" is %s, assuming not %s: %m",
                                                  *p,
                                                  wait_until_table[arg_wait_until],
                                                  wait_until_table[arg_wait_until]);
                        return false;
                }
        }

        return true;
}

static bool device_is_requested(struct udev_device *device) {
        struct udev_list_entry *entry;
        const char *name;
        char **p;

        /* For other events, at first check if the received device matches with the requested devices,
         * to avoid calling check() so many times within a short time. */

        name = udev_device_get_sysname(device);
        if (name)
                STRV_FOREACH(p, arg_devices) {
                        const char *s;

                        if (!path_startswith(*p, "/sys"))
                                continue;

                        s = strrchr(*p, '/');
                        if (!s || isempty(s + 1))
                                continue;

                        if (strneq(s + 1, name, strlen(s + 1)))
                                return true;
                }

        name = udev_device_get_devnode(device);
        if (!name)
                return false;

        STRV_FOREACH(p, arg_devices)
                if (path_equal(*p, name))
                        return true;

        udev_list_entry_foreach(entry, udev_device_get_devlinks_list_entry(device))
                STRV_FOREACH(p, arg_devices)
                        if (path_equal(*p, udev_list_entry_get_name(entry)))
                                return true;

        return false;
}

/* Returns true if the wait is over. */
static bool on_device(struct udev *udev, struct udev_monitor *monitor) {
        _cleanup_udev_device_unref_ struct udev_device *device = NULL;

        device = udev_monitor_receive_device(monitor);
        if (!device)
                return false;

        if (streq_ptr(udev_device_get_action(device), "remove") != (arg_wait_until == WAIT_UNTIL_REMOVED))
                return false;

        if (arg_wait_until == WAIT_UNTIL_REMOVED)
                /* On removed event, the received device may not contain enough information.
                 * Let's unconditionally check all requested devices are removed. */
                return check(udev);

        return device_is_requested(device) && check(udev);
}

static struct udev_monitor *setup_monitor(struct udev *udev, const char *name) {
        struct udev_monitor *monitor;
        int r;

        monitor = udev_monitor_new_from_netlink(udev, name);
        if (!monitor)
                return NULL;

        r = udev_monitor_enable_receiving(monitor);
        if (r < 0) {
                udev_monitor_unref(monitor);
                errno = -r;
                return NULL;
        }

        return monitor;
}

static void help(void) {
        pager_open(0);

        printf("%s wait [OPTIONS] DEVICE [DEVICE...]\n\n"
               "Wait for devices or device symlinks being created.\n\n"
               "  -h --help             Print this message\n"
               "  -V --version          Print version of the program\n"
               "  -t --timeout=SEC      Maximum time to wait for the device\n"
               "     --initialized=BOOL Wait for devices being initialized by udevd\n"
               "     --removed          Wait for devices being removed\n"
               "     --settle           Also wait for all queued events being processed\n",
               program_invocation_short_name);
        print_man_page_link();
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_INITIALIZED = 0x100,
                ARG_REMOVED,
                ARG_SETTLE,
        };

        static const struct option options[] = {
                { "timeout",     required_argument, NULL, 't'             },
                { "initialized", required_argument, NULL, ARG_INITIALIZED },
                { "removed",     no_argument,       NULL, ARG_REMOVED     },
                { "settle",      no_argument,       NULL, ARG_SETTLE      },
                { "help",        no_argument,       NULL, 'h'             },
                { "version",     no_argument,       NULL, 'V'             },
                {}
        };

        int c, r;

        while ((c = udevadm_getopt_long(argc, argv, "t:hV", options)) >= 0)
                switch (c) {
                case 't':
                        r = parse_sec(optarg, &arg_timeout_usec);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse -t/--timeout= parameter: %s", optarg);
                        break;

                case ARG_INITIALIZED:
                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --initialized= parameter: %s", optarg);
                        arg_wait_until = r ? WAIT_UNTIL_INITIALIZED : WAIT_UNTIL_ADDED;
                        break;

                case ARG_REMOVED:
                        arg_removed = true;
                        break;

                case ARG_SETTLE:
                        arg_settle = true;
                        break;

                case 'V':
                        printf("%s\n", UDEV_VERSION);
                        return 0;

                case 'h':
                        help();
                        return 0;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unknown option");
                }

        if (arg_removed)
                arg_wait_until = WAIT_UNTIL_REMOVED;

        if (optind >= argc) {
                log_error("Too few arguments, expected at least one device path or device symlink.");
                return -EINVAL;
        }

        arg_devices = strv_copy(argv + optind);
        if (!arg_devices)
                return log_oom();

        return 1; /* work to do */
}

static bool path_has_dot_dot(const char *p) {
        for (;;) {
                size_t n;

                p += strspn(p, "/");
                if (*p == '\0')
                        return false;

                n = strcspn(p, "/");
                if (n == 2 && strneq(p, "..", 2))
                        return true;
                p += n;
        }
}

static int wait_main(struct udev *udev) {
        _cleanup_udev_monitor_unref_ struct udev_monitor *udev_monitor = NULL, *kernel_monitor = NULL;
        _cleanup_close_ int inotify_fd = -1;
        usec_t deadline = USEC_INFINITY, next_periodic = USEC_INFINITY;
        unsigned counter = 0;
        char **p;

        STRV_FOREACH(p, arg_devices) {
                path_kill_slashes(*p);

                if (path_has_dot_dot(*p)) {
                        log_error("Device path cannot contain \"..\".");
                        return -EINVAL;
                }

                if (!path_startswith(*p, "/dev/") && !path_startswith(*p, "/sys/")) {
                        log_error("Specified path \"%s\" does not start with \"/dev/\" or \"/sys/\".", *p);
                        return -EINVAL;
                }
        }

        /* Check before configuring event sources, as devices may be already initialized. */
        if (check(udev))
                return 0;

        if (arg_timeout_usec != USEC_INFINITY)
                deadline = usec_add(now(CLOCK_BOOTTIME), arg_timeout_usec);

        if (arg_settle) {
                inotify_fd = inotify_init1(IN_CLOEXEC|IN_NONBLOCK);
                if (inotify_fd < 0)
                        return log_error_errno(errno, "Failed to set up inotify: %m");

                if (inotify_add_watch(inotify_fd, UDEV_ROOT_RUN "/udev", IN_CREATE | IN_DELETE) < 0)
                        return log_error_errno(errno, "Failed to set up inotify: %m");
        }

        udev_monitor = setup_monitor(udev, "udev");
        if (!udev_monitor)
                return log_error_errno(errno > 0 ? errno : ENOMEM, "Failed to set up udev uevent monitor: %m");

        if (arg_wait_until == WAIT_UNTIL_ADDED) {
                /* If --initialized=no is specified, it is not necessary to wait uevents for the specified
                 * devices to be processed by udevd. Hence, let's listen on the kernel's uevent stream. Then,
                 * we may be able to finish this program earlier when udevd is very busy.
                 * Note, we still need to also setup udev monitor, as this may be invoked with a devlink
                 * (e.g. /dev/disk/by-id/foo). In that case, the devlink may not exist when we received a
                 * uevent from kernel, as the udevd may not finish to process the uevent yet. Hence, we need
                 * to wait until the event is processed by udevd. */
                kernel_monitor = setup_monitor(udev, "kernel");
                if (!kernel_monitor)
                        return log_error_errno(errno > 0 ? errno : ENOMEM, "Failed to set up kernel uevent monitor: %m");

                /* This is a workaround for issues #24360 and #24450 of systemd.
                 * For some reasons, the kernel sometimes does not emit uevents for loop block device on
                 * attach. Hence, without the periodic timer, no event source for this program will be
                 * triggered, and this will be timed out. */
                next_periodic = now(CLOCK_BOOTTIME) + 250 * USEC_PER_MSEC;
        }

        /* Check before entering the event loop, as devices may be initialized during setting up event sources. */
        if (check(udev))
                return 0;

        for (;;) {
                struct pollfd pfd[3];
                usec_t n, until;
                int timeout_msec = -1, r;
                unsigned n_pfd = 0, i;

                pfd[n_pfd++] = (struct pollfd) { .fd = udev_monitor_get_fd(udev_monitor), .events = POLLIN };
                if (kernel_monitor)
                        pfd[n_pfd++] = (struct pollfd) { .fd = udev_monitor_get_fd(kernel_monitor), .events = POLLIN };
                if (inotify_fd >= 0)
                        pfd[n_pfd++] = (struct pollfd) { .fd = inotify_fd, .events = POLLIN };

                n = now(CLOCK_BOOTTIME);
                if (deadline != USEC_INFINITY && n >= deadline) {
                        log_error("Timed out for waiting devices being %s.", wait_until_table[arg_wait_until]);
                        return -ETIMEDOUT;
                }

                until = MIN(deadline, next_periodic);
                if (until != USEC_INFINITY) {
                        usec_t left = until > n ? (until - n + USEC_PER_MSEC - 1) / USEC_PER_MSEC : 0;

                        timeout_msec = left > INT_MAX ? INT_MAX : (int) left;
                }

                r = poll(pfd, n_pfd, timeout_msec);
                if (r < 0) {
                        if (errno == EINTR)
                                continue;
                        return log_error_errno(errno, "Event loop failed: %m");
                }

                /* uevents are always handled before the periodic timer */
                for (i = 0; i < n_pfd; i++) {
                        if (!(pfd[i].revents & POLLIN))
                                continue;

                        if (pfd[i].fd == inotify_fd) {
                                /* Only that something changed in /run/udev matters, not the events. */
                                r = flush_fd(inotify_fd);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to read inotify events: %m");

                                if (check(udev))
                                        return 0;
                        } else if (on_device(udev, pfd[i].fd == udev_monitor_get_fd(udev_monitor) ? udev_monitor : kernel_monitor))
                                return 0;
                }

                if (next_periodic != USEC_INFINITY && now(CLOCK_BOOTTIME) >= next_periodic) {
                        /* Even if all devices exists, we try to wait for uevents to be emitted from kernel. */
                        if (check(udev))
                                counter++;
                        else
                                counter = 0;

                        if (counter >= 2) {
                                log_debug("All requested devices popped up without receiving kernel uevents.");
                                return 0;
                        }

                        next_periodic = now(CLOCK_BOOTTIME) + 250 * USEC_PER_MSEC;
                }
        }
}

static int adm_wait(struct udev *udev, int argc, char *argv[]) {
        int r;

        r = parse_argv(argc, argv);
        if (r > 0)
                r = wait_main(udev);

        arg_devices = strv_free(arg_devices);
        return r < 0 ? 1 : 0;
}

const struct udevadm_cmd udevadm_wait = {
        .name = "wait",
        .cmd = adm_wait,
        .help = "Wait for device or device symlink",
};
