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

#include <poll.h>

#include "udev-util.h"
#include "udevadm-util.h"

struct udev_device *find_device(struct udev *udev,
                                const char *id,
                                const char *prefix) {

        assert(udev);
        assert(id);

        if (prefix && !startswith(id, prefix))
                id = strjoina(prefix, id);

        if (startswith(id, "/dev/")) {
                struct stat statbuf;
                char type;

                if (stat(id, &statbuf) < 0)
                        return NULL;

                if (S_ISBLK(statbuf.st_mode))
                        type = 'b';
                else if (S_ISCHR(statbuf.st_mode))
                        type = 'c';
                else
                        return NULL;

                return udev_device_new_from_devnum(udev, type, statbuf.st_rdev);
        } else if (startswith(id, "/sys/"))
                return udev_device_new_from_syspath(udev, id);
        else
                return NULL;
}

/* Like systemd's device_wait_for_initialization(): waits until udevd processed the device, i.e.
 * until it has an entry in the udev database. Returns a new reference to a device object with the
 * current state of the device. */
int device_wait_for_initialization(struct udev_device *device, usec_t timeout_usec, struct udev_device **ret) {
        _cleanup_udev_monitor_unref_ struct udev_monitor *monitor = NULL;
        struct udev *udev = udev_device_get_udev(device);
        const char *subsystem, *sysname;
        usec_t deadline;
        int r;

        assert(device);
        assert(ret);

        if (udev_device_get_is_initialized(device) > 0) {
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

        /* Check again, maybe things changed. libudev reads the db again if the device was not
         * initialized yet. */
        if (udev_device_get_is_initialized(device) > 0) {
                *ret = udev_device_ref(device);
                return 0;
        }

        deadline = timeout_usec == USEC_INFINITY ? USEC_INFINITY : now(CLOCK_MONOTONIC) + timeout_usec;

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

bool colors_enabled(void) {
        static int cached = -1;

        if (cached < 0)
                cached = isatty(STDOUT_FILENO) > 0 && !getenv("NO_COLOR") && !streq_ptr(getenv("TERM"), "dumb");
        return cached;
}

#define DEFINE_ANSI_FUNC(name, seq)                             \
        const char *ansi_##name(void) {                         \
                return colors_enabled() ? seq : "";             \
        }

/* The 256-color variants of systemd are replaced by their 16-color fallbacks. */
DEFINE_ANSI_FUNC(normal,            "\x1B[0m")
DEFINE_ANSI_FUNC(highlight,         "\x1B[0;1;39m")
DEFINE_ANSI_FUNC(highlight_red,     "\x1B[0;1;31m")
DEFINE_ANSI_FUNC(highlight_green,   "\x1B[0;1;32m")
DEFINE_ANSI_FUNC(highlight_yellow,  "\x1B[0;1;33m")
DEFINE_ANSI_FUNC(highlight_blue,    "\x1B[0;1;34m")
DEFINE_ANSI_FUNC(highlight_magenta, "\x1B[0;1;35m")
DEFINE_ANSI_FUNC(highlight_cyan,    "\x1B[0;1;36m")
DEFINE_ANSI_FUNC(grey,              "\x1B[0;90m")
