/***
  This file is part of systemd.

  Copyright 2012 Kay Sievers <kay@vrfy.org>

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

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>

#ifdef HAVE_LINUX_BTRFS_H
#include <linux/btrfs.h>
#endif

#include "missing.h"
#include "udev.h"

static int builtin_btrfs(struct udev_device *dev, int argc, char *argv[], enum udev_event_mode mode) {
        struct btrfs_ioctl_vol_args args = {};
        _cleanup_close_ int fd = -1;
        const char *node;
        int err;

        /* Like systemd, the errors are returned as negative error codes, with the reason. */
        if (!IN_SET(argc, 2, 3) || !streq(argv[1], "ready"))
                return log_device_error_errno(dev, EINVAL, "Invalid arguments.");

        node = udev_device_get_devnode(dev);
        if (!node)
                return log_device_error_errno(dev, ENOENT, "Failed to get device node: %m");

        if (argc == 3 && !streq(argv[2], node))
                return log_device_debug_errno(dev, EINVAL, "Device node '%s' is not owned by the device, it must be '%s'.", argv[2], node);

        if (strlen(node) >= sizeof(args.name))
                return log_device_debug_errno(dev, EINVAL, "Device name too long for BTRFS_IOC_DEVICES_READY call: %s", node);

        if (mode != EVENT_UDEV_WORKER) {
                log_device_debug(dev, "Running in test mode, skipping execution of 'btrfs' builtin command.");
                return EXIT_SUCCESS;
        }

        fd = open("/dev/btrfs-control", O_RDWR|O_CLOEXEC|O_NOCTTY);
        if (fd < 0) {
                if (IN_SET(errno, ENOENT, ENXIO, ENODEV, ENOMEDIUM)) {
                        /* Driver not installed? Then we aren't ready. This is useful in initrds that lack
                         * btrfs.ko. After the host transition (where btrfs.ko will hopefully become
                         * available) the device can be retriggered and will then be considered ready. */
                        udev_builtin_add_property(dev, mode, "ID_BTRFS_READY", "0");
                        return EXIT_SUCCESS;
                }

                return log_device_debug_errno(dev, errno, "Failed to open %s: %m", "/dev/btrfs-control");
        }

        strscpy(args.name, sizeof(args.name), node);
        err = ioctl(fd, BTRFS_IOC_DEVICES_READY, &args);
        if (err < 0)
                return log_device_debug_errno(dev, errno, "Failed to call BTRFS_IOC_DEVICES_READY: %m");

        udev_builtin_add_property(dev, mode, "ID_BTRFS_READY", one_zero(err == 0));
        return EXIT_SUCCESS;
}

const struct udev_builtin udev_builtin_btrfs = {
        .name = "btrfs",
        .cmd = builtin_btrfs,
        .help = "btrfs volume management",
};
