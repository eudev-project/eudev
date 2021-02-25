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

        if (!IN_SET(argc, 2, 3) || !streq(argv[1], "ready")) {
                log_error("Invalid arguments.");
                return EXIT_FAILURE;
        }

        node = udev_device_get_devnode(dev);
        if (!node) {
                log_error("Failed to get device node of '%s'", udev_device_get_syspath(dev));
                return EXIT_FAILURE;
        }

        if (argc == 3 && !streq(argv[2], node)) {
                log_debug("Device node '%s' is not owned by the device, it must be '%s'.", argv[2], node);
                return EXIT_FAILURE;
        }

        if (strlen(node) >= sizeof(args.name)) {
                log_debug("Device name too long for BTRFS_IOC_DEVICES_READY call: %s", node);
                return EXIT_FAILURE;
        }

        if (mode != EVENT_UDEV_WORKER) {
                log_debug("Running in test mode, skipping execution of 'btrfs' builtin command.");
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

                log_debug_errno(errno, "Failed to open /dev/btrfs-control: %m");
                return EXIT_FAILURE;
        }

        strscpy(args.name, sizeof(args.name), node);
        err = ioctl(fd, BTRFS_IOC_DEVICES_READY, &args);
        if (err < 0)
                return EXIT_FAILURE;

        udev_builtin_add_property(dev, mode, "ID_BTRFS_READY", one_zero(err == 0));
        return EXIT_SUCCESS;
}

const struct udev_builtin udev_builtin_btrfs = {
        .name = "btrfs",
        .cmd = builtin_btrfs,
        .help = "btrfs volume management",
};
