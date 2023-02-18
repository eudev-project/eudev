/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Identifies FIDO CTAP1 ("U2F")/CTAP2 security tokens based on the usage declared in their report
 * descriptor and outputs suitable environment variables.
 *
 * Inspired by Andrew Lutomirski's 'u2f-hidraw-policy.c'
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <errno.h>
#include <fcntl.h>
#include <linux/hid.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>


#include "fido_id_desc.h"
#include "libudev-private.h"
#include "libudev.h"
#include "log.h"
#include "macro.h"
#include "path-util.h"
#include "udev-util.h"
#include "udev.h"


int main(int argc, char **argv) {
        _cleanup_(udev_device_unrefp) struct udev_device *device = NULL;
        _cleanup_udev_unref_ struct udev *udev;
        _cleanup_free_ char *desc_path = NULL;
        _cleanup_close_ int fd = -1;

        struct udev_device *hid_device;
        const char *sys_path;
        uint8_t desc[HID_MAX_DESCRIPTOR_SIZE];
        ssize_t desc_len;

        int r;

        log_set_target(LOG_TARGET_AUTO);
        //udev_parse_config();
        //log_parse_environment();
        log_open();

        udev = udev_new();
        if (udev == NULL)
                return 1;

        if (argc > 2)
                return log_error_errno(/*SYNTHETIC_ERRNO*/(EINVAL), "Usage: %s [SYSFS_PATH]", program_invocation_short_name);

        if (argc == 1) {
                device = udev_device_new_from_environment(udev);
                if (device == NULL)
                        return log_error_errno(errno, "Failed to get current device from environment: %m");
        } else {
                device = udev_device_new_from_syspath(udev, argv[1]);
                if (device == NULL)
                        return log_error_errno(r, "Failed to get device from syspath: %m");
        }

        hid_device = udev_device_get_parent(device);
        if (hid_device == NULL)
                return log_error_errno(errno, "Failed to get parent HID device: %m");

        sys_path = udev_device_get_syspath(hid_device);
        if (sys_path == NULL)
                return log_error_errno(errno, "Failed to get syspath for HID device: %m");

        desc_path = path_join(sys_path, "report_descriptor");
        if (desc_path == NULL)
                return log_oom();

        fd = open(desc_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0)
                return log_error_errno(errno,
                                              "Failed to open report descriptor at '%s': %m", desc_path);

        desc_len = read(fd, desc, sizeof(desc));
        if (desc_len < 0)
                return log_error_errno(errno,
                                              "Failed to read report descriptor at '%s': %m", desc_path);
        if (desc_len == 0)
                return log_debug_errno(/*SYNTHETIC_ERRNO*/(EINVAL),
                                              "Empty report descriptor at '%s'.", desc_path);

        r = is_fido_security_token_desc(desc, desc_len);
        if (r < 0)
                return log_debug_errno(errno,
                                              "Failed to parse report descriptor at '%s'.", desc_path);
        if (r > 0) {
                printf("ID_FIDO_TOKEN=1\n");
                printf("ID_SECURITY_TOKEN=1\n");
        }

        return 0;
}

