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


//#include "libudev.h"
//#include "libudev-private.h"
//#include "fido_id_desc.h"
//#include "udev-util.h"


#include "libudev.h"
#include "libudev-private.h"
//#include "device-private.h"
//#include "device-util.h"
//#include "fd-util.h"
#include "fido_id_desc.h"
#include "log.h"
#include "macro.h"
//#include "main-func.h"
#include "path-util.h"
//#include "string-util.h"
#include "udev.h"
#include "udev-util.h"
#include "libudev.h"
#include "libudev-private.h"

int device_new_aux(struct udev_device **ret) {
        struct udev_device *device;

        assert(ret);

        device = new(struct udev_device, 1);
        if (!device)
                return -ENOMEM;

        *device = (struct udev_device) {
                .n_ref = 1,
                .watch_handle = -1,
                .devmode = MODE_INVALID,
                .devuid = UID_INVALID,
                .devgid = GID_INVALID,
                .action = _SD_DEVICE_ACTION_INVALID,
        };

        *ret = device;
        return 0;
}

int device_new_from_strv(struct udev_device **ret, char **strv) {
        _cleanup_(udev_device_unrefp) struct udev_device *device = NULL;
        const char *major = NULL, *minor = NULL;
        int r;

        assert(ret);
        assert(strv);

        r = device_new_aux(&device);
        if (r < 0)
                return r;

        STRV_FOREACH(key, strv) {
                r = device_append(device, *key, &major, &minor);
                if (r < 0)
                        return r;
        }

        if (major) {
                r = device_set_devnum(device, major, minor);
                if (r < 0)
                        return log_device_debug_errno(device, r, "sd-device: Failed to set devnum %s:%s: %m", major, minor);
        }

        r = device_verify(device);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(device);

        return 0;
}

int main(int argc, char **argv) {
        _cleanup_(udev_device_unrefp) struct udev_device *device = NULL;
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

        if (argc > 2)
                return log_error_errno(/*SYNTHETIC_ERRNO*/(EINVAL), "Usage: %s [SYSFS_PATH]", program_invocation_short_name);

        if (argc == 1) {
                r = device_new_from_strv(&device, environ);
                if (r < 0)
                        return log_error_errno(r, "Failed to get current device from environment: %m");
        } else {
                r = udev_device_new_from_syspath(&device, argv[1]);
                if (r < 0)
                        return log_error_errno(r, "Failed to get device from syspath: %m");
        }

        r = udev_device_get_parent(device, &hid_device);
        if (r < 0)
                return log_device_error_errno(device, r, "Failed to get parent HID device: %m");

        r = udev_device_get_syspath(hid_device, &sys_path);
        if (r < 0)
                return log_device_error_errno(hid_device, r, "Failed to get syspath for HID device: %m");

        desc_path = path_join(sys_path, "report_descriptor");
        if (!desc_path)
                return log_oom();

        fd = open(desc_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0)
                return log_device_error_errno(hid_device, errno,
                                              "Failed to open report descriptor at '%s': %m", desc_path);

        desc_len = read(fd, desc, sizeof(desc));
        if (desc_len < 0)
                return log_device_error_errno(hid_device, errno,
                                              "Failed to read report descriptor at '%s': %m", desc_path);
        if (desc_len == 0)
                return log_device_debug_errno(hid_device, /*SYNTHETIC_ERRNO*/(EINVAL),
                                              "Empty report descriptor at '%s'.", desc_path);

        r = is_fido_security_token_desc(desc, desc_len);
        if (r < 0)
                return log_device_debug_errno(hid_device, r,
                                              "Failed to parse report descriptor at '%s'.", desc_path);
        if (r > 0) {
                printf("ID_FIDO_TOKEN=1\n");
                printf("ID_SECURITY_TOKEN=1\n");
        }

        return 0;
}

