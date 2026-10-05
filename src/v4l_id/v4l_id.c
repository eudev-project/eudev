/*
 * Copyright (C) 2009 Kay Sievers <kay@vrfy.org>
 * Copyright (c) 2009 Filippo Argiolas <filippo.argiolas@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details:
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <linux/version.h>
#include <linux/videodev2.h>

#include "build.h"
#include "options.h"
#include "util.h"
#include "utf8.h"

int main(int argc, char *argv[]) {
        static const struct option options[] = {
                { "help",     no_argument, NULL, 'h' },
                { "version",  no_argument, NULL, 'v' },
                {}
        };
        _cleanup_close_ int fd = -1;
        char *device;
        struct v4l2_capability v2cap;
        int c;

        /* like the other helpers; unlike systemd's mtd_probe and v4l_id, which do not set up logging */
        log_parse_environment();
        log_open();

        while ((c = getopt_long_log(argc, argv, "h", options)) >= 0)

                switch (c) {
                case 'h':
                        printf("%s [OPTIONS...] DEVICE\n\n"
                               "Video4Linux device identification.\n\n"
                               "  -h --help     Show this help text\n"
                               "     --version  Show package version\n",
                               program_invocation_short_name);
                        return 0;
                case 'v':
                        return version();
                case '?':
                        return EXIT_FAILURE;

                default:
                        assert_not_reached("Unhandled option");
                }

        if (argc - optind != 1) {
                log_error("Need exactly one DEVICE argument.");
                return EXIT_FAILURE;
        }

        device = argv[optind];

        fd = open(device, O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0) {
                bool ignore = IN_SET(errno, ENODEV, ENXIO, ENOENT, ENOMEDIUM);
                log_full_errno(ignore ? LOG_DEBUG : LOG_WARNING, errno,
                               "Failed to open device node '%s'%s: %m",
                               device, ignore ? ", ignoring" : "");
                return ignore ? EXIT_SUCCESS : EXIT_FAILURE;
        }

        if (ioctl(fd, VIDIOC_QUERYCAP, &v2cap) == 0) {
                int capabilities;
                printf("ID_V4L_VERSION=2\n");
                if (utf8_is_valid((char *)v2cap.card) && !string_has_cc((char *)v2cap.card, /* ok= */ NULL))
                        printf("ID_V4L_PRODUCT=%s\n", v2cap.card);
                printf("ID_V4L_CAPABILITIES=:");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,0)
                if (v2cap.capabilities & V4L2_CAP_DEVICE_CAPS)
                        capabilities = v2cap.device_caps;
                else
#endif
                        capabilities = v2cap.capabilities;
                if ((capabilities & V4L2_CAP_VIDEO_CAPTURE) > 0 ||
                    (capabilities & V4L2_CAP_VIDEO_CAPTURE_MPLANE) > 0)
                        printf("capture:");
                if ((capabilities & V4L2_CAP_VIDEO_OUTPUT) > 0 ||
                    (capabilities & V4L2_CAP_VIDEO_OUTPUT_MPLANE) > 0)
                        printf("video_output:");
                if ((capabilities & V4L2_CAP_VIDEO_OVERLAY) > 0)
                        printf("video_overlay:");
                if ((capabilities & V4L2_CAP_AUDIO) > 0)
                        printf("audio:");
                if ((capabilities & V4L2_CAP_TUNER) > 0)
                        printf("tuner:");
                if ((capabilities & V4L2_CAP_RADIO) > 0)
                        printf("radio:");
                printf("\n");
        } else {
                /* Unlike systemd, which succeeds without output, fail if the device cannot be
                 * queried, so that IMPORT{program}="v4l_id ..." does not match then. */
                log_error_errno(errno, "Failed to query the capabilities of '%s': %m", device);
                return EXIT_FAILURE;
        }

        return 0;
}
