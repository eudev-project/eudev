/*
 * Copyright (C) 2010 - Maxim Levitsky
 *
 * mtd_probe is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * mtd_probe is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with mtd_probe; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor,
 * Boston, MA  02110-1301  USA
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <mtd/mtd-user.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include "mtd_probe.h"

static const char *arg_device = NULL;

static int parse_argv(int argc, char *argv[]) {
        static const struct option options[] = {
                { "help",   no_argument, NULL, 'h' },
                {}
        };
        int c;

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)
                switch (c) {
                case 'h':
                        printf("%s /dev/mtd[n]\n\n"
                               "  -h --help     Show this help text\n",
                               program_invocation_short_name);
                        return 0;
                case '?':
                        return -EINVAL;
                default:
                        assert_not_reached("Unknown option");
                }

        if (argc > 2)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Error: unexpected argument.");

        arg_device = argv[optind];
        if (!arg_device)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "DEVICE argument missing.");

        return 1;
}

int main(int argc, char** argv) {
        int mtd_fd = -1;
        mtd_info_t mtd_info;
        int r;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r < 0 ? EXIT_FAILURE : 0;

        mtd_fd = open(arg_device, O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (mtd_fd < 0) {
                bool ignore = IN_SET(errno, ENODEV, ENXIO, ENOENT, ENOMEDIUM);
                log_full_errno(ignore ? LOG_DEBUG : LOG_WARNING, errno,
                               "Failed to open device node '%s'%s: %m",
                               arg_device, ignore ? ", ignoring" : "");
                return ignore ? EXIT_SUCCESS : EXIT_FAILURE;
        }

        if (ioctl(mtd_fd, MEMGETINFO, &mtd_info) < 0) {
                log_error_errno(errno, "Failed to issue MEMGETINFO ioctl: %m");
                return EXIT_FAILURE;
        }

        if (probe_smart_media(mtd_fd, &mtd_info) < 0)
                return EXIT_FAILURE;

        return EXIT_SUCCESS;
}
