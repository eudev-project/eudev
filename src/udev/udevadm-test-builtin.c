/*
 * Copyright (C) 2011 Kay Sievers <kay@vrfy.org>
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
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <time.h>
#include <sys/inotify.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "pager.h"
#include "udev.h"
#include "udevadm-util.h"

static void help(struct udev *udev) {
        pager_open(0);

        printf("%s test-builtin [OPTIONS] COMMAND DEVPATH\n\n"
               "Test a built-in command.\n\n"
               "  -h --help               Print this message\n"
               "  -V --version            Print version of the program\n"
               "  -a --action=ACTION|help Set action string\n"
               , program_invocation_short_name);
        print_man_page_link();

        printf("\nCommands:\n");
        udev_builtin_list(udev);
}

static int adm_builtin(struct udev *udev, int argc, char *argv[]) {
        static const struct option options[] = {
                { "action",  required_argument, NULL, 'a' },
                { "help",    no_argument,       NULL, 'h' },
                { "version", no_argument,       NULL, 'V' },
                {}
        };
        const char *action = "add";
        char *command = NULL;
        char *syspath = NULL;
        struct udev_device *dev = NULL;
        enum udev_builtin_cmd cmd;
        int rc = EXIT_SUCCESS, c, r;

        while ((c = getopt_long(argc, argv, "a:hV", options, NULL)) >= 0)
                switch (c) {
                case 'a':
                        r = parse_device_action(optarg, &action);
                        if (r < 0) {
                                log_error("Invalid action '%s'", optarg);
                                rc = EXIT_FAILURE;
                                goto out;
                        }
                        if (r == 0)
                                goto out;
                        break;
                case 'h':
                        help(udev);
                        goto out;
                case 'V':
                        printf("%s\n", UDEV_VERSION);
                        goto out;
                case '?':
                        rc = EXIT_FAILURE;
                        goto out;
                default:
                        assert_not_reached("Unknown option");
                }

        if (argc - optind > 2) {
                log_error("Expected two arguments: command string and device path.");
                rc = EXIT_FAILURE;
                goto out;
        }

        command = argv[optind++];
        if (command == NULL) {
                fprintf(stderr, "command missing\n");
                help(udev);
                rc = 2;
                goto out;
        }

        syspath = argv[optind++];
        if (syspath == NULL) {
                fprintf(stderr, "device is missing\n");
                rc = 3;
                goto out;
        }

        udev_builtin_init(udev);

        cmd = udev_builtin_lookup(command);
        if (cmd >= UDEV_BUILTIN_MAX) {
                fprintf(stderr, "unknown command '%s'\n", command);
                help(udev);
                rc = 5;
                goto out;
        }

        dev = find_device_with_action(udev, syspath, action);
        if (dev == NULL) {
                log_error_errno(errno > 0 ? errno : ENODEV, "Failed to open device '%s': %m", syspath);
                rc = 4;
                goto out;
        }

        rc = udev_builtin_run(dev, cmd, command, EVENT_UDEVADM_TEST_BUILTIN);
        if (rc < 0) {
                fprintf(stderr, "error executing '%s', exit code %i\n\n", command, rc);
                rc = 6;
        }
out:
        udev_device_unref(dev);
        udev_builtin_exit(udev);
        return rc;
}

const struct udevadm_cmd udevadm_test_builtin = {
        .name = "test-builtin",
        .cmd = adm_builtin,
        .help = "Test a built-in command",
        .debug = true,
};
