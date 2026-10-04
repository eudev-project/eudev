/*
 * Copyright (C) 2006-2009 Kay Sievers <kay@vrfy.org>
 * Copyright (C) 2009 Canonical Ltd.
 * Copyright (C) 2009 Scott James Remnant <scott@netsplit.com>
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
#include <limits.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <time.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "pager.h"
#include "path-util.h"
#include "udev.h"
#include "udev-util.h"
#include "udevadm-util.h"
#include "util.h"
#include "virt.h"

static void help(void) {
        pager_open(0);

        printf("%s settle OPTIONS\n\n"
               "Wait for pending udev events.\n\n"
               "  -h --help                 Show this help\n"
               "  -V --version              Show package version\n"
               "  -t --timeout=SEC          Maximum time to wait for events\n"
               "  -E --exit-if-exists=FILE  Stop waiting if file exists\n"
               , program_invocation_short_name);
        print_man_page_link();
}

static int adm_settle(struct udev *udev, int argc, char *argv[]) {
        static const struct option options[] = {
                { "help",           no_argument,       NULL, 'h' },
                { "version",        no_argument,       NULL, 'V' },
                { "timeout",        required_argument, NULL, 't' },
                { "exit-if-exists", required_argument, NULL, 'E' },
                { "seq-start",      required_argument, NULL, 's' }, /* removed */
                { "seq-end",        required_argument, NULL, 'e' }, /* removed */
                { "quiet",          no_argument,       NULL, 'q' }, /* removed */
                {}
        };
        usec_t deadline, timeout_usec = 120 * USEC_PER_SEC;
        const char *exists = NULL;
        struct pollfd pfd[1] = { {.fd = -1}, };
        int c;
        struct udev_queue *queue;
        int rc = EXIT_FAILURE;

        while ((c = udevadm_getopt_long(argc, argv, "t:E:hs:e:qV", options)) >= 0) {
                switch (c) {

                case 't': {
                        int r;

                        /* Like systemd, units are accepted, e.g. "500ms", the default unit is seconds,
                         * and "infinity" waits without a limit. */
                        r = parse_sec(optarg, &timeout_usec);
                        if (r < 0) {
                                log_error_errno(r, "Failed to parse timeout value '%s': %m", optarg);
                                return EXIT_FAILURE;
                        }
                        break;
                }

                case 'E':
                        if (!path_is_valid(optarg)) {
                                log_error("Invalid path: %s", optarg);
                                return EXIT_FAILURE;
                        }

                        exists = optarg;
                        break;

                case 'h':
                        help();
                        return EXIT_SUCCESS;
                case 'V':
                        printf("%s\n", UDEV_VERSION);
                        return EXIT_SUCCESS;

                case 's':
                case 'e':
                case 'q':
                        log_info("Option -%c no longer supported.", c);
                        return EXIT_FAILURE;

                case '?':
                        return EXIT_FAILURE;

                default:
                        assert_not_reached("Unknown argument");
                }
        }

        if (optind < argc) {
                log_error("This subprogram takes no positional arguments.");
                return EXIT_FAILURE;
        }

        log_command_call(&udevadm_settle);

        if (running_in_chroot() > 0) {
                log_info("Running in chroot, ignoring request.");
                return 0;
        }

        deadline = usec_add(now(CLOCK_MONOTONIC), timeout_usec);

        /* guarantee that the udev daemon isn't pre-processing */
        if (getuid() == 0) {
                struct udev_ctrl *uctrl;
                usec_t ping_usec = MAX(5 * USEC_PER_SEC, timeout_usec);
                int ping_timeout;

                /* Like systemd v261, the last version that pings udevd through the control socket, fail
                 * if it cannot be created. */
                errno = 0;
                uctrl = udev_ctrl_new(udev);
                if (uctrl == NULL) {
                        log_error_errno(errno > 0 ? errno : ENOMEM, "Failed to initialize udev control: %m");
                        return EXIT_FAILURE;
                }

                /* The control socket takes the timeout in seconds, round up, and -1 waits without a
                 * limit. */
                if (ping_usec == USEC_INFINITY || ping_usec / USEC_PER_SEC >= INT_MAX / MSEC_PER_SEC)
                        ping_timeout = -1;
                else
                        ping_timeout = (ping_usec + USEC_PER_SEC - 1) / USEC_PER_SEC;

                if (udev_ctrl_send_ping(uctrl, ping_timeout) < 0) {
                        log_debug("no connection to daemon");
                        udev_ctrl_unref(uctrl);
                        return EXIT_SUCCESS;
                }
                udev_ctrl_unref(uctrl);
        } else if (access(UDEV_ROOT_RUN "/udev/control", F_OK) < 0) {
                /* Like systemd, for non-privileged users, at least check if udevd is running. */
                if (errno == ENOENT)
                        log_error("udevd is not running.");
                else
                        log_error_errno(errno, "Failed to check if " UDEV_ROOT_RUN "/udev/control exists: %m");
                return EXIT_FAILURE;
        }

        queue = udev_queue_new(udev);
        if (!queue) {
                log_error("unable to get udev queue");
                return EXIT_FAILURE;
        }

        pfd[0].events = POLLIN;
        pfd[0].fd = udev_queue_get_fd(queue);
        if (pfd[0].fd < 0) {
                log_debug("queue is empty, nothing to watch");
                rc = EXIT_SUCCESS;
                goto out;
        }

        for (;;) {
                usec_t n;

                if (exists && access(exists, F_OK) >= 0) {
                        rc = EXIT_SUCCESS;
                        break;
                }

                /* exit if queue is empty */
                if (udev_queue_get_queue_is_empty(queue)) {
                        rc = EXIT_SUCCESS;
                        break;
                }

                n = now(CLOCK_MONOTONIC);
                if (n >= deadline) {
                        log_error("Timed out while waiting for udev queue to empty.");
                        break;
                }

                /* wake up when queue is empty, at least every second, and at the deadline, which may
                 * be less than a second away */
                if (poll(pfd, 1, (int) MIN(MSEC_PER_SEC, (deadline - n + USEC_PER_MSEC - 1) / USEC_PER_MSEC)) > 0 &&
                    pfd[0].revents & POLLIN)
                        udev_queue_flush(queue);
        }

out:
        udev_queue_unref(queue);
        return rc;
}

const struct udevadm_cmd udevadm_settle = {
        .name = "settle",
        .cmd = adm_settle,
        .help = "Wait for pending udev events",
};
