/*
 * Copyright (C) 2003-2004 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2004-2008 Kay Sievers <kay@vrfy.org>
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
#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>
#include <getopt.h>
#include <sys/signalfd.h>

#include "udev.h"
#include "udev-util.h"

static int adm_test(struct udev *udev, int argc, char *argv[])
{
        int resolve_names = 1;
        char filename[UTIL_PATH_SIZE];
        const char *action = "add";
        const char *syspath = NULL;
        struct udev_list_entry *entry;
        _cleanup_udev_rules_unref_ struct udev_rules *rules = NULL;
        _cleanup_udev_device_unref_ struct udev_device *dev = NULL;
        _cleanup_udev_event_unref_ struct udev_event *event = NULL;
        sigset_t mask, sigmask_orig;
        int err;
        int rc = 0, c;

        static const struct option options[] = {
                { "action", required_argument, NULL, 'a' },
                { "resolve-names", required_argument, NULL, 'N' },
                { "help", no_argument, NULL, 'h' },
                {}
        };

        log_debug("version %s", VERSION);

        while((c = getopt_long(argc, argv, "a:N:h", options, NULL)) >= 0)
                switch (c) {
                case 'a':
                        action = optarg;
                        break;
                case 'N':
                        if (streq (optarg, "early")) {
                                resolve_names = 1;
                        } else if (streq (optarg, "late")) {
                                resolve_names = 0;
                        } else if (streq (optarg, "never")) {
                                resolve_names = -1;
                        } else {
                                fprintf(stderr, "resolve-names must be early, late or never\n");
                                log_error("resolve-names must be early, late or never");
                                exit(EXIT_FAILURE);
                        }
                        break;
                case 'h':
                        printf("Usage: udevadm test OPTIONS <syspath>\n"
                               "  -a,--action=ACTION                  set action string\n"
                               "  -N,--resolve-names=early|late|never when to resolve names\n"
                               "  -h,--help                           print this help string\n"
                               "\n");
                        exit(EXIT_SUCCESS);
                case '?':
                        exit(EXIT_FAILURE);
                default:
                        assert_not_reached("Unknown option");
                }

        syspath = argv[optind];
        if (syspath == NULL) {
                fprintf(stderr, "syspath parameter missing\n");
                rc = 2;
                goto out;
        }

        printf("This program is for debugging only, it does not run any program\n"
               "specified by a RUN key. It may show incorrect results, because\n"
               "some values may be different, or not available at a simulation run.\n"
               "\n");

        sigprocmask(SIG_SETMASK, NULL, &sigmask_orig);

        udev_builtin_init(udev);

        rules = udev_rules_new(udev, resolve_names);
        if (rules == NULL) {
                fprintf(stderr, "error reading rules\n");
                rc = 3;
                goto out;
        }

        /* add /sys if needed */
        if (!startswith(syspath, "/sys"))
                strscpyl(filename, sizeof(filename), "/sys", syspath, NULL);
        else
                strscpy(filename, sizeof(filename), syspath);
        util_remove_trailing_chars(filename, '/');

        dev = udev_device_new_from_syspath(udev, filename);
        if (dev == NULL) {
                fprintf(stderr, "unable to open device '%s'\n", filename);
                rc = 4;
                goto out;
        }

        /* skip reading of db, but read kernel parameters */
        udev_device_set_info_loaded(dev);
        udev_device_read_uevent_file(dev);

        udev_device_set_action(dev, action);
        event = udev_event_new(dev);

        sigfillset(&mask);
        sigprocmask(SIG_SETMASK, &mask, &sigmask_orig);
        event->fd_signal = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC);
        if (event->fd_signal < 0) {
                fprintf(stderr, "error creating signalfd\n");
                rc = 5;
                goto out;
        }

        err = udev_event_execute_rules(event, rules, &sigmask_orig);

        udev_list_entry_foreach(entry, udev_device_get_properties_list_entry(dev))
                printf("%s=%s\n", udev_list_entry_get_name(entry), udev_list_entry_get_value(entry));

        if (err == 0) {
                udev_list_entry_foreach(entry, udev_list_get_entry(&event->run_list)) {
                        char program[UTIL_PATH_SIZE];

                        udev_event_apply_format(event, udev_list_entry_get_name(entry), program, sizeof(program));
                        printf("run: '%s'\n", program);
                }
        }
out:
        if (event != NULL && event->fd_signal >= 0)
                close(event->fd_signal);
        udev_builtin_exit(udev);
        return rc;
}

const struct udevadm_cmd udevadm_test = {
        .name = "test",
        .cmd = adm_test,
        .help = "test an event run",
        .debug = true,
};
