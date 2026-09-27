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
#include <getopt.h>
#include <grp.h>
#include <pwd.h>
#include <sys/signalfd.h>

#include "udev.h"
#include "udev-util.h"
#include "terminal-util.h"

static bool use_colors(void) {
        static int cached = -1;

        if (cached < 0)
                cached = isatty(STDOUT_FILENO) > 0 && !getenv("NO_COLOR") && !streq_ptr(getenv("TERM"), "dumb");
        return cached;
}

static const char *ansi_highlight(void) {
        return use_colors() ? ANSI_HIGHLIGHT_ON : "";
}

static const char *ansi_normal(void) {
        return use_colors() ? ANSI_HIGHLIGHT_OFF : "";
}

static void dump_event(struct udev_event *event) {
        struct udev_device *dev = event->dev;
        struct udev_list_entry *entry;

        printf("%sProperties:%s\n", ansi_highlight(), ansi_normal());
        udev_list_entry_foreach(entry, udev_device_get_properties_list_entry(dev))
                printf("  %s=%s\n", udev_list_entry_get_name(entry), udev_list_entry_get_value(entry));

        if (udev_device_get_tags_list_entry(dev)) {
                printf("%sTags:%s\n", ansi_highlight(), ansi_normal());
                udev_list_entry_foreach(entry, udev_device_get_tags_list_entry(dev))
                        printf("  %s\n", udev_list_entry_get_name(entry));
        }

        if (major(udev_device_get_devnum(dev)) > 0) {
                /* The owner, group and mode are not determined for remove events, see
                 * udev_event_execute_rules(). */
                bool perms = !streq_ptr(udev_device_get_action(dev), "remove");

                if (udev_device_get_devlinks_list_entry(dev)) {
                        printf("%sDevice node symlinks:%s (priority=%i)\n", ansi_highlight(), ansi_normal(),
                               udev_device_get_devlink_priority(dev));
                        udev_list_entry_foreach(entry, udev_device_get_devlinks_list_entry(dev))
                                printf("  %s\n", udev_list_entry_get_name(entry));
                }

                printf("%sInotify watch:%s\n  %s\n", ansi_highlight(), ansi_normal(),
                       event->inotify_watch ? "enabled" : "disabled");

                if (perms) {
                        struct passwd *pw = getpwuid(event->uid);

                        printf("%sDevice node owner:%s\n  %s (uid="UID_FMT")\n", ansi_highlight(), ansi_normal(),
                               pw ? pw->pw_name : "n/a", event->uid);
                }

                if (perms) {
                        struct group *gr = getgrgid(event->gid);

                        printf("%sDevice node group:%s\n  %s (gid="GID_FMT")\n", ansi_highlight(), ansi_normal(),
                               gr ? gr->gr_name : "n/a", event->gid);
                }

                if (perms)
                        printf("%sDevice node permission:%s\n  %04o\n", ansi_highlight(), ansi_normal(), event->mode);

                if (udev_list_get_entry(&event->seclabel_list)) {
                        printf("%sDevice node security label:%s\n", ansi_highlight(), ansi_normal());
                        udev_list_entry_foreach(entry, udev_list_get_entry(&event->seclabel_list))
                                printf("  %s : %s\n", udev_list_entry_get_name(entry), udev_list_entry_get_value(entry));
                }
        }

        if (udev_device_get_ifindex(dev) > 0 && !isempty(event->name))
                printf("%sNetwork interface name:%s\n  %s\n", ansi_highlight(), ansi_normal(), event->name);

        if (udev_list_get_entry(&event->run_list)) {
                printf("%sQueued commands:%s\n", ansi_highlight(), ansi_normal());
                udev_list_entry_foreach(entry, udev_list_get_entry(&event->run_list)) {
                        if (udev_list_entry_get_num(entry) < UDEV_BUILTIN_MAX)
                                printf("  RUN{builtin} : %s\n", udev_list_entry_get_name(entry));
                        else
                                printf("  RUN{program} : %s\n", udev_list_entry_get_name(entry));
                }
        }
}

static void help(void) {

        printf("%s test OPTIONS <syspath>\n\n"
               "Test an event run.\n"
               "  -h --help                            Show this help\n"
               "     --version                         Show package version\n"
               "  -a --action=ACTION                   Set action string\n"
               "  -N --resolve-names=early|late|never  When to resolve names\n"
               , program_invocation_short_name);
}

static int adm_test(struct udev *udev, int argc, char *argv[]) {
        int resolve_names = 1;
        char filename[UTIL_PATH_SIZE];
        const char *action = "add";
        const char *syspath = NULL;
        _cleanup_udev_rules_unref_ struct udev_rules *rules = NULL;
        _cleanup_udev_device_unref_ struct udev_device *dev = NULL;
        _cleanup_udev_event_unref_ struct udev_event *event = NULL;
        sigset_t mask, sigmask_orig;
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
                        help();
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

        dev = udev_device_new_from_synthetic_event(udev, filename, action);
        if (dev == NULL) {
                fprintf(stderr, "unable to open device '%s'\n", filename);
                rc = 4;
                goto out;
        }

        /* don't read info from the db */
        udev_device_set_info_loaded(dev);

        event = udev_event_new(dev, EVENT_UDEVADM_TEST);

        sigfillset(&mask);
        sigprocmask(SIG_SETMASK, &mask, &sigmask_orig);
        event->fd_signal = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC);
        if (event->fd_signal < 0) {
                fprintf(stderr, "error creating signalfd\n");
                rc = 5;
                goto out;
        }

        udev_event_execute_rules(event,
                                 60 * USEC_PER_SEC, 20 * USEC_PER_SEC,
                                 NULL,
                                 rules,
                                 &sigmask_orig);

        dump_event(event);
out:
        if (event != NULL && event->fd_signal >= 0)
                close(event->fd_signal);
        udev_builtin_exit(udev);
        return rc;
}

const struct udevadm_cmd udevadm_test = {
        .name = "test",
        .cmd = adm_test,
        .help = "Test an event run",
        .debug = true,
};
