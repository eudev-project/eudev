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
#include <sys/signalfd.h>

#include "netif-naming-scheme.h"
#include "pager.h"
#include "path-util.h"
#include "strv.h"
#include "udev.h"
#include "udev-util.h"
#include "udevadm-util.h"

static void maybe_insert_empty_line(void) {
        if (log_get_max_level() < LOG_INFO)
                return;

        fputs("\n", stderr);
}

static void help(void) {
        pager_open(0);


        printf("%s test [OPTIONS] DEVPATH|FILE\n\n"
               "Test an event run.\n"
               "  -h --help                            Show this help\n"
               "  -V --version                         Show package version\n"
               "  -a --action=ACTION|help              Set action string\n"
               "  -N --resolve-names=early|late|never  When to resolve names\n"
               "  -D --extra-rules-dir=DIR             Also load rules from the directory\n"
               "  -v --verbose                         Show verbose logs\n"
               "     --json=pretty|short|off           Generate JSON output\n"
               , program_invocation_short_name);
        print_man_page_link();
}

static int adm_test(struct udev *udev, int argc, char *argv[]) {
        int resolve_names = 1;
        const char *action = "add";
        _cleanup_strv_free_ char **extra_rules_dir = NULL;
        bool verbose = false;
        const char *syspath = NULL;
        _cleanup_udev_rules_unref_ struct udev_rules *rules = NULL;
        _cleanup_udev_device_unref_ struct udev_device *dev = NULL;
        _cleanup_udev_event_unref_ struct udev_event *event = NULL;
        JsonFormatFlags json_format_flags = JSON_FORMAT_OFF;
        sigset_t mask;
        int rc = 0, c, r;

        enum {
                ARG_JSON = 0x100,
        };

        static const struct option options[] = {
                { "help", no_argument, NULL, 'h' },
                { "version", no_argument, NULL, 'V' },
                { "action", required_argument, NULL, 'a' },
                { "resolve-names", required_argument, NULL, 'N' },
                { "extra-rules-dir", required_argument, NULL, 'D' },
                { "verbose", no_argument, NULL, 'v' },
                { "json", required_argument, NULL, ARG_JSON },
                {}
        };

        while((c = getopt_long_log(argc, argv, "a:N:D:vhV", options)) >= 0)
                switch (c) {
                case 'a':
                        r = parse_device_action(optarg, &action);
                        if (r < 0)
                                exit(EXIT_FAILURE);
                        if (r == 0)
                                exit(EXIT_SUCCESS);
                        break;
                case 'N':
                        r = parse_resolve_name_timing(optarg, &resolve_names);
                        if (r < 0)
                                exit(EXIT_FAILURE);
                        if (r == 0)
                                exit(EXIT_SUCCESS);
                        break;
                case 'D': {
                        _cleanup_free_ char *escaped = NULL;
                        char *p;

                        p = path_make_absolute_cwd(optarg);
                        if (!p) {
                                log_oom();
                                exit(EXIT_FAILURE);
                        }
                        path_simplify(p);

                        /* The rules files are only looked up in existing directories, so say so instead of
                         * silently testing without the rules the caller wanted, e.g. for a typo or a rules file
                         * given instead of its directory. */
                        r = is_dir(p, /* follow= */ true);
                        if (r <= 0) {
                                escaped = utf8_escape_non_printable(p);
                                if (r < 0)
                                        log_error_errno(r, "Failed to access '%s': %m", escaped ?: p);
                                else
                                        log_error_errno(ENOTDIR, "'%s' is not a directory.", escaped ?: p);
                                free(p);
                                exit(EXIT_FAILURE);
                        }

                        if (strv_consume(&extra_rules_dir, p) < 0) {
                                log_oom();
                                exit(EXIT_FAILURE);
                        }
                        break;
                }
                case 'v':
                        verbose = true;
                        break;
                case ARG_JSON:
                        r = parse_json_argument(optarg, &json_format_flags);
                        if (r < 0)
                                exit(EXIT_FAILURE);
                        if (r == 0)
                                exit(EXIT_SUCCESS);
                        break;
                case 'h':
                        help();
                        exit(EXIT_SUCCESS);
                case 'V':
                        printf("%s\n", UDEV_VERSION);
                        exit(EXIT_SUCCESS);
                case '?':
                        exit(EXIT_FAILURE);
                default:
                        assert_not_reached("Unknown option");
                }

        syspath = argv[optind];
        if (syspath == NULL) {
                log_error("syspath parameter missing.");
                rc = EXIT_FAILURE;
                goto out;
        }

        /* after the arguments are checked, like systemd, which parses them first */
        log_command_call(&udevadm_test);
        log_debug("version %s (udev %s)", VERSION, UDEV_VERSION);

        log_info("This program is for debugging only, it does not run any program\n"
                 "specified by a RUN key. It may show incorrect results, because\n"
                 "some values may be different, or not available at a simulation run.");

        udev_event_check_config(udev);

        /* not in the middle of the output when NAME= or net_id selects it */
        naming_scheme_set_log_level(LOG_DEBUG);

        maybe_insert_empty_line();
        log_info("Loading builtins...");
        udev_builtin_init(udev);
        log_info("Loading builtins done.");

        maybe_insert_empty_line();
        log_info("Loading udev rules files...");
        errno = 0;
        rules = udev_rules_new_full(udev, resolve_names, extra_rules_dir);
        if (rules == NULL) {
                /* it fails only for lack of memory */
                log_error_errno(errno > 0 ? errno : ENOMEM, "Failed to read udev rules: %m");
                rc = EXIT_FAILURE;
                goto out;
        }
        log_info("Loading udev rules files done.");

        dev = find_device_with_action(udev, syspath, action);
        if (dev == NULL) {
                int error = errno > 0 ? errno : ENODEV;
                /* the argument escaped like the values in the messages of the rules */
                _cleanup_free_ char *escaped = log_escape(LOG_ERR, syspath);

                log_error_errno(error, "Failed to open device '%s': %m", escaped ?: syspath);
                rc = EXIT_FAILURE;
                goto out;
        }

        /* don't read info from the db */
        udev_device_set_info_loaded(dev);

        event = udev_event_new(dev, EVENT_UDEVADM_TEST);
        if (!event) {
                log_oom();
                rc = EXIT_FAILURE;
                goto out;
        }
        event->trace = verbose;

        sigfillset(&mask);
        sigprocmask(SIG_SETMASK, &mask, NULL);
        event->fd_signal = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC);
        if (event->fd_signal < 0) {
                log_error_errno(errno, "Failed to create signalfd: %m");
                rc = EXIT_FAILURE;
                goto out;
        }

        maybe_insert_empty_line();
        log_info("Processing udev rules%s...", verbose ? "" : " (verbose logs can be shown by -v/--verbose)");
        r = udev_event_execute_rules(event,
                                     60 * USEC_PER_SEC,
                                     NULL,
                                     rules);
        if (r < 0)
                log_warning_errno(r, "Failed to process the rules, udevd would stop processing the event here and not run RUN: %m");
        log_info("Processing udev rules done.");

        maybe_insert_empty_line();
        r = dump_event(event, json_format_flags, NULL);
        if (r < 0) {
                log_error_errno(r, "Failed to dump result: %m");
                rc = EXIT_FAILURE;
        }
        maybe_insert_empty_line();
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
