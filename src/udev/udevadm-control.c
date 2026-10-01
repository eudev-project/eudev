/*
 * Copyright (C) 2005-2011 Kay Sievers <kay@vrfy.org>
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
 */

#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>

#include "pager.h"
#include "strv.h"
#include "udev.h"
#include "udev-util.h"
#include "udevadm-util.h"
#include "virt.h"

static void print_help(void) {
        pager_open(0);

        printf("%s control COMMAND\n\n"
               "Control the udev daemon.\n\n"
               "  -h --help                Show this help\n"
               "  -V --version             Show package version\n"
               "  -e --exit                Instruct the daemon to cleanup and exit\n"
               "  -l --log-level=LEVEL     Set the udev log level for the daemon\n"
               "  -s --stop-exec-queue     Do not execute events, queue only\n"
               "  -S --start-exec-queue    Execute events, flush queue\n"
               "  -R --reload              Reload rules and databases\n"
               "  -p --property=KEY=VALUE  Set a global property for all events\n"
               "  -m --children-max=N      Maximum number of children\n"
               "     --ping                Wait for udev to respond to a ping message\n"
               "     --trace=BOOL          Enable/disable trace logging\n"
               "     --revert              Revert previously set configurations\n"
               "  -t --timeout=SECONDS     Maximum time to block for a reply\n"
               , program_invocation_short_name);
        print_man_page_link();
}

/* Like send_control_commands() of systemd: the commands are sent in a fixed order, whatever their order
 * on the command line, and the first one that fails stops it. --exit is sent alone. */
static int send_control_commands(struct udev_ctrl *uctrl, int timeout,
                                 bool arg_exit, bool arg_revert, int arg_log_level, int arg_start_exec_queue,
                                 bool arg_reload, char **arg_env, int arg_max_children, bool arg_ping, int arg_trace) {
        char **e;
        int r;

        if (arg_exit) {
                r = udev_ctrl_send_exit(uctrl, timeout);
                if (r < 0)
                        return log_error_errno(r, "Failed to send exit request: %m");
                return 0;
        }

        if (arg_revert) {
                r = udev_ctrl_send_revert(uctrl, timeout);
                if (r == -EOPNOTSUPP)
                        return log_error_errno(r, "udevd does not support --revert, restart it after upgrading.");
                if (r < 0)
                        return log_error_errno(r, "Failed to send revert request: %m");
        }

        if (arg_log_level >= 0) {
                r = udev_ctrl_send_set_log_level(uctrl, arg_log_level, timeout);
                if (r < 0)
                        return log_error_errno(r, "Failed to send request to set log level: %m");
        }

        if (arg_start_exec_queue >= 0) {
                if (arg_start_exec_queue)
                        r = udev_ctrl_send_start_exec_queue(uctrl, timeout);
                else
                        r = udev_ctrl_send_stop_exec_queue(uctrl, timeout);
                if (r < 0)
                        return log_error_errno(r, "Failed to send request to %s exec queue: %m",
                                               arg_start_exec_queue ? "start" : "stop");
        }

        if (arg_reload) {
                r = udev_ctrl_send_reload(uctrl, timeout);
                if (r < 0)
                        return log_error_errno(r, "Failed to send reload request: %m");
        }

        STRV_FOREACH(e, arg_env) {
                r = udev_ctrl_send_set_env(uctrl, *e, timeout);
                if (r < 0)
                        return log_error_errno(r, "Failed to send request to update environment: %m");
        }

        if (arg_max_children >= 0) {
                r = udev_ctrl_send_set_children_max(uctrl, arg_max_children, timeout);
                if (r < 0)
                        return log_error_errno(r, "Failed to send request to set number of children: %m");
        }

        if (arg_ping) {
                r = udev_ctrl_send_ping(uctrl, timeout);
                if (r < 0)
                        return log_error_errno(r, "Failed to send a ping message: %m");
        }

        if (arg_trace >= 0) {
                r = udev_ctrl_send_set_trace(uctrl, arg_trace, timeout);
                if (r == -EOPNOTSUPP)
                        return log_error_errno(r, "udevd does not support --trace, restart it after upgrading.");
                if (r < 0)
                        return log_error_errno(r, "Failed to send request to set trace logging: %m");
        }

        return 0;
}

static int adm_control(struct udev *udev, int argc, char *argv[]) {
        _cleanup_udev_ctrl_unref_ struct udev_ctrl *uctrl = NULL;
        _cleanup_strv_free_ char **arg_env = NULL;
        bool arg_exit = false, arg_revert = false, arg_reload = false, arg_ping = false;
        int arg_log_level = -1, arg_start_exec_queue = -1, arg_max_children = -1, arg_trace = -1;
        int timeout = 60;
        int c, r;

        enum {
                ARG_PING = 0x100,
                ARG_TRACE,
                ARG_REVERT,
        };

        static const struct option options[] = {
                { "exit",             no_argument,       NULL, 'e' },
                { "log-level",        required_argument, NULL, 'l' },
                { "log-priority",     required_argument, NULL, 'l' }, /* for backward compatibility */
                { "stop-exec-queue",  no_argument,       NULL, 's' },
                { "start-exec-queue", no_argument,       NULL, 'S' },
                { "reload",           no_argument,       NULL, 'R' },
                { "reload-rules",     no_argument,       NULL, 'R' }, /* alias for -R */
                { "property",         required_argument, NULL, 'p' },
                { "env",              required_argument, NULL, 'p' }, /* alias for -p */
                { "children-max",     required_argument, NULL, 'm' },
                { "ping",             no_argument,       NULL, ARG_PING },
                { "trace",            required_argument, NULL, ARG_TRACE },
                { "revert",           no_argument,       NULL, ARG_REVERT },
                { "timeout",          required_argument, NULL, 't' },
                { "help",             no_argument,       NULL, 'h' },
                { "version",          no_argument,       NULL, 'V' },
                {}
        };

        /* Like systemd, parse all options before anything is sent, so that --help and --version work without
         * root privileges, and an invalid option sends nothing. For the options that are given more than once,
         * the last one counts, except that all the properties of --property are set. */
        while ((c = getopt_long(argc, argv, "el:sSRp:m:t:hV", options, NULL)) >= 0)
                switch (c) {
                case 'e':
                        arg_exit = true;
                        break;
                case 'l':
                        arg_log_level = util_log_priority(optarg);
                        if (arg_log_level < 0) {
                                /* systemd's log_level_from_string() fails with EINVAL also for numbers
                                 * that are too large */
                                log_error_errno(EINVAL, "Failed to parse log level '%s': %m", optarg);
                                return 1;
                        }
                        break;
                case 's':
                        arg_start_exec_queue = false;
                        break;
                case 'S':
                        arg_start_exec_queue = true;
                        break;
                case 'R':
                        arg_reload = true;
                        break;
                case 'p':
                        if (strchr(optarg, '=') == NULL) {
                                log_error("expect <KEY>=<value> instead of '%s'", optarg);
                                return 1;
                        }
                        r = strv_extend(&arg_env, optarg);
                        if (r < 0) {
                                log_error_errno(r, "Failed to extend environment: %m");
                                return 1;
                        }
                        break;
                case 'm': {
                        unsigned i;

                        /* Like systemd, 0 asks udevd to use its default, computed from the system resources. */
                        r = safe_atou(optarg, &i);
                        if (r < 0) {
                                log_error_errno(r, "Failed to parse maximum number of children '%s': %m", optarg);
                                return 1;
                        }
                        if (i > INT_MAX) {
                                log_error("Maximum number of children is too large: %s", optarg);
                                return 1;
                        }
                        arg_max_children = i;
                        break;
                }
                case ARG_PING:
                        arg_ping = true;
                        break;
                case ARG_TRACE:
                        r = parse_boolean(optarg);
                        if (r < 0) {
                                log_error_errno(r, "Failed to parse boolean argument to '--trace=': %s", optarg);
                                return 1;
                        }
                        arg_trace = r;
                        break;
                case ARG_REVERT:
                        arg_revert = true;
                        break;
                case 't': {
                        usec_t timeout_usec;

                        /* Like systemd, units are accepted, e.g. "500ms", and the default unit is
                         * seconds. The control socket takes the timeout in seconds, round up. 0 means
                         * the default. */
                        r = parse_sec(optarg, &timeout_usec);
                        if (r < 0) {
                                log_error_errno(r, "Failed to parse timeout value '%s': %m", optarg);
                                return 1;
                        }
                        if (timeout_usec == 0)
                                timeout = 60;
                        else if (timeout_usec == USEC_INFINITY || timeout_usec / USEC_PER_SEC >= INT_MAX / MSEC_PER_SEC)
                                timeout = -1;
                        else
                                timeout = (timeout_usec + USEC_PER_SEC - 1) / USEC_PER_SEC;
                        break;
                }
                case 'h':
                        print_help();
                        return 0;
                case 'V':
                        printf("%s\n", UDEV_VERSION);
                        return 0;
                case '?':
                        return 1;
                default:
                        assert_not_reached("Unknown option");
                }

        if (!arg_exit && !arg_revert && arg_log_level < 0 && arg_start_exec_queue < 0 && !arg_reload &&
            strv_isempty(arg_env) && arg_max_children < 0 && !arg_ping && arg_trace < 0) {
                log_error("No control command option is specified.");
                return 1;
        }
        if (optind < argc) {
                log_error("This subprogram takes no positional arguments.");
                return 1;
        }

        /* Unlike systemd, the options are parsed first, so that --help, --version and invalid options
         * work in a chroot too, and only the commands are not sent there. */
        if (running_in_chroot() > 0) {
                log_info("Running in chroot, ignoring request.");
                return 0;
        }

        if (getuid() != 0) {
                log_error("root privileges required");
                return 1;
        }

        errno = 0;
        uctrl = udev_ctrl_new(udev);
        if (uctrl == NULL) {
                log_error_errno(errno > 0 ? errno : ENOMEM, "Failed to initialize udev control: %m");
                return 1;
        }

        r = send_control_commands(uctrl, timeout, arg_exit, arg_revert, arg_log_level, arg_start_exec_queue,
                                  arg_reload, arg_env, arg_max_children, arg_ping, arg_trace);
        return r < 0 ? 1 : 0;
}

const struct udevadm_cmd udevadm_control = {
        .name = "control",
        .cmd = adm_control,
        .help = "Control the udev daemon",
};
