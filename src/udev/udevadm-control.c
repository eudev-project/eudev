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

/* A control message of udevadm control, with what the messages of send_control_commands() call it. */
struct control_command {
        enum udev_ctrl_msg_type type;
        int intval;
        const char *buf;
        const char *what;
        /* the message when udevd does not know it, see udev_ctrl_send_one() */
        const char *unsupported;
};

static int log_send_failure(const struct control_command *c, int r) {
        if (r == -EOPNOTSUPP && c->unsupported)
                return log_error_errno(r, "%s", c->unsupported);

        return log_error_errno(r, "Failed to send %s: %m", c->what);
}

/* Like send_control_commands_via_ctrl() of systemd v261: the commands are sent in a fixed order, whatever their
 * order on the command line, and then udevadm waits once until udevd handled all of them; the first one that
 * fails stops it. --exit is sent alone, and waits until udevd exits. */
static int send_control_commands(struct udev_ctrl *uctrl, int timeout,
                                 bool arg_exit, bool arg_revert, int arg_log_level, int arg_start_exec_queue,
                                 bool arg_reload, char **arg_env, int arg_max_children, bool arg_ping, int arg_trace) {
        _cleanup_free_ struct control_command *commands = NULL;
        size_t n = 0, i;
        char **e;
        int r;

        if (arg_exit) {
                r = udev_ctrl_send_exit(uctrl, timeout);
                if (r < 0)
                        return log_error_errno(r, "Failed to send exit request: %m");
                return 0;
        }

        commands = new0(struct control_command, 7 + strv_length(arg_env));
        if (!commands)
                return log_oom();

        if (arg_revert)
                commands[n++] = (struct control_command) {
                        .type = UDEV_CTRL_REVERT,
                        .what = "revert request",
                        .unsupported = "udevd does not support --revert, restart it after upgrading.",
                };

        if (arg_log_level >= 0)
                commands[n++] = (struct control_command) {
                        .type = UDEV_CTRL_SET_LOG_LEVEL,
                        .intval = arg_log_level,
                        .what = "request to set log level",
                };

        if (arg_start_exec_queue >= 0)
                commands[n++] = (struct control_command) {
                        .type = arg_start_exec_queue ? UDEV_CTRL_START_EXEC_QUEUE : UDEV_CTRL_STOP_EXEC_QUEUE,
                        .what = arg_start_exec_queue ? "request to start exec queue" : "request to stop exec queue",
                };

        if (arg_reload)
                commands[n++] = (struct control_command) {
                        .type = UDEV_CTRL_RELOAD,
                        .what = "reload request",
                };

        STRV_FOREACH(e, arg_env)
                commands[n++] = (struct control_command) {
                        .type = UDEV_CTRL_SET_ENV,
                        .buf = *e,
                        .what = "request to update environment",
                };

        if (arg_max_children >= 0)
                commands[n++] = (struct control_command) {
                        .type = UDEV_CTRL_SET_CHILDREN_MAX,
                        .intval = arg_max_children,
                        .what = "request to set number of children",
                };

        if (arg_ping)
                commands[n++] = (struct control_command) {
                        .type = UDEV_CTRL_PING,
                        .what = "a ping message",
                };

        if (arg_trace >= 0)
                commands[n++] = (struct control_command) {
                        .type = UDEV_CTRL_SET_TRACE,
                        .intval = arg_trace,
                        .what = "request to set trace logging",
                        .unsupported = "udevd does not support --trace, restart it after upgrading.",
                };

        for (i = 0; i < n; i++) {
                r = udev_ctrl_send(uctrl, commands[i].type, commands[i].intval, commands[i].buf);
                if (r == -EPROTONOSUPPORT)
                        goto one_by_one;
                if (r < 0)
                        return log_send_failure(&commands[i], r);
        }

        r = udev_ctrl_wait(uctrl, timeout);
        if (r == -EPROTONOSUPPORT)
                goto one_by_one;
        if (r < 0)
                return log_error_errno(r, "Failed to wait for daemon to reply: %m");

        return 0;

one_by_one:
        /* udevd of eudev before udev_ctrl_send() handles only the first message of a connection, and handled
         * none of these, see udev_ctrl_send(): send each message on a connection of its own, and wait each
         * time, which also finds out whether it knows --trace and --revert. */
        log_debug("udevd handles one control message per connection, sending each one alone.");

        for (i = 0; i < n; i++) {
                r = udev_ctrl_send_one(uctrl, commands[i].type, commands[i].intval, commands[i].buf, timeout, NULL);
                if (r < 0)
                        return log_send_failure(&commands[i], r);
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
                { "help",             no_argument,       NULL, 'h' },
                { "version",          no_argument,       NULL, 'V' },
                { "exit",             no_argument,       NULL, 'e' },
                { "log-priority",     required_argument, NULL, 'l' }, /* for backward compatibility */
                { "log-level",        required_argument, NULL, 'l' },
                { "stop-exec-queue",  no_argument,       NULL, 's' },
                { "start-exec-queue", no_argument,       NULL, 'S' },
                { "reload-rules",     no_argument,       NULL, 'R' }, /* alias for -R */
                { "reload",           no_argument,       NULL, 'R' },
                { "env",              required_argument, NULL, 'p' }, /* alias for -p */
                { "property",         required_argument, NULL, 'p' },
                { "children-max",     required_argument, NULL, 'm' },
                { "ping",             no_argument,       NULL, ARG_PING },
                { "trace",            required_argument, NULL, ARG_TRACE },
                { "revert",           no_argument,       NULL, ARG_REVERT },
                { "timeout",          required_argument, NULL, 't' },
                {}
        };

        /* Like systemd, parse all options before anything is sent, so that --help and --version work without
         * root privileges, and an invalid option sends nothing. For the options that are given more than once,
         * the last one counts, except that all the properties of --property are set. */
        while ((c = getopt_long_log(argc, argv, "el:sSRp:m:t:hV", options)) >= 0)
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

        log_command_call(&udevadm_control);

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
                log_error_errno(errno_or_else(ENOMEM), "Failed to initialize udev control: %m");
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
