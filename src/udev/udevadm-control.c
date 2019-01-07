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

/* A command option, which is sent to the daemon after all options are parsed. */
struct control_command {
        int c;
        const char *arg;
        int value;
};

static int adm_control(struct udev *udev, int argc, char *argv[]) {
        _cleanup_udev_ctrl_unref_ struct udev_ctrl *uctrl = NULL;
        _cleanup_free_ struct control_command *commands = NULL;
        size_t n_commands = 0, i;
        int timeout = 60;
        int rc = 1, c, r;

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

        /* Parse all options before anything is sent, so that --help and --version work without root
         * privileges, and an invalid option does not leave the commands before it done. */
        commands = new0(struct control_command, argc);
        if (!commands) {
                log_oom();
                return 1;
        }

        while ((c = getopt_long(argc, argv, "el:sSRp:m:t:hV", options, NULL)) >= 0)
                switch (c) {
                case 'e':
                case 's':
                case 'S':
                case 'R':
                case ARG_PING:
                case ARG_REVERT:
                        commands[n_commands++] = (struct control_command) { .c = c };
                        break;
                case 'l': {
                        int i;

                        i = util_log_priority(optarg);
                        if (i < 0) {
                                fprintf(stderr, "invalid log level '%s'\n", optarg);
                                return rc;
                        }
                        commands[n_commands++] = (struct control_command) { .c = c, .value = i };
                        break;
                }
                case 'p':
                        if (strchr(optarg, '=') == NULL) {
                                fprintf(stderr, "expect <KEY>=<value> instead of '%s'\n", optarg);
                                return rc;
                        }
                        commands[n_commands++] = (struct control_command) { .c = c, .arg = optarg };
                        break;
                case 'm': {
                        char *endp;
                        int i;

                        i = strtoul(optarg, &endp, 0);
                        if (endp[0] != '\0' || i < 1) {
                                fprintf(stderr, "invalid number '%s'\n", optarg);
                                return rc;
                        }
                        commands[n_commands++] = (struct control_command) { .c = c, .value = i };
                        break;
                }
                case ARG_TRACE:
                        r = parse_boolean(optarg);
                        if (r < 0) {
                                log_error_errno(r, "Failed to parse boolean argument to --trace=: %s.", optarg);
                                return rc;
                        }
                        commands[n_commands++] = (struct control_command) { .c = c, .value = r };
                        break;
                case 't': {
                        int seconds;

                        seconds = atoi(optarg);
                        if (seconds >= 0)
                                timeout = seconds;
                        else
                                fprintf(stderr, "invalid timeout value\n");
                        break;
                }
                case 'h':
                        print_help();
                        return 0;
                case 'V':
                        printf("%s\n", UDEV_VERSION);
                        return 0;
                case '?':
                        return rc;
                default:
                        assert_not_reached("Unknown option");
                }

        if (optind < argc) {
                fprintf(stderr, "Extraneous argument: %s\n", argv[optind]);
                return rc;
        }
        if (n_commands == 0) {
                fprintf(stderr, "Option missing\n");
                return rc;
        }

        /* Unlike systemd, the options are parsed first, so that --help, --version and invalid options
         * work in a chroot too, and only the commands are not sent there. */
        if (running_in_chroot() > 0) {
                log_info("Running in chroot, ignoring request.");
                return 0;
        }

        if (getuid() != 0) {
                fprintf(stderr, "root privileges required\n");
                return 1;
        }

        uctrl = udev_ctrl_new(udev);
        if (uctrl == NULL)
                return 2;

        for (i = 0; i < n_commands; i++)
                switch (commands[i].c) {
                case 'e':
                        if (udev_ctrl_send_exit(uctrl, timeout) < 0)
                                rc = 2;
                        else
                                rc = 0;
                        break;
                case 'l':
                        if (udev_ctrl_send_set_log_level(uctrl, commands[i].value, timeout) < 0)
                                rc = 2;
                        else
                                rc = 0;
                        break;
                case 's':
                        if (udev_ctrl_send_stop_exec_queue(uctrl, timeout) < 0)
                                rc = 2;
                        else
                                rc = 0;
                        break;
                case 'S':
                        if (udev_ctrl_send_start_exec_queue(uctrl, timeout) < 0)
                                rc = 2;
                        else
                                rc = 0;
                        break;
                case 'R':
                        if (udev_ctrl_send_reload(uctrl, timeout) < 0)
                                rc = 2;
                        else
                                rc = 0;
                        break;
                case 'p':
                        if (udev_ctrl_send_set_env(uctrl, commands[i].arg, timeout) < 0)
                                rc = 2;
                        else
                                rc = 0;
                        break;
                case 'm':
                        if (udev_ctrl_send_set_children_max(uctrl, commands[i].value, timeout) < 0)
                                rc = 2;
                        else
                                rc = 0;
                        break;
                case ARG_PING:
                        r = udev_ctrl_send_ping(uctrl, timeout);
                        if (r < 0) {
                                log_error_errno(r, "Failed to connect to udev daemon: %m");
                                rc = 2;
                        } else
                                rc = 0;
                        break;
                case ARG_TRACE:
                        r = udev_ctrl_send_set_trace(uctrl, commands[i].value, timeout);
                        if (r == -EOPNOTSUPP)
                                log_error("udevd does not support --trace, restart it after upgrading.");
                        if (r < 0)
                                rc = 2;
                        else
                                rc = 0;
                        break;
                case ARG_REVERT:
                        r = udev_ctrl_send_revert(uctrl, timeout);
                        if (r == -EOPNOTSUPP)
                                log_error("udevd does not support --revert, restart it after upgrading.");
                        if (r < 0)
                                rc = 2;
                        else
                                rc = 0;
                        break;
                default:
                        assert_not_reached("Unknown command");
                }

        return rc;
}

const struct udevadm_cmd udevadm_control = {
        .name = "control",
        .cmd = adm_control,
        .help = "Control the udev daemon",
};
