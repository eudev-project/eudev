/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/
/*
 * Copyright (C) 2007-2012 Kay Sievers <kay@vrfy.org>
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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include "pager.h"
#include "udev.h"
#include "udevadm-util.h"

static int adm_version(struct udev *udev __attribute__((unused)), int argc __attribute__((unused)), char *argv[] __attribute__((unused))) {
        printf("%s\n", UDEV_VERSION);
        return 0;
}

static const struct udevadm_cmd udevadm_version = {
        .name = "version",
        .cmd = adm_version,
};

static int adm_help(struct udev *udev, int argc, char *argv[]);

static const struct udevadm_cmd udevadm_help = {
        .name = "help",
        .cmd = adm_help,
};

static const struct udevadm_cmd *udevadm_cmds[] = {
        &udevadm_info,
        &udevadm_trigger,
        &udevadm_settle,
        &udevadm_control,
        &udevadm_monitor,
        &udevadm_hwdb,
        &udevadm_test,
        &udevadm_test_builtin,
        &udevadm_verify,
        &udevadm_cat,
        &udevadm_wait,
        &udevadm_lock,
        &udevadm_version,
        &udevadm_help,
};

static int adm_help(struct udev *udev __attribute__((unused)), int argc __attribute__((unused)), char *argv[] __attribute__((unused))) {
        unsigned int i;

        pager_open(0);

        printf("%s [OPTIONS] COMMAND [COMMAND OPTIONS]\n\n"
               "Send control commands or test the device manager.\n\n"
               "Commands:\n"
               , program_invocation_short_name);

        for (i = 0; i < ELEMENTSOF(udevadm_cmds); i++)
                if (udevadm_cmds[i]->help != NULL)
                        printf("  %-12s  %s\n", udevadm_cmds[i]->name, udevadm_cmds[i]->help);

        printf("\nOptions:\n"
               "  -h --help     Show this help\n"
               "  -V --version  Show package version\n"
               "  -d --debug    Enable debug logging\n");
        print_man_page_link();
        return 0;
}

static int run_command(struct udev *udev, const struct udevadm_cmd *cmd, int argc, char *argv[]) {
        if (cmd->debug)
                log_set_max_level(LOG_DEBUG);
        log_debug("calling: %s", cmd->name);
        return cmd->cmd(udev, argc, argv);
}

int main(int argc, char *argv[]) {
        struct udev *udev = NULL;
        static const struct option options[] = {
                { "help", no_argument, NULL, 'h' },
                { "version", no_argument, NULL, 'V' },
                { "debug", no_argument, NULL, 'd' },
                {}
        };
        const char *command;
        unsigned int i;
        bool debug = false;
        int rc = 1, c, level;

        /* Like systemd's udevadm, the log settings of the environment and -d/--debug take precedence over
         * udev_log= of udev.conf. Unlike systemd, which reads udev.conf before log_setup(), so that the debug
         * messages of its parser never show, they are applied before udev_new() reads udev.conf, and then
         * the log level once more, see below. */
        log_parse_environment();
        log_open();
        mac_selinux_init("/dev");

        while ((c = udevadm_getopt_long(argc, argv, "+dhV", options)) >= 0)
                switch (c) {

                case 'd':
                        debug = true;
                        log_set_max_level(LOG_DEBUG);
                        break;

                case 'h':
                        rc = adm_help(udev, argc, argv);
                        goto out;

                case 'V':
                        rc = adm_version(udev, argc, argv);
                        goto out;

                default:
                        goto out;
                }

        level = log_get_max_level();
        udev = udev_new();
        if (udev == NULL)
                goto out;
        /* again, over udev_log= of udev.conf, which udev_new() applied */
        if (debug || log_max_level_from_environment())
                log_set_max_level(level);

        command = argv[optind];

        if (command != NULL)
                for (i = 0; i < ELEMENTSOF(udevadm_cmds); i++)
                        if (streq(udevadm_cmds[i]->name, command)) {
                                argc -= optind;
                                argv += optind;
                                /* we need '0' here to reset the internal state */
                                optind = 0;
                                rc = run_command(udev, udevadm_cmds[i], argc, argv);
                                /* also if the pager, which is closed at exit, was quit before all output
                                 * was written */
                                pager_set_exit_status(rc);
                                goto out;
                        }

        fprintf(stderr, "%s: missing or unknown command\n", program_invocation_short_name);
        rc = 2;
out:
        mac_selinux_finish();
        udev_unref(udev);
        log_close();
        return rc;
}
