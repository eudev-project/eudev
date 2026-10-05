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

static int print_version(void) {
        printf("%s\n", UDEV_VERSION);
        return 0;
}

static int adm_version(struct udev *udev, int argc, char *argv[]);

static const struct udevadm_cmd udevadm_version = {
        .name = "version",
        .cmd = adm_version,
};

static int adm_version(struct udev *udev __attribute__((unused)), int argc, char *argv[] __attribute__((unused))) {
        /* Like systemd, the command takes no arguments, unlike -V/--version, which ignores the ones after it. */
        if (argc > 1) {
                log_error("Too many arguments.");
                return 1;
        }

        log_command_call(&udevadm_version);
        return print_version();
}

static int adm_help(struct udev *udev, int argc, char *argv[]);

static const struct udevadm_cmd udevadm_help = {
        .name = "help",
        .cmd = adm_help,
};

/* in the order of the verbs of systemd's udevadm, which its messages about a missing or unknown command
 * list, see find_closest_command() */
static const struct udevadm_cmd *udevadm_cmds[] = {
        &udevadm_help,
        &udevadm_info,
        &udevadm_trigger,
        &udevadm_settle,
        &udevadm_control,
        &udevadm_monitor,
        &udevadm_test,
        &udevadm_test_builtin,
        &udevadm_verify,
        &udevadm_cat,
        &udevadm_wait,
        &udevadm_lock,
        &udevadm_hwdb,
        &udevadm_version,
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

/* Like strlevenshtein() of systemd: the Damerau-Levenshtein distance of x and y, or -ENOMEM. */
static ssize_t strlevenshtein(const char *x, const char *y) {
        _cleanup_free_ size_t *t0 = NULL, *t1 = NULL, *t2 = NULL;
        size_t xl, yl, i, j, *dummy;

        if (streq(x, y))
                return 0;

        xl = strlen(x);
        yl = strlen(y);

        if (xl == 0)
                return yl;
        if (yl == 0)
                return xl;

        t0 = new0(size_t, yl + 1);
        t1 = new0(size_t, yl + 1);
        t2 = new0(size_t, yl + 1);
        if (!t0 || !t1 || !t2)
                return -ENOMEM;

        for (i = 0; i <= yl; i++)
                t1[i] = i;

        for (i = 0; i < xl; i++) {
                t2[0] = i + 1;

                for (j = 0; j < yl; j++) {
                        /* Substitution */
                        t2[j+1] = t1[j] + (x[i] != y[j]);

                        /* Swap */
                        if (i > 0 && j > 0 && x[i-1] == y[j] && x[i] == y[j-1] && t2[j+1] > t0[j-1] + 1)
                                t2[j+1] = t0[j-1] + 1;

                        /* Deletion */
                        if (t2[j+1] > t1[j+1] + 1)
                                t2[j+1] = t1[j+1] + 1;

                        /* Insertion */
                        if (t2[j+1] > t2[j] + 1)
                                t2[j+1] = t2[j] + 1;
                }

                dummy = t0;
                t0 = t1;
                t1 = t2;
                t2 = dummy;
        }

        return t1[yl];
}

/* Like strv_find_closest() of systemd for the names of the commands: the command whose name begins
 * with name, the shortest one if there are several, or else the one with the smallest Levenshtein
 * distance to name, if that is at most 5; the first one if there are several, or NULL. */
static const char *find_closest_command(const char *name) {
        const char *best = NULL;
        size_t best_length = SIZE_MAX, i;
        ssize_t best_distance = SSIZE_MAX;

        for (i = 0; i < ELEMENTSOF(udevadm_cmds); i++) {
                const char *e = startswith(udevadm_cmds[i]->name, name);

                if (e && strlen(e) < best_length) {
                        best_length = strlen(e);
                        best = udevadm_cmds[i]->name;
                }
        }
        if (best)
                return best;

        for (i = 0; i < ELEMENTSOF(udevadm_cmds); i++) {
                ssize_t distance = strlevenshtein(udevadm_cmds[i]->name, name);

                if (distance < 0) {
                        log_debug_errno(distance, "Failed to determine Levenshtein distance between %s and %s: %m",
                                        udevadm_cmds[i]->name, name);
                        return NULL;
                }

                /* If the distance is just too far off, don't make a bad suggestion */
                if (distance > 5)
                        continue;

                if (distance < best_distance) {
                        best_distance = distance;
                        best = udevadm_cmds[i]->name;
                }
        }

        return best;
}

/* Like _dispatch_verb() of systemd: "Command verb required (one of help, info, …)." */
static void log_command_required(void) {
        _cleanup_free_ char *list = NULL;
        size_t n = 0, i;
        char *p;

        for (i = 0; i < ELEMENTSOF(udevadm_cmds); i++)
                n += strlen(", ") + strlen(udevadm_cmds[i]->name);

        list = new(char, n + 1);
        if (!list) {
                log_oom();
                return;
        }

        p = list;
        for (i = 0; i < ELEMENTSOF(udevadm_cmds); i++)
                p = stpcpy(stpcpy(p, i == 0 ? "" : ", "), udevadm_cmds[i]->name);
        *p = '\0';

        log_error("Command verb required (one of %s).", list);
}

static int run_command(struct udev *udev, const struct udevadm_cmd *cmd, int argc, char *argv[]) {
        if (cmd->debug)
                log_set_max_level(LOG_DEBUG);
        /* The other commands log this after they checked their arguments, see log_command_call(). */
        if (cmd == &udevadm_help)
                log_command_call(cmd);
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
        const char *command, *closest;
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

        while ((c = getopt_long_log(argc, argv, "+dhV", options)) >= 0)
                switch (c) {

                case 'd':
                        debug = true;
                        log_set_max_level(LOG_DEBUG);
                        break;

                case 'h':
                        rc = adm_help(udev, argc, argv);
                        goto out;

                case 'V':
                        rc = print_version();
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
        if (command == NULL) {
                log_command_required();
                goto out;
        }

        for (i = 0; i < ELEMENTSOF(udevadm_cmds); i++)
                if (streq(udevadm_cmds[i]->name, command)) {
                        argc -= optind;
                        argv += optind;
                        /* we need '0' here to reset the internal state */
                        optind = 0;
                        rc = run_command(udev, udevadm_cmds[i], argc, argv);
                        /* also if the pager, which is closed at exit, was quit before all output was
                         * written */
                        pager_set_exit_status(rc);
                        goto out;
                }

        /* like systemd, with a hint what may have been meant */
        closest = find_closest_command(command);
        if (closest)
                log_error("Unknown command verb '%s', did you mean '%s'?", command, closest);
        else
                log_error("Unknown command verb '%s'.", command);
out:
        mac_selinux_finish();
        udev_unref(udev);
        log_close();
        return rc;
}
