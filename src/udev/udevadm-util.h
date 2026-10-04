/*
 * Copyright (C) 2014 Zbigniew Jędrzejewski-Szmek <zbyszek@in.waw.pl>
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

#pragma once

#include <getopt.h>

#include "json-writer.h"
#include "terminal-util.h"
#include "udev.h"

/* Like systemd's find_device(): the device of a device ID like "b8:0", "c1:3", "n1" or "+net:lo",
 * of a path in /dev or /sys, see device_new_from_path(), or of that path below prefix. Sets errno
 * on failure, EINVAL if id is not a path. */
struct udev_device *find_device(struct udev *udev,
                                const char *id,
                                const char *prefix);

/* Like systemd's find_device_with_action(): the device of find_device() below /sys, with the
 * properties of its uevent file and the action set. Sets errno on failure. */
struct udev_device *find_device_with_action(struct udev *udev, const char *id, const char *action);

/* Like systemd's device_is_processed(): 1 if udevd processed the device, i.e. it has an entry in the
 * udev database without ID_PROCESSING=1, which udevd sets while it processes the device, e.g. while
 * RUN programs run, 0 if not, or a negative error. */
int device_is_processed(struct udev_device *dev);
int device_wait_for_initialization(struct udev_device *device, usec_t timeout_usec, struct udev_device **ret);

/* Like systemd's parse_path_argument() with suppress_root: makes the path absolute and simplifies
 * it, and returns NULL for an empty path or "/". */
int parse_root_argument(const char *s, char **ret);

/* Like systemd's search_rules_files(): without arguments, all rules files in the rules
 * directories below root, a file overriding the ones with the same name in later directories,
 * except masked files, i.e. empty ones or symlinks to /dev/null. Otherwise, each argument is
 * the name of a rules file that is searched in the rules directories, or the path of a rules
 * file or of a directory of rules files, below root. Returns the paths as found in ret_names,
 * and the ones with symlinks resolved in ret_paths. */
int search_rules_files(char * const *args, const char *root, char ***ret_names, char ***ret_paths);

/* Parses the argument of --json= with json_parse_format(), and logs an unknown argument, like
 * systemd's parse_json_argument(). Returns 1 if the argument was parsed, 0 if a list of the
 * arguments was shown for "help", and a negative error for an unknown argument. */
int parse_json_argument(const char *s, JsonFormatFlags *ret);

/* Like systemd's device_action_from_string(): the index of the kernel uevent action, or -EINVAL. */
int device_action_from_string(const char *s);

/* Like systemd's parse_device_action(): returns 1 and the action if str is one, 0 after listing the
 * actions for "help", and -EINVAL after logging "Invalid action 'str'." otherwise. */
int parse_device_action(const char *str, const char **ret);

/* Like systemd's parse_resolve_name_timing(): returns 1 and the value of --resolve-names= as
 * udev_rules_new() takes it, see udev_parse_resolve_names(), 0 after listing the values for "help",
 * and -EINVAL after logging an error otherwise. */
int parse_resolve_name_timing(const char *str, int *ret);

/* The last line of the help texts, like systemd's: "See the udevadm(8) man page for details.",
 * with a link to the man page if links are enabled. */
void print_man_page_link(void);

/* getopt_long() with the messages of systemd's option parser instead of the ones of the C library,
 * e.g. "udevadm: unrecognized option '-Z'", "udevadm: option '--name' requires an argument" or
 * "udevadm: option '--exp' is ambiguous; possibilities: --export, --export-prefix, --export-db".
 * Like that parser, an abbreviated long option is ambiguous whenever the names of several long
 * options begin with it, also if they are aliases. Returns '?' after logging an invalid option. */
int udevadm_getopt_long(int argc, char *argv[], const char *optstring, const struct option *longopts);

/* Logs at debug level which command runs, e.g. "calling: test". The commands call it after they checked
 * their arguments, so that it does not come before a message about an invalid one. */
void log_command_call(const struct udevadm_cmd *cmd);
