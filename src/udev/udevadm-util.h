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

#include "json-writer.h"
#include "terminal-util.h"
#include "udev.h"

struct udev_device *find_device(struct udev *udev,
                                const char *id,
                                const char *prefix);

/* Like systemd's device_is_processed(): 1 if udevd processed the device, i.e. it has an entry in the
 * udev database without ID_PROCESSING=1, which udevd sets while it processes the device, e.g. while
 * RUN programs run, 0 if not, or a negative error. */
int device_is_processed(struct udev_device *dev);
int device_wait_for_initialization(struct udev_device *device, usec_t timeout_usec, struct udev_device **ret);

/* Like systemd's parse_path_argument() with suppress_root: makes the path absolute and
 * returns NULL for "/". */
int parse_root_argument(const char *s, char **ret);

/* Resolves path below root, like systemd's chase() with CHASE_PREFIX_ROOT: absolute symlinks
 * are resolved relative to root, and ".." does not leave it. The result starts with root.
 * Without root, this is realpath(3). */
int chase_below_root(const char *root, const char *path, char **ret);

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
