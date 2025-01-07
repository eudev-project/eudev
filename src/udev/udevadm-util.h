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
#include "udev.h"

struct udev_device *find_device(struct udev *udev,
                                const char *id,
                                const char *prefix);

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

/* Colors for the output on standard output, as systemd's ansi-color.h uses them. They
 * are empty strings unless standard output is a terminal, $NO_COLOR is not set and
 * $TERM is not "dumb". */
bool colors_enabled(void);
const char *ansi_normal(void);
const char *ansi_highlight(void);
const char *ansi_highlight_red(void);
const char *ansi_highlight_green(void);
const char *ansi_highlight_yellow(void);
const char *ansi_highlight_blue(void);
const char *ansi_highlight_magenta(void);
const char *ansi_highlight_cyan(void);
const char *ansi_grey(void);
const char *ansi_highlight_grey(void);

/* Tree drawing glyphs, as systemd's glyph-util.h has them. UTF-8 box drawing characters are used
 * unless the locale's character set is not UTF-8, like systemd's is_locale_utf8() decides. */
typedef enum Glyph {
        GLYPH_TREE_VERTICAL,
        GLYPH_TREE_BRANCH,
        GLYPH_TREE_RIGHT,
        GLYPH_TREE_SPACE,
        GLYPH_VERTICAL_DOTTED,
        _GLYPH_MAX,
} Glyph;

bool is_locale_utf8(void);
const char *glyph(Glyph code);

/* Parses the argument of --json= with json_parse_format(), and logs an unknown argument, like
 * systemd's parse_json_argument(). Returns 1 if the argument was parsed, 0 if a list of the
 * arguments was shown for "help", and a negative error for an unknown argument. */
int parse_json_argument(const char *s, JsonFormatFlags *ret);
