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

#include "udev.h"

struct udev_device *find_device(struct udev *udev,
                                const char *id,
                                const char *prefix);

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
