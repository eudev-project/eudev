#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <errno.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/types.h>

#include "macro.h"
#include "time-util.h"

#define ANSI_HIGHLIGHT_ON "\x1B[1;39m"
#define ANSI_RED_ON "\x1B[31m"
#define ANSI_HIGHLIGHT_RED_ON "\x1B[1;31m"
#define ANSI_GREEN_ON "\x1B[32m"
#define ANSI_HIGHLIGHT_GREEN_ON "\x1B[1;32m"
#define ANSI_HIGHLIGHT_YELLOW_ON "\x1B[1;33m"
#define ANSI_HIGHLIGHT_BLUE_ON "\x1B[1;34m"
#define ANSI_HIGHLIGHT_OFF "\x1B[0m"
#define ANSI_ERASE_TO_END_OF_LINE "\x1B[K"

int open_terminal(const char *name, int mode);

/* Like get_ctty_devnr() of systemd: the device number of the controlling terminal of the process (0 for the
 * calling process), -ENXIO if it has none, or another error if it cannot be read from /proc. */
int get_ctty_devnr(pid_t pid, dev_t *ret);

/* Like systemd's on_tty(): whether both standard output and standard error are terminals. The
 * result is cached. */
bool on_tty(void);
/* Like systemd's getenv_terminal_is_dumb() and terminal_is_dumb(): whether $TERM is unset or
 * "dumb", or, for the latter, also whether standard output or standard error is not a terminal. */
bool getenv_terminal_is_dumb(void);
bool terminal_is_dumb(void);

/* Limits the use of ANSI colors to a subset, like systemd's ColorMode. */
typedef enum ColorMode {
        COLOR_OFF,        /* No colors, monochrome output. */
        COLOR_16,         /* Only the base 16 colors. */
        COLOR_256,        /* Only 256 colors. */
        COLOR_24BIT,      /* For truecolor or 24bit color support, no restriction. */
        _COLOR_MODE_FIXED_MAX,

        /* The "AUTO" modes are as the above, but subject to suitable settings for the environment variables
         * TERM and NO_COLOR. */
        COLOR_AUTO_16 = _COLOR_MODE_FIXED_MAX,
        COLOR_AUTO_256,
        COLOR_AUTO_24BIT,

        /* Same as default (unset), except that $NO_COLOR is ignored/overridden */
        COLOR_TRUE,

        _COLOR_MODE_MAX,
        _COLOR_MODE_INVALID = -EINVAL,
} ColorMode;

/* Colors for the output on standard output, chosen like systemd's get_color_mode() does it: as
 * $SYSTEMD_COLORS says if it is set, otherwise none if $NO_COLOR is set, if standard output or
 * standard error is not a terminal, or if $TERM is unset or "dumb", and 24 bit colors if
 * $COLORTERM says so, 256 colors otherwise. The ansi_*() functions return the sequences of
 * systemd's ansi-color.h for the mode, or empty strings without colors. */
ColorMode parse_systemd_colors(void);
ColorMode get_color_mode(void);
bool colors_enabled(void);
const char *ansi_normal(void);
const char *ansi_highlight(void);
const char *ansi_highlight_red(void);
const char *ansi_highlight_green(void);
const char *ansi_highlight_yellow(void);
const char *ansi_highlight_yellow4(void);
const char *ansi_highlight_blue(void);
const char *ansi_highlight_magenta(void);
const char *ansi_highlight_cyan(void);
const char *ansi_grey(void);
const char *ansi_highlight_grey(void);
/* Like systemd's underline_enabled(), ansi_underline() and ansi_add_italics(): underlining and italics
 * only with colors, and not on the Linux console ($TERM is "linux"). */
bool underline_enabled(void);
const char *ansi_underline(void);
const char *ansi_add_italics(void);

/* Like systemd's get_log_colors(): the colors of a log message of the priority, see write_to_console() in
 * log.c: errors and more important ones in red, warnings in yellow, notices highlighted, debug messages in
 * grey, and informational ones in the normal color. */
void get_log_colors(int priority, const char **on, const char **off, const char **highlight);

/* Tree drawing glyphs, as systemd's glyph-util.h has them. UTF-8 box drawing characters are used
 * unless the locale's character set is not UTF-8, like systemd's is_locale_utf8() decides. */
typedef enum Glyph {
        GLYPH_TREE_VERTICAL,
        GLYPH_TREE_BRANCH,
        GLYPH_TREE_RIGHT,
        GLYPH_TREE_SPACE,
        GLYPH_VERTICAL_DOTTED,
        GLYPH_ELLIPSIS,
        _GLYPH_MAX,
} Glyph;

bool is_locale_utf8(void);
const char *glyph(Glyph code);

/* Clickable links for terminal emulators that support them (OSC 8), like systemd's
 * pretty-print.c: enabled by the boolean $SYSTEMD_URLIFY, and otherwise if colors are. The
 * functions return the text alone without links. */
bool urlify_enabled(void);
int terminal_urlify(const char *url, const char *text, char **ret);
int terminal_urlify_path(const char *path, const char *text, char **ret);
int terminal_urlify_man(const char *page, const char *section, char **ret);
