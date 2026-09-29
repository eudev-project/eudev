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

#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>

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
        GLYPH_ELLIPSIS,
        _GLYPH_MAX,
} Glyph;

bool is_locale_utf8(void);
const char *glyph(Glyph code);
