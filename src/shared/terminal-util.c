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

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <assert.h>
#include <poll.h>
#include <linux/vt.h>
#include <linux/tiocl.h>
#include <linux/kd.h>
#include <langinfo.h>
#include <locale.h>

#include "terminal-util.h"
#include "time-util.h"
#include "process-util.h"
#include "util.h"
#include "fileio.h"
#include "path-util.h"

static volatile unsigned cached_columns = 0;
static volatile unsigned cached_lines = 0;

int open_terminal(const char *name, int mode) {
        int fd, r;
        unsigned c = 0;

        /*
         * If a TTY is in the process of being closed opening it might
         * cause EIO. This is horribly awful, but unlikely to be
         * changed in the kernel. Hence we work around this problem by
         * retrying a couple of times.
         *
         * https://bugs.launchpad.net/ubuntu/+source/linux/+bug/554172/comments/245
         */

        assert(!(mode & O_CREAT));

        for (;;) {
                fd = open(name, mode, 0);
                if (fd >= 0)
                        break;

                if (errno != EIO)
                        return -errno;

                /* Max 1s in total */
                if (c >= 20)
                        return -errno;

                usleep(50 * USEC_PER_MSEC);
                c++;
        }

        r = isatty(fd);
        if (r < 0) {
                safe_close(fd);
                return -errno;
        }

        if (!r) {
                safe_close(fd);
                return -ENOTTY;
        }

        return fd;
}

bool colors_enabled(void) {
        static int cached = -1;

        if (cached < 0)
                cached = isatty(STDOUT_FILENO) > 0 && !getenv("NO_COLOR") && !streq_ptr(getenv("TERM"), "dumb");
        return cached;
}

#define DEFINE_ANSI_FUNC(name, seq)                             \
        const char *ansi_##name(void) {                         \
                return colors_enabled() ? seq : "";             \
        }

/* The 256-color variants of systemd are replaced by their 16-color fallbacks. */
DEFINE_ANSI_FUNC(normal,            "\x1B[0m")
DEFINE_ANSI_FUNC(highlight,         "\x1B[0;1;39m")
DEFINE_ANSI_FUNC(highlight_red,     "\x1B[0;1;31m")
DEFINE_ANSI_FUNC(highlight_green,   "\x1B[0;1;32m")
DEFINE_ANSI_FUNC(highlight_yellow,  "\x1B[0;1;33m")
DEFINE_ANSI_FUNC(highlight_blue,    "\x1B[0;1;34m")
DEFINE_ANSI_FUNC(highlight_magenta, "\x1B[0;1;35m")
DEFINE_ANSI_FUNC(highlight_cyan,    "\x1B[0;1;36m")
DEFINE_ANSI_FUNC(grey,              "\x1B[0;90m")
DEFINE_ANSI_FUNC(highlight_grey,    "\x1B[0;1;90m")

static bool is_locale_utf8_impl(void) {
        const char *set;

        /* Note that we default to 'true' here, since today UTF8 is pretty much supported everywhere. */

        if (!setlocale(LC_ALL, ""))
                return true;

        set = nl_langinfo(CODESET);
        if (!set || streq(set, "UTF-8"))
                return true;

        set = setlocale(LC_CTYPE, NULL);
        if (!set)
                return true;

        /* Unless LC_CTYPE is explicitly overridden, return true. Because here CTYPE is effectively unset
         * and everything can do to UTF-8 nowadays. */
        return (streq(set, "C") || streq(set, "POSIX")) &&
                !getenv("LC_ALL") &&
                !getenv("LC_CTYPE") &&
                !getenv("LANG");
}

bool is_locale_utf8(void) {
        static int cached = -1;

        if (cached < 0)
                cached = is_locale_utf8_impl();

        return cached;
}

const char *glyph(Glyph code) {
        static const char* const draw_table[2][_GLYPH_MAX] = {
                /* ASCII fallback */
                [false] = {
                        [GLYPH_TREE_VERTICAL]   = "| ",
                        [GLYPH_TREE_BRANCH]     = "|-",
                        [GLYPH_TREE_RIGHT]      = "`-",
                        [GLYPH_TREE_SPACE]      = "  ",
                        [GLYPH_VERTICAL_DOTTED] = ":",
                        [GLYPH_ELLIPSIS]        = "...",
                },

                /* UTF-8 */
                [true] = {
                        [GLYPH_TREE_VERTICAL]   = "\u2502 ",        /* │ */
                        [GLYPH_TREE_BRANCH]     = "\u251c\u2500",   /* ├─ */
                        [GLYPH_TREE_RIGHT]      = "\u2514\u2500",   /* └─ */
                        [GLYPH_TREE_SPACE]      = "  ",
                        [GLYPH_VERTICAL_DOTTED] = "\u2506",         /* ┆ */
                        [GLYPH_ELLIPSIS]        = "\u2026",         /* … */
                },
        };

        assert(code >= 0 && code < _GLYPH_MAX);

        return draw_table[is_locale_utf8()][code];
}
