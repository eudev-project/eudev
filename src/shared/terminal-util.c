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
#include <sys/sysmacros.h>
#include <sys/stat.h>
#include <sys/utsname.h>
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
#include "log.h"
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

static int cached_on_tty = -1;
static int cached_on_dev_null = -1;

bool on_tty(void) {

        /* Like systemd, check both standard output and standard error, so that the output is not
         * colored if either one is piped somewhere. The result is cached, so that it is kept when
         * a pager is opened, see pager_open(). */

        if (cached_on_tty < 0)
                cached_on_tty = isatty(STDOUT_FILENO) > 0 && isatty(STDERR_FILENO) > 0;

        return cached_on_tty;
}

static bool on_dev_null(void) {
        struct stat dst, ost, est;

        if (cached_on_dev_null >= 0)
                return cached_on_dev_null;

        if (stat("/dev/null", &dst) < 0 || fstat(STDOUT_FILENO, &ost) < 0 || fstat(STDERR_FILENO, &est) < 0)
                cached_on_dev_null = false;
        else
                cached_on_dev_null = dst.st_dev == ost.st_dev && dst.st_ino == ost.st_ino &&
                                     dst.st_dev == est.st_dev && dst.st_ino == est.st_ino;

        return cached_on_dev_null;
}

bool getenv_terminal_is_dumb(void) {
        const char *e;

        e = getenv("TERM");
        if (!e)
                return true;

        return streq(e, "dumb");
}

bool terminal_is_dumb(void) {
        if (!on_tty() && !on_dev_null())
                return true;

        return getenv_terminal_is_dumb();
}

static const char* const color_mode_table[_COLOR_MODE_MAX] = {
        [COLOR_OFF]        = "off",
        [COLOR_16]         = "16",
        [COLOR_256]        = "256",
        [COLOR_24BIT]      = "24bit",
        [COLOR_AUTO_16]    = "auto-16",
        [COLOR_AUTO_256]   = "auto-256",
        [COLOR_AUTO_24BIT] = "auto-24bit",
        [COLOR_TRUE]       = "true",
};

/* Like systemd's color_mode_from_string(), which also takes a boolean, true for COLOR_TRUE. */
static ColorMode color_mode_from_string(const char *s) {
        int m, r;

        for (m = 0; m < _COLOR_MODE_MAX; m++)
                if (streq(color_mode_table[m], s))
                        return m;

        r = parse_boolean(s);
        if (r < 0)
                return _COLOR_MODE_INVALID;

        return r ? COLOR_TRUE : COLOR_OFF;
}

ColorMode parse_systemd_colors(void) {
        const char *e;

        /* Note: do not log in this function, to avoid infinite recursion issues, as the log functions call
         * this when deciding whether to color the output. */

        e = getenv("SYSTEMD_COLORS");
        if (!e)
                return _COLOR_MODE_INVALID;

        return color_mode_from_string(e);
}

static ColorMode get_color_mode_impl(void) {
        const char *e;
        ColorMode m;

        /* Returns the mode used to choose output colors. The possible modes are COLOR_OFF for no colors,
         * COLOR_16 for only the base 16 ANSI colors, COLOR_256 for more colors, and COLOR_24BIT for
         * unrestricted color output. */

        /* First, we check $SYSTEMD_COLORS, which is the explicit way to change the mode. */
        m = parse_systemd_colors();
        if (m >= 0 && m < _COLOR_MODE_FIXED_MAX)
                return m;

        /* If SYSTEMD_COLORS=true was set explicitly, skip the environment checks below — the user
         * explicitly requested colors, so honor it even when stdout is piped or $NO_COLOR is set. */
        if (m != COLOR_TRUE) {
                /* Check for the presence of $NO_COLOR; value is ignored. */
                if (getenv("NO_COLOR"))
                        return COLOR_OFF;

                /* Turn colors off unless we are on a TTY. And if we are on a TTY we turn it off if $TERM
                 * is set to "dumb". There's one special tweak though: if we are PID 1 then we do not check
                 * whether we are connected to a TTY, because we don't keep /dev/console open continuously
                 * due to fear of SAK, and hence things are a bit weird. */
                if (getpid() == 1 ? getenv_terminal_is_dumb() : terminal_is_dumb())
                        return COLOR_OFF;
        }

        /* We failed to figure out any reason to *disable* colors. Let's see how many colors we shall use. */
        if (m == COLOR_AUTO_16)
                return COLOR_16;
        if (m == COLOR_AUTO_256)
                return COLOR_256;
        if (m == COLOR_AUTO_24BIT)
                return COLOR_24BIT;

        e = getenv("COLORTERM");
        if (streq_ptr(e, "truecolor") || streq_ptr(e, "24bit"))
                return COLOR_24BIT;

        /* Note that the Linux console can only display 16 colors. We still enable 256 color mode
         * even for PID1 output though (which typically goes to the Linux console), since the Linux
         * console is able to parse the 256 color sequences and automatically map them to the closest
         * color in the 16 color palette (since kernel 3.16). Doing 256 colors is nice for people who
         * invoke systemd in a container or via a serial link or such, and use a true 256 color
         * terminal to do so. */
        return COLOR_256;
}

ColorMode get_color_mode(void) {
        static int cached_color_mode = _COLOR_MODE_INVALID;

        if (cached_color_mode < 0) {
                cached_color_mode = get_color_mode_impl();
                assert(cached_color_mode >= 0 && cached_color_mode < _COLOR_MODE_FIXED_MAX);
        }

        return cached_color_mode;
}

bool colors_enabled(void) {
        return get_color_mode() != COLOR_OFF;
}

#define DEFINE_ANSI_FUNC(name, seq)                             \
        const char *ansi_##name(void) {                         \
                return colors_enabled() ? seq : "";             \
        }

/* Like systemd's DEFINE_ANSI_FUNC_256(): in 256 color mode the 16 color fallback is emitted
 * first, for terminals with incomplete 256 color support, like the Linux console. */
#define DEFINE_ANSI_FUNC_256(name, seq, fallback)               \
        const char *ansi_##name(void) {                         \
                switch (get_color_mode()) {                     \
                case COLOR_OFF: return "";                      \
                case COLOR_16: return fallback;                 \
                case COLOR_256: return fallback seq;            \
                default: return seq;                            \
                }                                               \
        }

DEFINE_ANSI_FUNC(normal,                "\x1B[0m")
DEFINE_ANSI_FUNC(highlight,             "\x1B[0;1;39m")
DEFINE_ANSI_FUNC(highlight_red,         "\x1B[0;1;31m")
DEFINE_ANSI_FUNC(highlight_green,       "\x1B[0;1;32m")
DEFINE_ANSI_FUNC_256(highlight_yellow,  "\x1B[0;1;38:5:185m", "\x1B[0;1;33m")
DEFINE_ANSI_FUNC_256(highlight_yellow4, "\x1B[0;1;38:5:100m", "\x1B[0;1;33m")
DEFINE_ANSI_FUNC(highlight_blue,        "\x1B[0;1;34m")
DEFINE_ANSI_FUNC(highlight_magenta,     "\x1B[0;1;35m")
DEFINE_ANSI_FUNC(highlight_cyan,        "\x1B[0;1;36m")
DEFINE_ANSI_FUNC_256(grey,              "\x1B[0;38:5:245m", "\x1B[0;90m")
DEFINE_ANSI_FUNC_256(highlight_grey,    "\x1B[0;1;38:5:245m", "\x1B[0;1;90m")

bool underline_enabled(void) {
        static int cached_underline_enabled = -1;

        /* The Linux console doesn't support underlining, turn it off, but only there. */
        if (cached_underline_enabled < 0)
                cached_underline_enabled = colors_enabled() && !streq_ptr(getenv("TERM"), "linux");

        return cached_underline_enabled;
}

const char *ansi_underline(void) {
        return underline_enabled() ? "\x1B[0;4m" : "";
}

/* italics is hooked into the underline checks too, like systemd does it */
const char *ansi_add_italics(void) {
        return underline_enabled() ? "\x1B[3m" : "";
}

int get_ctty_devnr(pid_t pid, dev_t *ret) {
        _cleanup_free_ char *line = NULL;
        unsigned long ttynr;
        const char *p;
        int r;

        assert(pid >= 0);

        p = procfs_file_alloca(pid, "stat");
        r = read_one_line_file(p, &line);
        if (r < 0)
                return r;

        p = strrchr(line, ')');
        if (!p)
                return -EIO;

        p++;

        if (sscanf(p, " "
                   "%*c "  /* state */
                   "%*d "  /* ppid */
                   "%*d "  /* pgrp */
                   "%*d "  /* session */
                   "%lu ", /* ttynr */
                   &ttynr) != 1)
                return -EIO;

        if (major((dev_t) ttynr) == 0 && minor((dev_t) ttynr) == 0)
                return -ENXIO;

        if (ret)
                *ret = (dev_t) ttynr;

        return 0;
}

void get_log_colors(int priority, const char **on, const char **off, const char **highlight) {
        /* Note that this will initialize output variables only when there's something to output.
         * The caller must pre-initialize to "" or NULL as appropriate. */

        if (priority <= LOG_ERR) {
                if (on)
                        *on = ansi_highlight_red();
                if (off)
                        *off = ansi_normal();
                if (highlight)
                        *highlight = ansi_highlight();

        } else if (priority <= LOG_WARNING) {
                if (on)
                        *on = ansi_highlight_yellow();
                if (off)
                        *off = ansi_normal();
                if (highlight)
                        *highlight = ansi_highlight();

        } else if (priority <= LOG_NOTICE) {
                if (on)
                        *on = ansi_highlight();
                if (off)
                        *off = ansi_normal();
                if (highlight)
                        *highlight = ansi_highlight_red();

        } else if (priority >= LOG_DEBUG) {
                if (on)
                        *on = ansi_grey();
                if (off)
                        *off = ansi_normal();
                if (highlight)
                        *highlight = ansi_highlight_red();
        }
}

static bool is_locale_utf8_impl(void) {
        const char *set;
        int r;

        /* Note that we default to 'true' here, since today UTF8 is pretty much supported everywhere. */

        r = secure_getenv_bool("SYSTEMD_UTF8");
        if (r >= 0)
                return r;
        if (r != -ENXIO)
                log_debug_errno(r, "Failed to parse $SYSTEMD_UTF8, ignoring: %m");

        /* This function may be called from a library, and setlocale() is not thread safe. Assuming yes. */
        if (!is_main_thread())
                return true;

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

/* The "operating system command" ("OSC") start sequence, and the "string terminator", as systemd
 * uses them. */
#define ANSI_OSC "\x1B]"
#define ANSI_ST "\x1B\\"

bool urlify_enabled(void) {
        static int cached_urlify_enabled = -1;

        if (cached_urlify_enabled < 0) {
                const char *e;
                int val = -ENXIO;

                e = getenv("SYSTEMD_URLIFY");
                if (e)
                        val = parse_boolean(e);
                if (val >= 0)
                        cached_urlify_enabled = val;
                else
                        cached_urlify_enabled = colors_enabled();
        }

        return cached_urlify_enabled;
}

static bool url_suitable_for_osc8(const char *url) {
        const char *c;

        assert(url);

        /* Not all URLs are safe for inclusion in OSC 8 due to charset and length restrictions. Let's detect
         * which ones those are */

        /* If the URL is longer than 2K let's not try to do OSC 8. As per recommendation in
         * https://gist.github.com/egmontkob/eb114294efbcd5adb1944c9f3cb5feda#length-limits */
        if (strlen(url) > 2000)
                return false;

        /* OSC sequences may only contain chars from the 32..126 range, as per ECMA-48 */
        for (c = url; *c; c++)
                if ((unsigned char) *c < 32 || (unsigned char) *c >= 127)
                        return false;

        return true;
}

int terminal_urlify(const char *url, const char *text, char **ret) {
        char *n;

        assert(url);
        assert(ret);

        /* Takes a URL and a pretty string and formats it as clickable link for the terminal. See
         * https://gist.github.com/egmontkob/eb114294efbcd5adb1944c9f3cb5feda for details. */

        if (isempty(text))
                text = url;

        if (urlify_enabled() && url_suitable_for_osc8(url))
                n = strjoin(ANSI_OSC "8;;", url, ANSI_ST,
                            text,
                            ANSI_OSC "8;;" ANSI_ST, NULL);
        else
                n = strdup(text);
        if (!n)
                return -ENOMEM;

        *ret = n;
        return 0;
}

static int file_url_from_path(const char *path, char **ret) {
        _cleanup_free_ char *absolute = NULL;
        struct utsname u;
        char *url;

        assert(path);
        assert(ret);

        if (uname(&u) < 0)
                return -errno;

        if (!path_is_absolute(path)) {
                absolute = path_make_absolute_cwd(path);
                if (!absolute)
                        return -ENOMEM;

                path = absolute;
        }

        /* As suggested by https://gist.github.com/egmontkob/eb114294efbcd5adb1944c9f3cb5feda, let's include the local
         * hostname here. Note that we don't use gethostname_malloc() or gethostname_strict() since we are interested
         * in the raw string the kernel has set, whatever it may be, under the assumption that terminals are not overly
         * careful with validating the strings either. */

        url = strjoin("file://", u.nodename, path, NULL);
        if (!url)
                return -ENOMEM;

        *ret = url;
        return 0;
}

int terminal_urlify_path(const char *path, const char *text, char **ret) {
        _cleanup_free_ char *url = NULL;
        char *n;
        int r;

        assert(path);
        assert(ret);

        /* Much like terminal_urlify() above, but takes a file system path as input
         * and turns it into a proper file:// URL first. */

        if (isempty(path))
                return -EINVAL;

        if (isempty(text))
                text = path;

        if (!urlify_enabled()) {
                n = strdup(text);
                if (!n)
                        return -ENOMEM;

                *ret = n;
                return 0;
        }

        r = file_url_from_path(path, &url);
        if (r < 0)
                return r;

        return terminal_urlify(url, text, ret);
}

int terminal_urlify_man(const char *page, const char *section, char **ret) {
        _cleanup_free_ char *url = NULL, *text = NULL;

        assert(page);
        assert(section);
        assert(ret);

        url = strjoin("man:", page, "(", section, ")", NULL);
        text = strjoin(page, "(", section, ")", NULL);
        if (!url || !text)
                return -ENOMEM;

        return terminal_urlify(url, text, ret);
}
