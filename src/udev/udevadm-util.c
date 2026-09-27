/*
 * Copyright (C) 2008-2009 Kay Sievers <kay@vrfy.org>
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

#include "udevadm-util.h"

struct udev_device *find_device(struct udev *udev,
                                const char *id,
                                const char *prefix) {

        assert(udev);
        assert(id);

        if (prefix && !startswith(id, prefix))
                id = strjoina(prefix, id);

        if (startswith(id, "/dev/")) {
                struct stat statbuf;
                char type;

                if (stat(id, &statbuf) < 0)
                        return NULL;

                if (S_ISBLK(statbuf.st_mode))
                        type = 'b';
                else if (S_ISCHR(statbuf.st_mode))
                        type = 'c';
                else
                        return NULL;

                return udev_device_new_from_devnum(udev, type, statbuf.st_rdev);
        } else if (startswith(id, "/sys/"))
                return udev_device_new_from_syspath(udev, id);
        else
                return NULL;
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
