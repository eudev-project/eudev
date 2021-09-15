/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <getopt.h>

#include "log.h"
#include "util.h"
#include "fileio.h"
#include "path-util.h"
#include "sysctl-util.h"

char *sysctl_normalize(char *s) {
        char *n;

        n = strpbrk(s, "/.");

        /* If the first separator is a slash, the path is
         * assumed to be normalized and slashes remain slashes
         * and dots remains dots. */

        if (n && *n == '.')
                /* Dots become slashes and slashes become dots. Fun. */
                do {
                        if (*n == '.')
                                *n = '/';
                        else
                                *n = '.';

                        n = strpbrk(n + 1, "/.");
                } while (n);

        path_simplify(s);

        /* Kill the leading slash, but keep the first character of the string in the same place. */
        if (*s == '/' && *(s+1))
                memmove(s, s+1, strlen(s));

        return s;
}

int sysctl_write(const char *property, const char *value) {
        char *p;

        assert(property);
        assert(value);

        p = strjoina("/proc/sys/", property);

        path_simplify(p);
        if (!path_is_normalized(p))
                return -EINVAL;

        log_debug("Setting '%s' to '%s'", p, value);

        return write_string_file(p, value);
}

/* Like sysctl_read() of systemd, which reads the entry with read_full_virtual_file(). Unlike there, the file is
 * opened with O_NONBLOCK by read_virtual_file(), so that a property that names something else than a regular
 * file fails with EBADF instead of blocking. */
int sysctl_read(const char *property, char **content) {
        char *p;
        int r;

        assert(property);

        p = strjoina("/proc/sys/", property);

        path_simplify(p);
        if (!path_is_normalized(p)) /* Filter out attempts to write to /proc/sys/../../…, just in case */
                return -EINVAL;

        r = read_virtual_file(p, SIZE_MAX, content, NULL);
        if (r < 0)
                return r;
        if (content)
                delete_trailing_chars(*content, NEWLINE);

        return 0;
}
