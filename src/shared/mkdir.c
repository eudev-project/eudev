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

#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

#include "label.h"
#include "util.h"
#include "mkdir.h"

static int is_dir(const char* path) {
        struct stat st;

        if (stat(path, &st) < 0)
                return -errno;

        return S_ISDIR(st.st_mode);
}


char* path_startswith(const char *path, const char *prefix) {
        assert(path);
        assert(prefix);

        if ((path[0] == '/') != (prefix[0] == '/'))
                return NULL;

        for (;;) {
                size_t a, b;

                path += strspn(path, "/");
                prefix += strspn(prefix, "/");

                if (*prefix == 0)
                        return (char*) path;

                if (*path == 0)
                        return NULL;

                a = strcspn(path, "/");
                b = strcspn(prefix, "/");

                if (a != b)
                        return NULL;

                if (memcmp(path, prefix, a) != 0)
                        return NULL;

                path += a;
                prefix += b;
        }
}

static int mkdir_parents_internal(const char *prefix, const char *path, mode_t mode, bool apply) {
        const char *p, *e;
        int r;

        assert(path);

        if (prefix && !path_startswith(path, prefix))
                return -ENOTDIR;

        /* return immediately if directory exists */
        e = strrchr(path, '/');
        if (!e)
                return -EINVAL;

        if (e == path)
                return 0;

	char buf[PATH_MAX + 1];
	p = buf;
	assert(e-path < sizeof(buf));
	memcpy(buf, path, e-path);
	buf[e-path] = 0;

        r = is_dir(p);
        if (r > 0)
                return 0;
        if (r == 0)
                return -ENOTDIR;

        /* create every parent directory in the path, except the last component */
        p = path + strspn(path, "/");
        for (;;) {
                char t[strlen(path) + 1];

                e = p + strcspn(p, "/");
                p = e + strspn(e, "/");

                /* Is this the last component? If so, then we're
                 * done */
                if (*p == 0)
                        return 0;

                memcpy(t, path, e - path);
                t[e-path] = 0;

                if (prefix && path_startswith(prefix, t))
                        continue;

                r = label_mkdir(t, mode, apply);
                if (r < 0 && errno != EEXIST)
                        return -errno;
        }
}

int mkdir_parents(const char *path, mode_t mode) {
        return mkdir_parents_internal(NULL, path, mode, false);
}

int mkdir_parents_label(const char *path, mode_t mode) {
        return mkdir_parents_internal(NULL, path, mode, true);
}

static int mkdir_p_internal(const char *prefix, const char *path, mode_t mode, bool apply) {
        int r;

        /* Like mkdir -p */

        r = mkdir_parents_internal(prefix, path, mode, apply);
        if (r < 0)
                return r;

        r = label_mkdir(path, mode, apply);
        if (r < 0 && (errno != EEXIST || is_dir(path) <= 0))
                return -errno;

        return 0;
}

int mkdir_p(const char *path, mode_t mode) {
        return mkdir_p_internal(NULL, path, mode, false);
}
