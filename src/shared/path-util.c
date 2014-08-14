/***
  This file is part of eudev, forked from systemd.

  Copyright 2010-2012 Lennart Poettering

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
#include <signal.h>
#include <stdio.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/statvfs.h>

#include "macro.h"
#include "util.h"
#include "log.h"
#include "strv.h"
#include "mkdir.h"
#include "path-util.h"
#include "missing.h"

bool path_is_absolute(const char *p) {
        return p[0] == '/';
}

bool is_path(const char *p) {
        return !!strchr(p, '/');
}

int path_get_parent(const char *path, char **_r) {
        const char *e, *a = NULL, *b = NULL, *p;
        char *r;
        bool slash = false;

        assert(path);
        assert(_r);

        if (!*path)
                return -EINVAL;

        for (e = path; *e; e++) {

                if (!slash && *e == '/') {
                        a = b;
                        b = e;
                        slash = true;
                } else if (slash && *e != '/')
                        slash = false;
        }

        if (*(e-1) == '/')
                p = a;
        else
                p = b;

        if (!p)
                return -EINVAL;

        if (p == path)
                r = strdup("/");
        else
                r = strndup(path, p-path);

        if (!r)
                return -ENOMEM;

        *_r = r;
        return 0;
}

char *path_make_absolute(const char *p, const char *prefix) {
        assert(p);

        /* Makes every item in the list an absolute path by prepending
         * the prefix, if specified and necessary */

        if (path_is_absolute(p) || !prefix)
                return strdup(p);

        return strjoin(prefix, "/", p, NULL);
}

char *path_make_absolute_cwd(const char *p) {
        _cleanup_free_ char *cwd = NULL;

        assert(p);

        /* Similar to path_make_absolute(), but prefixes with the
         * current working directory. */

        if (path_is_absolute(p))
                return strdup(p);

        cwd = get_current_dir_name();
        if (!cwd)
                return NULL;

        return path_make_absolute(p, cwd);
}

char **path_strv_resolve(char **l, const char *prefix) {
        char **s;
        unsigned k = 0;
        bool enomem = false;

        if (strv_isempty(l))
                return l;

        /* Goes through every item in the string list and canonicalize
         * the path. This works in place and won't rollback any
         * changes on failure. */

        STRV_FOREACH(s, l) {
                char *t, *u;
                _cleanup_free_ char *orig = NULL;

                if (!path_is_absolute(*s)) {
                        free(*s);
                        continue;
                }

                if (prefix) {
                        orig = *s;
                        t = strappend(prefix, orig);
                        if (!t) {
                                enomem = true;
                                continue;
                        }
                } else
                        t = *s;

                errno = 0;
                u = realpath(t, 0);
                if (!u) {
                        if (errno == ENOENT) {
                                if (prefix) {
                                        u = orig;
                                        orig = NULL;
                                        free(t);
                                } else
                                        u = t;
                        } else {
                                free(t);
                                if (errno == ENOMEM || errno == 0)
                                        enomem = true;

                                continue;
                        }
                } else if (prefix) {
                        char *x;

                        free(t);
                        x = path_startswith(u, prefix);
                        if (x) {
                                /* restore the slash if it was lost */
                                if (!startswith(x, "/"))
                                        *(--x) = '/';

                                t = strdup(x);
                                free(u);
                                if (!t) {
                                        enomem = true;
                                        continue;
                                }
                                u = t;
                        } else {
                                /* canonicalized path goes outside of
                                 * prefix, keep the original path instead */
                                u = orig;
                                orig = NULL;
                        }
                } else
                        free(t);

                l[k++] = u;
        }

        l[k] = NULL;

        if (enomem)
                return NULL;

        return l;
}

char **path_strv_resolve_uniq(char **l, const char *prefix) {

        if (strv_isempty(l))
                return l;

        if (!path_strv_resolve(l, prefix))
                return NULL;

        return strv_uniq(l);
}

char *path_kill_slashes(char *path) {
        char *f, *t;
        bool slash = false;

        /* Removes redundant inner and trailing slashes. Modifies the
         * passed string in-place.
         *
         * ///foo///bar/ becomes /foo/bar
         */

        for (f = path, t = path; *f; f++) {

                if (*f == '/') {
                        slash = true;
                        continue;
                }

                if (slash) {
                        slash = false;
                        *(t++) = '/';
                }

                *(t++) = *f;
        }

        /* Special rule, if we are talking of the root directory, a
        trailing slash is good */

        if (t == path && slash)
                *(t++) = '/';

        *t = 0;
        return path;
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

bool path_equal(const char *a, const char *b) {
        assert(a);
        assert(b);

        if ((a[0] == '/') != (b[0] == '/'))
                return false;

        for (;;) {
                size_t j, k;

                a += strspn(a, "/");
                b += strspn(b, "/");

                if (*a == 0 && *b == 0)
                        return true;

                if (*a == 0 || *b == 0)
                        return false;

                j = strcspn(a, "/");
                k = strcspn(b, "/");

                if (j != k)
                        return false;

                if (memcmp(a, b, j) != 0)
                        return false;

                a += j;
                b += k;
        }
}

int path_is_mount_point(const char *t, bool allow_symlink) {

        union file_handle_union h = {
                .handle.handle_bytes = MAX_HANDLE_SZ
        };

        int mount_id, mount_id_parent;
        _cleanup_free_ char *parent = NULL;
        struct stat a, b;
        int r;

        /* We are not actually interested in the file handles, but
         * name_to_handle_at() also passes us the mount ID, hence use
         * it but throw the handle away */

        if (path_equal(t, "/"))
                return 1;

        r = name_to_handle_at(AT_FDCWD, t, &h.handle, &mount_id, allow_symlink ? AT_SYMLINK_FOLLOW : 0);
        if (r < 0) {
                if (IN_SET(errno, ENOSYS, EOPNOTSUPP))
                        /* This kernel or file system does not support
                         * name_to_handle_at(), hence fallback to the
                         * traditional stat() logic */
                        goto fallback;

                if (errno == ENOENT)
                        return 0;

                return -errno;
        }

        r = path_get_parent(t, &parent);
        if (r < 0)
                return r;

        h.handle.handle_bytes = MAX_HANDLE_SZ;
        r = name_to_handle_at(AT_FDCWD, parent, &h.handle, &mount_id_parent, 0);
        if (r < 0) {
                /* The parent can't do name_to_handle_at() but the
                 * directory we are interested in can? If so, it must
                 * be a mount point */
                if (errno == EOPNOTSUPP)
                        return 1;

                return -errno;
        }

        return mount_id != mount_id_parent;

fallback:
        if (allow_symlink)
                r = stat(t, &a);
        else
                r = lstat(t, &a);

        if (r < 0) {
                if (errno == ENOENT)
                        return 0;

                return -errno;
        }

        r = path_get_parent(t, &parent);
        if (r < 0)
                return r;

        r = lstat(parent, &b);
        if (r < 0)
                return -errno;

        return a.st_dev != b.st_dev;
}

bool paths_check_timestamp(const char* const* paths, usec_t *timestamp, bool update) {
        bool changed = false;
        const char* const* i;

        assert(timestamp);

        if (paths == NULL)
                return false;

        STRV_FOREACH(i, paths) {
                struct stat stats;
                usec_t u;

                if (stat(*i, &stats) < 0)
                        continue;

                u = timespec_load(&stats.st_mtim);

                /* first check */
                if (*timestamp >= u)
                        continue;

                log_debug("timestamp of '%s' changed", *i);

                /* update timestamp */
                if (update) {
                        *timestamp = u;
                        changed = true;
                } else
                        return true;
        }

        return changed;
}
