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
#include <sys/stat.h>
#include <sys/statvfs.h>

#include "macro.h"
#include "util.h"
#include "log.h"
#include "strv.h"
#include "mkdir.h"
#include "path-util.h"
#include "missing.h"
#include "fileio.h"

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

        return strjoin(cwd, "/", p, NULL);
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
                                free(u);
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

int path_compare(const char *a, const char *b) {
        int d;

        assert(a);
        assert(b);

        /* A relative path and an absolute path must not compare as equal.
         * Which one is sorted before the other does not really matter.
         * Here a relative path is ordered before an absolute path. */
        d = (a[0] == '/') - (b[0] == '/');
        if (d)
                return d;

        for (;;) {
                size_t j, k;

                a += strspn(a, "/");
                b += strspn(b, "/");

                if (*a == 0 && *b == 0)
                        return 0;

                /* Order prefixes first: "/foo" before "/foo/bar" */
                if (*a == 0)
                        return -1;
                if (*b == 0)
                        return 1;

                j = strcspn(a, "/");
                k = strcspn(b, "/");

                /* Alphabetical sort: "/foo/aaa" before "/foo/b" */
                d = memcmp(a, b, MIN(j, k));
                if (d)
                        return (d > 0) - (d < 0); /* sign of d */

                /* Sort "/foo/a" before "/foo/aaa" */
                d = (j > k) - (j < k);  /* sign of (j - k) */
                if (d)
                        return d;

                a += j;
                b += k;
        }
}

bool path_equal(const char *a, const char *b) {
        return path_compare(a, b) == 0;
}

static int fd_fdinfo_mnt_id(int fd, const char *filename, int flags, int *mnt_id) {
        char path[strlen("/proc/self/fdinfo/") + DECIMAL_STR_MAX(int)];
        _cleanup_free_ char *fdinfo = NULL;
        _cleanup_close_ int subfd = -1;
        char *p;
        int r;

        if ((flags & AT_EMPTY_PATH) && isempty(filename))
                xsprintf(path, "/proc/self/fdinfo/%i", fd);
        else {
                subfd = openat(fd, filename, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_PATH);
                if (subfd < 0)
                        return -errno;

                xsprintf(path, "/proc/self/fdinfo/%i", subfd);
        }

        r = read_full_file(path, &fdinfo, NULL);
        if (r == -ENOENT) /* The fdinfo directory is a relatively new addition */
                return -EOPNOTSUPP;
        if (r < 0)
                return -errno;

        p = startswith(fdinfo, "mnt_id:");
        if (!p) {
                p = strstr(fdinfo, "\nmnt_id:");
                if (!p) /* The mnt_id field is a relatively new addition */
                        return -EOPNOTSUPP;

                p += 8;
        }

        p += strspn(p, WHITESPACE);
        p[strcspn(p, WHITESPACE)] = 0;

        return safe_atoi(p, mnt_id);
}

int fd_is_mount_point(int fd) {
        union file_handle_union h = FILE_HANDLE_INIT, h_parent = FILE_HANDLE_INIT;
        int mount_id = -1, mount_id_parent = -1;
        bool nosupp = false, check_st_dev = true;
        struct stat a, b;
        int r;

        assert(fd >= 0);

        /* First we will try the name_to_handle_at() syscall, which
         * tells us the mount id and an opaque file "handle". It is
         * not supported everywhere though (kernel compile-time
         * option, not all file systems are hooked up). If it works
         * the mount id is usually good enough to tell us whether
         * something is a mount point.
         *
         * If that didn't work we will try to read the mount id from
         * /proc/self/fdinfo/<fd>. This is almost as good as
         * name_to_handle_at(), however, does not return the the
         * opaque file handle. The opaque file handle is pretty useful
         * to detect the root directory, which we should always
         * consider a mount point. Hence we use this only as
         * fallback. Exporting the mnt_id in fdinfo is a pretty recent
         * kernel addition.
         *
         * As last fallback we do traditional fstat() based st_dev
         * comparisons. This is how things were traditionally done,
         * but unionfs breaks breaks this since it exposes file
         * systems with a variety of st_dev reported. Also, btrfs
         * subvolumes have different st_dev, even though they aren't
         * real mounts of their own. */

        r = name_to_handle_at(fd, "", &h.handle, &mount_id, AT_EMPTY_PATH);
        if (r < 0) {
                if (errno == ENOSYS)
                        /* This kernel does not support name_to_handle_at()
                         * fall back to simpler logic. */
                        goto fallback_fdinfo;
                else if (errno == EOPNOTSUPP)
                        /* This kernel or file system does not support
                         * name_to_handle_at(), hence let's see if the
                         * upper fs supports it (in which case it is a
                         * mount point), otherwise fallback to the
                         * traditional stat() logic */
                        nosupp = true;
                else
                        return -errno;
        }

        r = name_to_handle_at(fd, "..", &h_parent.handle, &mount_id_parent, 0);
        if (r < 0) {
                if (errno == EOPNOTSUPP) {
                        if (nosupp)
                                /* Neither parent nor child do name_to_handle_at()?
                                   We have no choice but to fall back. */
                                goto fallback_fdinfo;
                        else
                                /* The parent can't do name_to_handle_at() but the
                                 * directory we are interested in can?
                                 * If so, it must be a mount point. */
                                return 1;
                } else
                        return -errno;
        }

        /* The parent can do name_to_handle_at() but the
         * directory we are interested in can't? If so, it
         * must be a mount point. */
        if (nosupp)
                return 1;

        /* If the file handle for the directory we are
         * interested in and its parent are identical, we
         * assume this is the root directory, which is a mount
         * point. */

        if (h.handle.handle_bytes == h_parent.handle.handle_bytes &&
            h.handle.handle_type == h_parent.handle.handle_type &&
            memcmp(h.handle.f_handle, h_parent.handle.f_handle, h.handle.handle_bytes) == 0)
                return 1;

        return mount_id != mount_id_parent;

fallback_fdinfo:
        r = fd_fdinfo_mnt_id(fd, "", AT_EMPTY_PATH, &mount_id);
        if (r == -EOPNOTSUPP)
                goto fallback_fstat;
        if (r < 0)
                return r;

        r = fd_fdinfo_mnt_id(fd, "..", 0, &mount_id_parent);
        if (r < 0)
                return r;

        if (mount_id != mount_id_parent)
                return 1;

        /* Hmm, so, the mount ids are the same. This leaves one
         * special case though for the root file system. For that,
         * let's see if the parent directory has the same inode as we
         * are interested in. Hence, let's also do fstat() checks now,
         * too, but avoid the st_dev comparisons, since they aren't
         * that useful on unionfs mounts. */
        check_st_dev = false;

fallback_fstat:
        if (fstatat(fd, "", &a, AT_EMPTY_PATH) < 0)
                return -errno;

        if (fstatat(fd, "..", &b, 0) < 0)
                return -errno;

        /* A directory with same device and inode as its parent? Must
         * be the root directory */
        if (a.st_dev == b.st_dev &&
            a.st_ino == b.st_ino)
                return 1;

        return check_st_dev && (a.st_dev != b.st_dev);
}

/* Like path_get_mnt_id() of systemd before it required statx(): the mount ID of the file system of path,
 * which is not followed if it is a symlink, from name_to_handle_at(), or from /proc/self/fdinfo when that is
 * not supported or not allowed, like is_name_to_handle_at_fatal_error() of systemd says. */
int path_get_mnt_id(const char *path, int *ret) {
        union file_handle_union h = FILE_HANDLE_INIT;
        int r;

        assert(path);
        assert(ret);

        r = name_to_handle_at(AT_FDCWD, path, &h.handle, ret, 0);
        if (r >= 0)
                return 0;
        if (!IN_SET(errno, EOPNOTSUPP, ENOSYS, EACCES, EPERM, EOVERFLOW, EINVAL))
                return -errno;

        return fd_fdinfo_mnt_id(AT_FDCWD, path, 0, ret);
}

/* Like dev_is_devtmpfs() of systemd: whether /dev is a devtmpfs, according to /proc/self/mountinfo; a
 * negative errno if that cannot be found out. */
int dev_is_devtmpfs(void) {
        _cleanup_fclose_ FILE *f = NULL;
        int mount_id, r;

        r = path_get_mnt_id("/dev", &mount_id);
        if (r < 0)
                return r;

        f = fopen("/proc/self/mountinfo", "re");
        if (!f)
                return -errno;

        for (;;) {
                _cleanup_free_ char *line = NULL;
                const char *e;
                int mid;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (sscanf(line, "%i", &mid) != 1)
                        continue;

                if (mid != mount_id)
                        continue;

                e = strstr(line, " - ");
                if (!e)
                        continue;

                /* accept any name that starts with the currently expected type */
                if (startswith(e + 3, "devtmpfs"))
                        return true;
        }

        return false;
}

int path_is_mount_point(const char *t, bool allow_symlink) {
        _cleanup_close_ int fd = -1;

        assert(t);

        if (path_equal(t, "/"))
                return 1;

        fd = openat(AT_FDCWD, t, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC|(allow_symlink ? 0 : O_PATH));
        if (fd < 0)
                return -errno;

        return fd_is_mount_point(fd);
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

char *prefix_root(const char *root, const char *path) {
        char *n, *p;
        size_t l;

        /* If root is passed, prefixes path with it. Otherwise returns
         * it as is. */

        assert(path);

        /* First, drop duplicate prefixing slashes from the path */
        while (path[0] == '/' && path[1] == '/')
                path++;

        if (isempty(root) || path_equal(root, "/"))
                return strdup(path);

        l = strlen(root) + 1 + strlen(path) + 1;

        n = new(char, l);
        if (!n)
                return NULL;

        p = stpcpy(n, root);

        while (p > n && p[-1] == '/')
                p--;

        if (path[0] != '/')
                *(p++) = '/';

        strcpy(p, path);
        return n;
}

int chase(const char *path, const char *root, ChaseFlags flags, char **ret_path) {
        _cleanup_free_ char *path_abs = NULL, *done = NULL, *todo = NULL;
        unsigned max_follow = 32; /* like systemd's CHASE_MAX */
        const char *p;
        char *result;
        bool exists = true;

        assert(path);
        assert(ret_path);

        if (empty_or_root(root))
                root = NULL;

        if (!root && !path_is_absolute(path)) {
                path_abs = path_make_absolute_cwd(path);
                if (!path_abs)
                        return -ENOMEM;
                path = path_abs;
        }

        /* the part of the path that is resolved, below root, empty for root itself */
        done = strdup("");
        todo = strdup(path);
        if (!done || !todo)
                return -ENOMEM;

        p = todo;
        for (;;) {
                _cleanup_free_ char *c = NULL, *full = NULL, *target = NULL;
                struct stat st;
                size_t n;
                char *d;
                int r;

                p += strspn(p, "/");
                if (*p == '\0')
                        break;

                n = strcspn(p, "/");
                c = strndup(p, n);
                if (!c)
                        return -ENOMEM;
                p += n;

                if (streq(c, "."))
                        continue;

                if (streq(c, "..")) {
                        /* never above root */
                        char *slash = strrchr(done, '/');

                        if (slash)
                                *slash = '\0';
                        continue;
                }

                full = strjoin(root ?: "", done, "/", c, NULL);
                if (!full)
                        return -ENOMEM;

                if (lstat(full, &st) < 0) {
                        if (errno != ENOENT || !(flags & CHASE_NONEXISTENT))
                                return -errno;

                        /* the rest of the path as given */
                        d = strjoin(done, "/", c, p, NULL);
                        if (!d)
                                return -ENOMEM;
                        free(done);
                        done = d;
                        exists = false;
                        break;
                }

                if (S_ISLNK(st.st_mode)) {
                        char *rest;

                        if (--max_follow == 0)
                                return -ELOOP;

                        r = readlink_malloc(full, &target);
                        if (r < 0)
                                return r;

                        /* continue with the target, followed by the rest of the path */
                        rest = strjoin(target, "/", p, NULL);
                        if (!rest)
                                return -ENOMEM;

                        if (path_is_absolute(target))
                                done[0] = '\0';

                        free(todo);
                        todo = rest;
                        p = todo;
                        continue;
                }

                d = strjoin(done, "/", c, NULL);
                if (!d)
                        return -ENOMEM;
                free(done);
                done = d;
        }

        result = strjoin(root ?: "", "/", done, NULL);
        if (!result)
                return -ENOMEM;

        *ret_path = path_simplify(result);
        return exists;
}

char* path_extend_internal(char **x, ...) {
        size_t sz, old_sz;
        char *q, *nx;
        const char *p;
        va_list ap;
        bool slash;

        /* Joins all listed strings until the sentinel and places a "/" between them unless the strings end/begin
         * already with one so that it is unnecessary. Note that slashes which are already duplicate won't be
         * removed. The string returned is hence always equal to or longer than the sum of the lengths of each
         * individual string.
         *
         * The first argument may be an already allocated string that is extended via realloc() if
         * non-NULL. path_extend() and path_join() are macro wrappers around this function, making use of the
         * first parameter to distinguish the two operations.
         *
         * Note: any listed empty string is simply skipped. This can be useful for concatenating strings of which some
         * are optional.
         *
         * Examples:
         *
         * path_join("foo", "bar") → "foo/bar"
         * path_join("foo/", "bar") → "foo/bar"
         * path_join("", "foo", "", "bar", "") → "foo/bar" */

        sz = old_sz = x ? strlen_ptr(*x) : 0;
        va_start(ap, x);
        while ((p = va_arg(ap, char*)) != POINTER_MAX) {
                size_t add;

                if (isempty(p))
                        continue;

                add = 1 + strlen(p);
                if (sz > SIZE_MAX - add) { /* overflow check */
                        va_end(ap);
                        return NULL;
                }

                sz += add;
        }
        va_end(ap);

        /* no need to generate a slash if there is nothing yet or it already ends in one */
        slash = old_sz == 0 || (*x)[old_sz-1] == '/';

        nx = realloc(x ? *x : NULL, GREEDY_ALLOC_ROUND_UP(sz+1));
        if (!nx)
                return NULL;
        if (x)
                *x = nx;

        if (old_sz == 0)
                nx[0] = 0;

        q = nx + old_sz;

        va_start(ap, x);
        while ((p = va_arg(ap, char*)) != POINTER_MAX) {
                if (isempty(p))
                        continue;

                if (!slash && p[0] != '/')
                        *(q++) = '/';

                q = stpcpy(q, p);
                slash = endswith(p, "/");
        }
        va_end(ap);

        return nx;
}


static const char* skip_slash_or_dot(const char *p) {
        for (; !isempty(p); p++) {
                if (*p == '/')
                        continue;
                if (startswith(p, "./")) {
                        p++;
                        continue;
                }
                break;
        }
        return p;
}

int path_find_first_component(const char **p, bool accept_dot_dot, const char **ret) {
        const char *q, *first, *end_first, *next;
        size_t len;

        assert(p);

        /* When a path is input, then returns the pointer to the first component and its length, and
         * move the input pointer to the next component or nul. This skips both over any '/'
         * immediately *before* and *after* the first component before returning.
         *
         * Examples
         *   Input:  p: "//.//aaa///bbbbb/cc"
         *   Output: p: "bbbbb///cc"
         *           ret: "aaa///bbbbb/cc"
         *           return value: 3 (== strlen("aaa"))
         *
         *   Input:  p: "aaa//"
         *   Output: p: (pointer to NUL)
         *           ret: "aaa//"
         *           return value: 3 (== strlen("aaa"))
         *
         *   Input:  p: "/", ".", ""
         *   Output: p: (pointer to NUL)
         *           ret: NULL
         *           return value: 0
         *
         *   Input:  p: NULL
         *   Output: p: NULL
         *           ret: NULL
         *           return value: 0
         *
         *   Input:  p: "(too long component)"
         *   Output: return value: -EINVAL
         *
         *   (when accept_dot_dot is false)
         *   Input:  p: "//..//aaa///bbbbb/cc"
         *   Output: return value: -EINVAL
         */

        q = *p;

        first = skip_slash_or_dot(q);
        if (isempty(first)) {
                *p = first;
                if (ret)
                        *ret = NULL;
                return 0;
        }
        if (streq(first, ".")) {
                *p = first + 1;
                if (ret)
                        *ret = NULL;
                return 0;
        }

        end_first = strchrnul(first, '/');
        len = end_first - first;

        if (len > NAME_MAX)
                return -EINVAL;
        if (!accept_dot_dot && len == 2 && first[0] == '.' && first[1] == '.')
                return -EINVAL;

        next = skip_slash_or_dot(end_first);

        *p = next + streq(next, ".");
        if (ret)
                *ret = first;
        return len;
}

char* path_simplify(char *path) {
        bool add_slash = false, absolute, beginning = true;
        char *f = path;
        int r;

        /* Removes redundant inner and trailing slashes. Also removes unnecessary dots.
         * Modifies the passed string in-place.
         *
         * ///foo//./bar/.   becomes /foo/bar
         * .//./foo//./bar/. becomes foo/bar
         * /../foo/bar       becomes /foo/bar
         * /../foo/bar/..    becomes /foo/bar/..
         */

        if (isempty(path))
                return path;

        absolute = path_is_absolute(path);
        f += absolute;  /* Keep leading /, if present. */

        for (const char *p = f;;) {
                const char *e;

                r = path_find_first_component(&p, true, &e);
                if (r == 0)
                        break;

                if (r > 0 && absolute && beginning && path_startswith(e, ".."))
                        /* If we're at the beginning of an absolute path, we can safely skip ".." */
                        continue;

                beginning = false;

                if (add_slash)
                        *f++ = '/';

                if (r < 0) {
                        /* if path is invalid, then refuse to simplify the remaining part. */
                        memmove(f, p, strlen(p) + 1);
                        return path;
                }

                memmove(f, e, r);
                f += r;

                add_slash = true;
        }

        /* Special rule, if we stripped everything, we need a "." for the current directory. */
        if (f == path)
                *f++ = '.';

        *f = '\0';
        return path;
}

int path_simplify_alloc(const char *path, char **ret) {
        char *t;

        assert(ret);

        if (!path) {
                *ret = NULL;
                return 0;
        }

        t = strdup(path);
        if (!t)
                return -ENOMEM;

        *ret = path_simplify(t);
        return 0;
}

bool path_is_valid_full(const char *p, bool accept_dot_dot) {
        if (isempty(p))
                return false;

        for (const char *e = p;;) {
                int r;

                r = path_find_first_component(&e, accept_dot_dot, NULL);
                if (r < 0)
                        return false;

                if (e - p >= PATH_MAX) /* Already reached the maximum length for a path? (PATH_MAX is counted
                                        * *with* the trailing NUL byte) */
                        return false;
                if (*e == 0)           /* End of string? Yay! */
                        return true;
        }
}

bool path_is_normalized(const char *p) {
        if (!path_is_safe(p))
                return false;

        if (streq(p, ".") || startswith(p, "./") || endswith(p, "/.") || strstr(p, "/./"))
                return false;

        if (strstr(p, "//"))
                return false;

        return true;
}

bool empty_or_root(const char *path) {

        /* For operations relative to some root directory, returns true if the specified root directory is
         * redundant, i.e. either / or NULL or the empty string or any equivalent. */

        if (isempty(path))
                return true;

        return path_equal(path, "/");
}

int path_make_relative(const char *from, const char *to, char **ret) {
        _cleanup_free_ char *result = NULL;
        unsigned n_parents;
        const char *f, *t;
        int r, k;
        char *p;

        assert(from);
        assert(to);
        assert(ret);

        /* Strips the common part, and adds ".." elements as necessary. */

        if (!path_is_absolute(from) || !path_is_absolute(to))
                return -EINVAL;

        for (;;) {
                r = path_find_first_component(&from, true, &f);
                if (r < 0)
                        return r;

                k = path_find_first_component(&to, true, &t);
                if (k < 0)
                        return k;

                if (r == 0) {
                        /* end of 'from' */
                        if (k == 0) {
                                /* from and to are equivalent. */
                                result = strdup(".");
                                if (!result)
                                        return -ENOMEM;
                        } else {
                                /* 'to' is inside of 'from'. */
                                r = path_simplify_alloc(t, &result);
                                if (r < 0)
                                        return r;

                                if (!path_is_valid(result))
                                        return -EINVAL;
                        }

                        *ret = TAKE_PTR(result);
                        return 0;
                }

                if (r != k || !strneq(f, t, r))
                        break;
        }

        /* If we're here, then "from_dir" has one or more elements that need to
         * be replaced with "..". */

        for (n_parents = 1;; n_parents++) {
                /* If this includes ".." we can't do a simple series of "..". */
                r = path_find_first_component(&from, false, &f);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;
        }

        if (isempty(t) && n_parents * 3 > PATH_MAX)
                /* PATH_MAX is counted *with* the trailing NUL byte */
                return -EINVAL;

        result = new(char, n_parents * 3 + !isempty(t) + strlen_ptr(t));
        if (!result)
                return -ENOMEM;

        for (p = result; n_parents > 0; n_parents--)
                p = mempcpy(p, "../", 3);

        if (isempty(t)) {
                /* Remove trailing slash and terminate string. */
                *(--p) = '\0';
                *ret = TAKE_PTR(result);
                return 0;
        }

        strcpy(p, t);

        path_simplify(result);

        if (!path_is_valid(result))
                return -EINVAL;

        *ret = TAKE_PTR(result);
        return 0;
}

int path_make_relative_parent(const char *from_child, const char *to, char **ret) {
        _cleanup_free_ char *from = NULL;

        assert(from_child);
        assert(to);
        assert(ret);

        /* Similar to path_make_relative(), but provides the relative path from the parent directory of
         * 'from_child'. This may be useful when creating relative symlink.
         *
         * E.g.
         * - from = "/path/to/aaa", to = "/path/to/bbb"
         *      path_make_relative(from, to) = "../bbb"
         *      path_make_relative_parent(from, to) = "bbb"
         *
         * - from = "/path/to/aaa/bbb", to = "/path/to/ccc/ddd"
         *      path_make_relative(from, to) = "../../ccc/ddd"
         *      path_make_relative_parent(from, to) = "../ccc/ddd"
         */

        if (!path_is_absolute(from_child))
                return -EINVAL;

        from = dirname_malloc(from_child);
        if (!from)
                return -ENOMEM;

        return path_make_relative(from, to, ret);
}
