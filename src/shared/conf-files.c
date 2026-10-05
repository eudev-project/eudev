/***
  This file is part of eudev, forked from systemd.

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
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <dirent.h>

#include "macro.h"
#include "util.h"
#include "missing.h"
#include "log.h"
#include "strv.h"
#include "path-util.h"
#include "hashmap.h"
#include "set.h"
#include "conf-files.h"

ConfFile *conf_file_free(ConfFile *c) {
        if (!c)
                return NULL;

        free(c->filename);
        free(c->result);
        free(c->original_path);
        free(c->resolved_path);
        free(c);
        return NULL;
}

void conf_file_free_array(ConfFile **files, size_t n_files) {
        size_t i;

        for (i = 0; i < n_files; i++)
                conf_file_free(files[i]);
        free(files);
}

static int conf_files_log_level(ConfFilesFlags flags) {
        return FLAGS_SET(flags, CONF_FILES_WARN) ? LOG_WARNING : LOG_DEBUG;
}

static bool conf_files_need_stat(ConfFilesFlags flags) {
        return (flags & (CONF_FILES_FILTER_MASKED | CONF_FILES_REGULAR)) != 0;
}

static ChaseFlags conf_files_chase_flags(ConfFilesFlags flags) {
        /* Like systemd: a file that is not checked may be missing, and a symlink to /dev/null is a
         * mask also where /dev/null does not exist, e.g. below the root directory. */
        if (!conf_files_need_stat(flags) || FLAGS_SET(flags, CONF_FILES_FILTER_MASKED_BY_SYMLINK))
                return CHASE_NONEXISTENT;

        return 0;
}

/* The absolute path below root of path, which is prefixed with root. */
static const char *skip_root(const char *root, const char *path) {
        const char *p = root ? path_startswith(path, root) : NULL;

        if (!p)
                return path;

        /* path_startswith() returns the rest after the slash, keep the slash */
        return p > path && p[-1] == '/' ? p - 1 : p;
}

static int conf_file_mask(Set *masked, const char *name, const char *original_path, const char *what) {
        int r;

        /* the files with this name in the later directories are masked too */
        if (masked) {
                r = set_put_strdup(masked, name);
                if (r < 0)
                        return r;
        }

        log_debug("File '%s' is a mask (%s).", original_path, what);
        return -ERFKILL;
}

/* Like systemd's conf_file_chase_and_verify(): resolves the symlinks of path below root, and checks the
 * file as flags ask. Returns 0 and the resolved path, prefixed with root, if the file is listed,
 * -ERFKILL if it is a mask, after adding name to masked, or another negative errno if it is skipped.
 * original_path is the path as found, prefixed with root, for the messages. */
static int conf_file_chase_and_verify(const char *root, const char *original_path, const char *path,
                                      const char *name, Set *masked, ConfFilesFlags flags,
                                      char **ret_resolved) {
        _cleanup_free_ char *resolved = NULL;
        int log_level = conf_files_log_level(flags);
        struct stat st;
        int r;

        r = chase(path, root, conf_files_chase_flags(flags), &resolved);
        if (r == -ENOENT && FLAGS_SET(flags, CONF_FILES_QUIET_MISSING))
                return r;
        if (r < 0)
                return log_full_errno(log_level, r, "Failed to chase '%s': %m", original_path);
        if (r == 0) {
                if (FLAGS_SET(flags, CONF_FILES_FILTER_MASKED_BY_SYMLINK) &&
                    path_equal(skip_root(root, resolved), "/dev/null"))
                        return conf_file_mask(masked, name, original_path, "symlink to /dev/null");

                if (conf_files_need_stat(flags)) {
                        if (FLAGS_SET(flags, CONF_FILES_QUIET_MISSING))
                                return -ENOENT;
                        return log_full_errno(log_level, ENOENT, "Failed to chase '%s': %m", original_path);
                }
        } else if (conf_files_need_stat(flags)) {
                if (stat(resolved, &st) < 0)
                        return log_full_errno(log_level, errno, "Failed to stat '%s': %m", original_path);

                if (FLAGS_SET(flags, CONF_FILES_FILTER_MASKED_BY_SYMLINK) &&
                    S_ISCHR(st.st_mode) && st.st_rdev == makedev(1, 3))
                        return conf_file_mask(masked, name, original_path, "symlink to /dev/null");

                if (FLAGS_SET(flags, CONF_FILES_FILTER_MASKED_BY_EMPTY) &&
                    S_ISREG(st.st_mode) && st.st_size <= 0)
                        return conf_file_mask(masked, name, original_path, "an empty file");

                if (FLAGS_SET(flags, CONF_FILES_REGULAR) && !S_ISREG(st.st_mode)) {
                        if (S_ISDIR(st.st_mode))
                                return log_debug_errno(EISDIR, "File '%s' is not a regular file: %m",
                                                       original_path);

                        /* Unlike systemd, without the text of EBADFD, "File descriptor in bad state",
                         * which says nothing about e.g. a FIFO. */
                        log_debug("File '%s' is not a regular file, ignoring.", original_path);
                        return -EBADFD;
                }
        }

        if (ret_resolved)
                *ret_resolved = TAKE_PTR(resolved);
        return 0;
}

static ConfFile *conf_file_make(const char *filename, char **result, char **original_path, char **resolved_path) {
        ConfFile *c;

        c = new0(ConfFile, 1);
        if (!c)
                return NULL;

        c->filename = strdup(filename);
        if (!c->filename)
                return conf_file_free(c);

        c->result = TAKE_PTR(*result);
        c->original_path = TAKE_PTR(*original_path);
        c->resolved_path = TAKE_PTR(*resolved_path);
        return c;
}

int conf_file_new(const char *path, const char *root, ConfFilesFlags flags, ConfFile **ret) {
        _cleanup_free_ char *path_abs = NULL, *p = NULL, *dirpath = NULL, *resolved_dirpath = NULL,
                *original_path = NULL, *result = NULL, *resolved_path = NULL, *filename = NULL;
        int log_level = conf_files_log_level(flags);
        const char *e;
        ConfFile *c;
        int r;

        assert(path);
        assert(ret);

        if (empty_or_root(root))
                root = NULL;

        /* Like systemd: without root, a relative path is relative to the current directory, with root
         * relative to root. */
        if (!root && !path_is_absolute(path)) {
                path_abs = path_make_absolute_cwd(path);
                if (!path_abs)
                        return log_oom();
                path = path_abs;
        }

        /* Like systemd's conf_file_new_at(): the path must name a file, i.e. it must not be the root
         * directory, "." below root, or end with "..". */
        r = path_extract_filename(path, &filename);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                return log_full_errno(log_level, r, "Failed to extract filename from '%s': %m", path);

        p = strdup(path);
        original_path = prefix_root(root, path);
        if (!p || !original_path)
                return log_oom();
        path_simplify(p);
        path_simplify(original_path);

        /* the simplified path ends with the file name */
        e = strrchr(p, '/');
        dirpath = e ? strndup(p, e - p) : strdup("");
        if (!dirpath)
                return log_oom();

        r = chase(dirpath, root, conf_files_chase_flags(flags), &resolved_dirpath);
        if (r == -ENOENT && FLAGS_SET(flags, CONF_FILES_QUIET_MISSING))
                return r;
        if (r < 0) {
                _cleanup_free_ char *d = prefix_root(root, isempty(dirpath) ? "/" : dirpath);

                return log_full_errno(log_level, r, "Failed to chase '%s': %m", d ? path_simplify(d) : dirpath);
        }

        result = strjoin(resolved_dirpath, "/", filename, NULL);
        if (!result)
                return log_oom();
        path_simplify(result);

        r = conf_file_chase_and_verify(root, original_path, skip_root(root, result), filename,
                                       NULL, flags, &resolved_path);
        if (r < 0)
                return r;

        c = conf_file_make(filename, &result, &original_path, &resolved_path);
        if (!c)
                return log_oom();

        *ret = c;
        return 0;
}

static void conf_file_hashmap_free(Hashmap *h) {
        ConfFile *c;

        while ((c = hashmap_steal_first(h)))
                conf_file_free(c);
        hashmap_free(h);
}

/* original_dirpath is the directory as given and resolved_dirpath with symlinks resolved, both prefixed
 * with root. */
static int files_add(Hashmap *h, Set *masked, DIR *dir, const char *root, const char *original_dirpath,
                     const char *resolved_dirpath, const char *suffix, ConfFilesFlags flags) {
        int log_level = conf_files_log_level(flags);

        for (;;) {
                _cleanup_free_ char *original_path = NULL, *result = NULL, *resolved_path = NULL;
                struct dirent *de;
                ConfFile *c;
                int r;

                errno = 0;
                de = readdir(dir);
                if (!de) {
                        if (errno != 0)
                                return log_full_errno(log_level, errno, "Failed to read directory '%s': %m",
                                                      original_dirpath);
                        break;
                }

                /* Without checks, only regular files and symlinks are listed, as before. With checks,
                 * all files, so that e.g. a FIFO is skipped with a message, like systemd. */
                if (flags == 0 ? !dirent_is_file_with_suffix(de, suffix) :
                                 hidden_file(de->d_name) || !endswith(de->d_name, suffix))
                        continue;

                /* like systemd, with path_join(), so that there is no double slash after the root
                 * directory "/" */
                original_path = path_join(original_dirpath, de->d_name);
                result = path_join(resolved_dirpath, de->d_name);
                if (!original_path || !result)
                        return -ENOMEM;

                /* Like systemd: a file of an earlier directory overrides the files with the same name, a
                 * mask masks them, and a file that is neither listed nor a mask, e.g. one that is not a
                 * regular file, does not hide them. */
                if (hashmap_contains(h, de->d_name)) {
                        log_debug("Skipping overridden file '%s'.", original_path);
                        continue;
                }

                if (masked && set_contains(masked, de->d_name)) {
                        log_debug("File '%s' is masked by previous entry.", original_path);
                        continue;
                }

                if (flags != 0) {
                        r = conf_file_chase_and_verify(root, original_path, skip_root(root, result),
                                                       de->d_name, masked, flags, &resolved_path);
                        if (r == -ENOMEM)
                                return r;
                        if (r < 0)
                                continue;
                } else {
                        resolved_path = strdup(result);
                        if (!resolved_path)
                                return -ENOMEM;
                }

                c = conf_file_make(de->d_name, &result, &original_path, &resolved_path);
                if (!c)
                        return -ENOMEM;

                r = hashmap_put(h, c->filename, c);
                if (r < 0) {
                        conf_file_free(c);
                        return r;
                }
        }

        return 0;
}

static int conf_file_cmp(const void *a, const void *b) {
        const ConfFile *c1 = *(ConfFile * const *) a, *c2 = *(ConfFile * const *) b;

        return strcmp(c1->filename, c2->filename);
}

/* Like systemd's conf_files_list_impl() and dump_files(): the files of dirs, below root, sorted by
 * their names. A directory that is missing is ignored, as is one that cannot be read, after a
 * message, unless CONF_FILES_FAIL_ON_UNREADABLE_DIR is set: then the error is returned, after all
 * directories are read. */
static int conf_files_list_impl(const char *suffix, const char *root, ConfFilesFlags flags,
                                const char * const *dirs, ConfFile ***ret_files, size_t *ret_n_files) {
        _cleanup_strv_free_ char **resolved_dirs = NULL;
        _cleanup_set_free_free_ Set *masked = NULL;
        int log_level = conf_files_log_level(flags);
        const char * const *d;
        bool fail = FLAGS_SET(flags, CONF_FILES_FAIL_ON_UNREADABLE_DIR);
        Hashmap *h;
        ConfFile **files, *c;
        size_t n = 0;
        int r = 0, dir_error = 0;

        assert(suffix);
        assert(ret_files);
        assert(ret_n_files);

        if (empty_or_root(root))
                root = NULL;

        h = hashmap_new(&string_hash_ops);
        if (!h)
                return -ENOMEM;

        /* the names of the masked files */
        if (flags & CONF_FILES_FILTER_MASKED) {
                masked = set_new(&string_hash_ops);
                if (!masked) {
                        r = -ENOMEM;
                        goto finish;
                }
        }

        STRV_FOREACH(d, dirs) {
                _cleanup_free_ char *resolved_dirpath = NULL, *original_dirpath = NULL, *dir_abs = NULL;
                _cleanup_closedir_ DIR *dir = NULL;
                const char *dirpath = *d;

                /* Like prepare_dirs() of systemd: without root, a relative directory is relative to the
                 * current directory, and with root, relative to root. */
                if (!root && !path_is_absolute(dirpath)) {
                        dir_abs = path_make_absolute_cwd(dirpath);
                        if (!dir_abs) {
                                r = -ENOMEM;
                                goto finish;
                        }
                        dirpath = dir_abs;
                }

                original_dirpath = prefix_root(root, dirpath);
                if (!original_dirpath) {
                        r = -ENOMEM;
                        goto finish;
                }
                path_simplify(original_dirpath);

                /* The directory is resolved below root, like the files in it. A directory that is the same
                 * as an earlier one, e.g. through a symlink, is read only once. */
                r = chase(dirpath, root, 0, &resolved_dirpath);
                if (r >= 0 && strv_contains(resolved_dirs, resolved_dirpath))
                        continue;
                if (r >= 0) {
                        dir = opendir(resolved_dirpath);
                        if (!dir)
                                r = -errno;
                }
                if (r == -ENOMEM)
                        goto finish;
                if (r == -ENOENT)
                        continue;
                if (r < 0) {
                        log_full_errno(log_level, r, "Failed to chase and open directory '%s'%s: %m",
                                       original_dirpath, fail ? "" : ", ignoring");
                        if (dir_error == 0)
                                dir_error = r;
                        continue;
                }

                r = strv_extend(&resolved_dirs, resolved_dirpath);
                if (r < 0)
                        goto finish;

                r = files_add(h, masked, dir, root, original_dirpath, resolved_dirpath, suffix, flags);
                if (r == -ENOMEM)
                        goto finish;
                if (r < 0 && dir_error == 0)
                        dir_error = r;
        }

        if (fail && dir_error < 0) {
                r = dir_error;
                goto finish;
        }

        files = new(ConfFile*, hashmap_size(h) + 1);
        if (!files) {
                r = -ENOMEM;
                goto finish;
        }

        while ((c = hashmap_steal_first(h)))
                files[n++] = c;

        qsort_safe(files, n, sizeof(ConfFile*), conf_file_cmp);
        *ret_files = files;
        *ret_n_files = n;
        r = 0;

finish:
        conf_file_hashmap_free(h);
        return r;
}

int conf_files_list_strv_full(const char *suffix, const char *root, ConfFilesFlags flags,
                              const char * const *dirs, ConfFile ***ret_files, size_t *ret_n_files) {
        return conf_files_list_impl(suffix, root, flags, dirs, ret_files, ret_n_files);
}

int conf_files_list_strv(char ***ret, const char *suffix, const char *root, ConfFilesFlags flags,
                         const char * const *dirs) {
        ConfFile **files = NULL;
        char **l;
        size_t n = 0, i;
        int r;

        assert(ret);

        r = conf_files_list_impl(suffix, root, flags, dirs, &files, &n);
        if (r < 0)
                return r;

        l = new0(char*, n + 1);
        if (!l) {
                conf_file_free_array(files, n);
                return -ENOMEM;
        }

        /* like systemd, the path in the directory with the symlinks of the directory resolved */
        for (i = 0; i < n; i++)
                l[i] = TAKE_PTR(files[i]->result);

        conf_file_free_array(files, n);
        *ret = l;
        return 0;
}
