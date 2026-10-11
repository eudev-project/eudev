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

#pragma once

#include <stdbool.h>

#include "macro.h"
#include "time-util.h"

int path_get_parent(const char *path, char **parent);
bool path_is_absolute(const char *p) _pure_;
char* path_make_absolute(const char *p, const char *prefix);
char* path_make_absolute_cwd(const char *p);
char* path_kill_slashes(char *path);
char* path_startswith(const char *path, const char *prefix) _pure_;
int path_compare(const char *a, const char *b) _pure_;
bool path_equal(const char *a, const char *b) _pure_;

char** path_strv_resolve(char **l, const char *prefix);
char** path_strv_resolve_uniq(char **l, const char *prefix);

int fd_is_mount_point(int fd);
int path_is_mount_point(const char *path, bool allow_symlink);
int path_get_mnt_id(const char *path, int *ret);
int dev_is_devtmpfs(void);

char *prefix_root(const char *root, const char *path);

typedef enum ChaseFlags {
        CHASE_NONEXISTENT = 1 << 0, /* it is OK if the path does not exist */
} ChaseFlags;

/* Like systemd's chase(): resolves the symlinks, "." and ".." of path below root, i.e. absolute
 * symlinks are resolved relative to root, and ".." does not leave it. root may be NULL, empty or "/"
 * for the host, and then a relative path is relative to the current directory; with a root, the
 * path is relative to root. Returns 1 and the resolved path, prefixed with root, if it exists. If a
 * component does not exist, returns 0 and the path resolved as far as possible, followed by the
 * rest as given, with CHASE_NONEXISTENT, and -ENOENT without. Other errors are returned as a
 * negative errno, e.g. -ELOOP for too many symlinks. */
int chase(const char *path, const char *root, ChaseFlags flags, char **ret_path);

char* path_extend_internal(char **x, ...);

int path_find_first_component(const char **p, bool accept_dot_dot, const char **ret);
/* Like chase() of systemd, which refuses a path that has a component longer than NAME_MAX with EINVAL before
 * it looks at anything: returns -EINVAL for such a path, 0 otherwise. */
int path_check_name_max(const char *path);
int path_find_last_component(const char *path, bool accept_dot_dot, const char **next, const char **ret);
/* Like systemd's path_extract_filename(): the last component of path, which is a valid file name, i.e.
 * neither "." nor "..". Returns -EINVAL if path is not valid or ends with "..", -EADDRNOTAVAIL if it
 * has no file name, i.e. it is the root directory or ".", and else O_DIRECTORY if path ends with a
 * slash, or 0. */
int path_extract_filename(const char *path, char **ret);
char* path_simplify(char *path);
int path_simplify_alloc(const char *path, char **ret);
bool path_is_valid_full(const char *p, bool accept_dot_dot) _pure_;
static inline bool path_is_valid(const char *p) {
        return path_is_valid_full(p, /* accept_dot_dot= */ true);
}
static inline bool path_is_safe(const char *p) {
        return path_is_valid_full(p, /* accept_dot_dot= */ false);
}
bool path_is_normalized(const char *p) _pure_;
bool empty_or_root(const char *path) _pure_;
int path_make_relative(const char *from, const char *to, char **ret);
int path_make_relative_parent(const char *from_child, const char *to, char **ret);
#define path_extend(x, ...) path_extend_internal(x, __VA_ARGS__, POINTER_MAX)
#define path_join(...) path_extend_internal(NULL, __VA_ARGS__, POINTER_MAX)
