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

#include <stdbool.h>
#include <inttypes.h>

typedef uint64_t usec_t;
typedef uint64_t nsec_t;

char* path_get_file_name(const char *p) _pure_;
int path_get_parent(const char *path, char **parent);
bool path_is_absolute(const char *p) _pure_;
char* path_make_absolute(const char *p, const char *prefix);
char* path_make_absolute_cwd(const char *p);
char* path_kill_slashes(char *path);
bool path_equal(const char *a, const char *b) _pure_;

char** path_strv_canonicalize(char **l);
char** path_strv_canonicalize_uniq(char **l);

int path_is_mount_point(const char *path, bool allow_symlink);
bool paths_check_timestamp(const char* const* paths, usec_t *paths_ts_usec, bool update);

