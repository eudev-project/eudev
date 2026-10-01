/***
  This file is part of eudev, forked from systemd.

  Copyright 2010-2012 Lennart Poettering
  Copyright 2010-2012 Kay Sievers

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

#include "macro.h"

/* The flags of systemd's conf_files_list_strv_full(), as far as they are implemented. */
typedef enum ConfFilesFlags {
        CONF_FILES_REGULAR                  = 1 << 1, /* inode must be regular file */
        CONF_FILES_FILTER_MASKED_BY_SYMLINK = 1 << 4, /* implement /dev/null symlink based masking */
        CONF_FILES_FILTER_MASKED_BY_EMPTY   = 1 << 5, /* implement masking by empty file */
        CONF_FILES_FILTER_MASKED            = CONF_FILES_FILTER_MASKED_BY_SYMLINK | CONF_FILES_FILTER_MASKED_BY_EMPTY,
        CONF_FILES_WARN                     = 1 << 7, /* warn on some errors */
} ConfFilesFlags;

int conf_files_list_strv(char ***strv, const char *suffix, const char *root, const char* const* dirs);
int conf_files_list_strv_full(char ***strv, const char *suffix, const char *root, ConfFilesFlags flags, const char* const* dirs);
int conf_files_list_strv_path(char ***strv, const char *suffix, const char *root, ConfFilesFlags flags, const char* path);
