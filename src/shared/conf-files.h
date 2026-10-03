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

#include <stddef.h>

#include "macro.h"

/* The flags of systemd's conf_files_list_strv_full(), as far as they are implemented. */
typedef enum ConfFilesFlags {
        CONF_FILES_REGULAR                  = 1 << 1, /* inode must be regular file */
        CONF_FILES_FILTER_MASKED_BY_SYMLINK = 1 << 4, /* implement /dev/null symlink based masking */
        CONF_FILES_FILTER_MASKED_BY_EMPTY   = 1 << 5, /* implement masking by empty file */
        CONF_FILES_FILTER_MASKED            = CONF_FILES_FILTER_MASKED_BY_SYMLINK | CONF_FILES_FILTER_MASKED_BY_EMPTY,
        CONF_FILES_WARN                     = 1 << 7, /* warn on some errors */
        CONF_FILES_FAIL_ON_UNREADABLE_DIR   = 1 << 16, /* eudev: fail if a directory that exists cannot be read */
} ConfFilesFlags;

/* Like systemd's ConfFile, without the file descriptor: a file found in a configuration directory. The
 * paths are prefixed with the root directory, if one is given. */
typedef struct ConfFile {
        char *filename;      /* the name of the file, which orders the files and overrides the same name */
        char *result;        /* the path with the symlinks of the directory resolved */
        char *original_path; /* the path as found in the directory, without resolving symlinks */
        char *resolved_path; /* the path with all symlinks resolved */
} ConfFile;

ConfFile *conf_file_free(ConfFile *c);
void conf_file_free_array(ConfFile **files, size_t n_files);

/* Like systemd's conf_file_new(): the file path, below root, checked as flags ask. Returns -ERFKILL
 * for a mask, -ENOENT if it does not exist, -EISDIR for a directory, -EBADFD for another file that is
 * not a regular file, with CONF_FILES_REGULAR, -EADDRNOTAVAIL if path has no file name, i.e. it is
 * the root directory, or "." below root, -EINVAL if it ends with "..", or another negative errno. */
int conf_file_new(const char *path, const char *root, ConfFilesFlags flags, ConfFile **ret);

/* Like systemd's conf_files_list_strv() and conf_files_list_strv_full(): the files with the suffix in
 * the directories dirs, below root, sorted by name, where a file overrides the files with the same
 * name in later directories, and with CONF_FILES_FILTER_MASKED a mask, i.e. a symlink to /dev/null or
 * an empty file, masks them. A relative directory is relative to root, or without root to the current
 * directory. conf_files_list_strv() returns the paths in ConfFile.result. */
int conf_files_list_strv(char ***ret, const char *suffix, const char *root, ConfFilesFlags flags, const char * const *dirs);
int conf_files_list_strv_full(const char *suffix, const char *root, ConfFilesFlags flags, const char * const *dirs,
                              ConfFile ***ret_files, size_t *ret_n_files);
