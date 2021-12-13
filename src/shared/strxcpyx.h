/***
  This file is part of eudev from systemd.

  Copyright 2013 Kay Sievers

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

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>

#include "macro.h"

size_t strnpcpy_full(char **dest, size_t size, const char *src, size_t len, bool *ret_truncated);
static inline size_t strnpcpy(char **dest, size_t size, const char *src, size_t len) {
        return strnpcpy_full(dest, size, src, len, NULL);
}
size_t strpcpy_full(char **dest, size_t size, const char *src, bool *ret_truncated);
static inline size_t strpcpy(char **dest, size_t size, const char *src) {
        return strpcpy_full(dest, size, src, NULL);
}
size_t strpcpyf_full(char **dest, size_t size, bool *ret_truncated, const char *src, ...) _printf_(4, 5);
#define strpcpyf(dest, size, src, ...) \
        strpcpyf_full((dest), (size), NULL, (src), ##__VA_ARGS__)
size_t strpcpyl_full(char **dest, size_t size, bool *ret_truncated, const char *src, ...) _sentinel_;
#define strpcpyl(dest, size, src, ...) \
        strpcpyl_full((dest), (size), NULL, (src), ##__VA_ARGS__)
size_t strnscpy_full(char *dest, size_t size, const char *src, size_t len, bool *ret_truncated);
static inline size_t strnscpy(char *dest, size_t size, const char *src, size_t len) {
        return strnscpy_full(dest, size, src, len, NULL);
}
size_t strscpy_full(char *dest, size_t size, const char *src, bool *ret_truncated);
static inline size_t strscpy(char *dest, size_t size, const char *src) {
        return strscpy_full(dest, size, src, NULL);
}
size_t strscpyl_full(char *dest, size_t size, bool *ret_truncated, const char *src, ...) _sentinel_;
#define strscpyl(dest, size, src, ...) \
        strscpyl_full(dest, size, NULL, src, ##__VA_ARGS__)
