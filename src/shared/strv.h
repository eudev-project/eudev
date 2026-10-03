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

#pragma once

#include <stdarg.h>
#include <stdbool.h>

#include "util.h"

char **strv_free(char **l);
DEFINE_TRIVIAL_CLEANUP_FUNC(char**, strv_free);
#define _cleanup_strv_free_ _cleanup_(strv_freep)

void strv_clear(char **l);

char **strv_copy(char * const *l);
unsigned strv_length(char * const *l) _pure_;

int strv_extend(char ***l, const char *value);
int strv_push(char ***l, char *value);
int strv_consume(char ***l, char *value);

char **strv_remove(char **l, const char *s);
char **strv_uniq(char **l);

char *strv_find(char * const *l, const char *name) _pure_;
#define strv_contains(l, s) (!!strv_find((l), (s)))

#define STRV_MAKE(...) ((char**) ((const char*[]) { __VA_ARGS__, NULL }))

#define STR_IN_SET(x, ...) strv_contains(STRV_MAKE(__VA_ARGS__), x)

char **strv_sort(char **l);

int strv_split_and_extend(char ***l, const char *s, const char *separators, bool filter_duplicates);
int strv_split_full(char ***t, const char *s, const char *separators, ExtractFlags flags);
char **strv_split(const char *s, const char *separators);
int strv_push_prepend(char ***l, char *value);
int strv_consume_prepend(char ***l, char *value);
int strv_prepend(char ***l, const char *value);

char **strv_new(const char *x, ...) _sentinel_;
char **strv_new_ap(const char *x, va_list ap);

static inline bool strv_isempty(char * const *l) {
        return !l || !*l;
}

#define STRV_FOREACH(s, l)                      \
        for ((s) = (l); (s) && *(s); (s)++)
