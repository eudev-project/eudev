/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

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

/* Pretty straightforward set implementation. Internally based on the
 * hashmap. That means that as a minor optimization a NULL set
 * object will be treated as empty set for all read
 * operations. That way it is not necessary to instantiate an object
 * for each set use. */

#include "hashmap.h"

typedef struct Set Set;

Set *set_new(hash_func_t hash_func, compare_func_t compare_func);
void set_free(Set* s);
static inline void set_freep(Set **s) {
        set_free(*s);
}

int set_put(Set *s, void *value);
void *set_get(Set *s, void *value);
bool set_contains(Set *s, void *value);

void *set_iterate(Set *s, Iterator *i);
void *set_iterate_backwards(Set *s, Iterator *i);

#define _cleanup_set_free_ _cleanup_(set_freep)
