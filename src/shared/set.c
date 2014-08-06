/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include <stdlib.h>

#include "set.h"
#include "hashmap.h"

#define MAKE_SET(h) ((Set*) (h))
#define MAKE_HASHMAP(s) ((Hashmap*) (s))

/* For now this is not much more than a wrapper around a hashmap */

Set *set_new(hash_func_t hash_func, compare_func_t compare_func) {
        return MAKE_SET(hashmap_new(hash_func, compare_func));
}

void set_free(Set* s) {
        hashmap_free(MAKE_HASHMAP(s));
}

int set_put(Set *s, void *value) {
        return hashmap_put(MAKE_HASHMAP(s), value, value);
}

void *set_get(Set *s, void *value) {
        return hashmap_get(MAKE_HASHMAP(s), value);
}

bool set_contains(Set *s, void *value) {
        return hashmap_contains(MAKE_HASHMAP(s), value);
}

void *set_iterate(Set *s, Iterator *i) {
        return hashmap_iterate(MAKE_HASHMAP(s), i, NULL);
}

void *set_iterate_backwards(Set *s, Iterator *i) {
        return hashmap_iterate_backwards(MAKE_HASHMAP(s), i, NULL);
}
