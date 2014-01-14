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

#include <stdbool.h>

#include "macro.h"

/* Pretty straightforward hash table implementation. As a minor
 * optimization a NULL hashmap object will be treated as empty hashmap
 * for all read operations. That way it is not necessary to
 * instantiate an object for each Hashmap use. */

#define HASH_KEY_SIZE 16

typedef struct Hashmap Hashmap;
typedef struct _IteratorStruct _IteratorStruct;
typedef _IteratorStruct* Iterator;

#define ITERATOR_FIRST ((Iterator) 0)
#define ITERATOR_LAST ((Iterator) -1)

typedef unsigned long (*hash_func_t)(const void *p, const uint8_t hash_key[HASH_KEY_SIZE]);
typedef int (*compare_func_t)(const void *a, const void *b);

unsigned long string_hash_func(const void *p, const uint8_t hash_key[HASH_KEY_SIZE]) _pure_;
int string_compare_func(const void *a, const void *b) _pure_;

/* This will compare the passed pointers directly, and will not
 * dereference them. This is hence not useful for strings or
 * suchlike. */
unsigned long trivial_hash_func(const void *p, const uint8_t hash_key[HASH_KEY_SIZE]) _pure_;
int trivial_compare_func(const void *a, const void *b) _const_;

Hashmap *hashmap_new(hash_func_t hash_func, compare_func_t compare_func);
void hashmap_free(Hashmap *h);
void hashmap_free_free(Hashmap *h);

int hashmap_put(Hashmap *h, const void *key, void *value);
void *hashmap_get(Hashmap *h, const void *key);
bool hashmap_contains(Hashmap *h, const void *key);

unsigned hashmap_size(Hashmap *h) _pure_;

void *hashmap_iterate(Hashmap *h, Iterator *i, const void **key);
void *hashmap_iterate_backwards(Hashmap *h, Iterator *i, const void **key);

void hashmap_clear(Hashmap *h);
void hashmap_clear_free(Hashmap *h);

void *hashmap_steal_first(Hashmap *h);

char **hashmap_get_strv(Hashmap *h);

#define HASHMAP_FOREACH(e, h, i) \
        for ((i) = ITERATOR_FIRST, (e) = hashmap_iterate((h), &(i), NULL); (e); (e) = hashmap_iterate((h), &(i), NULL))
