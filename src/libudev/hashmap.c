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

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "util.h"
#include "hashmap.h"
#include "macro.h"
#include "siphash24.h"

#define INITIAL_N_BUCKETS 31

struct hashmap_entry {
        const void *key;
        void *value;
        struct hashmap_entry *bucket_next, *bucket_previous;
        struct hashmap_entry *iterate_next, *iterate_previous;
};

struct Hashmap {
        hash_func_t hash_func;
        compare_func_t compare_func;

        struct hashmap_entry *iterate_list_head, *iterate_list_tail;

        struct hashmap_entry ** buckets;
        unsigned n_buckets, n_entries;

        uint8_t hash_key[HASH_KEY_SIZE];
        bool from_pool:1;
};

struct pool {
        struct pool *next;
        unsigned n_tiles;
        unsigned n_used;
};

static struct pool *first_hashmap_pool = NULL;
static void *first_hashmap_tile = NULL;

static struct pool *first_entry_pool = NULL;
static void *first_entry_tile = NULL;

static void* allocate_tile(struct pool **first_pool, void **first_tile, size_t tile_size, unsigned at_least) {
        unsigned i;

        /* When a tile is released we add it to the list and simply
         * place the next pointer at its offset 0. */

        assert(tile_size >= sizeof(void*));
        assert(at_least > 0);

        if (*first_tile) {
                void *r;

                r = *first_tile;
                *first_tile = * (void**) (*first_tile);
                return r;
        }

        if (_unlikely_(!*first_pool) || _unlikely_((*first_pool)->n_used >= (*first_pool)->n_tiles)) {
                unsigned n;
                size_t size;
                struct pool *p;

                n = *first_pool ? (*first_pool)->n_tiles : 0;
                n = MAX(at_least, n * 2);
                size = PAGE_ALIGN(ALIGN(sizeof(struct pool)) + n*tile_size);
                n = (size - ALIGN(sizeof(struct pool))) / tile_size;

                p = malloc(size);
                if (!p)
                        return NULL;

                p->next = *first_pool;
                p->n_tiles = n;
                p->n_used = 0;

                *first_pool = p;
        }

        i = (*first_pool)->n_used++;

        return ((uint8_t*) (*first_pool)) + ALIGN(sizeof(struct pool)) + i*tile_size;
}

static void deallocate_tile(void **first_tile, void *p) {
        * (void**) p = *first_tile;
        *first_tile = p;
}

unsigned long string_hash_func(const void *p, const uint8_t hash_key[HASH_KEY_SIZE]) {
        uint64_t u;
        siphash24((uint8_t*) &u, p, strlen(p), hash_key);
        return (unsigned long) u;
}

int string_compare_func(const void *a, const void *b) {
        return strcmp(a, b);
}

unsigned long trivial_hash_func(const void *p, const uint8_t hash_key[HASH_KEY_SIZE]) {
        uint64_t u;
        siphash24((uint8_t*) &u, &p, sizeof(p), hash_key);
        return (unsigned long) u;
}

int trivial_compare_func(const void *a, const void *b) {
        return a < b ? -1 : (a > b ? 1 : 0);
}

static unsigned bucket_hash(Hashmap *h, const void *p) {
        return (unsigned) (h->hash_func(p, h->hash_key) % h->n_buckets);
}

static void get_hash_key(uint8_t hash_key[HASH_KEY_SIZE], bool reuse_is_ok) {
        static uint8_t current[HASH_KEY_SIZE];
        static bool current_initialized = false;

        /* Returns a hash function key to use. In order to keep things
         * fast we will not generate a new key each time we allocate a
         * new hash table. Instead, we'll just reuse the most recently
         * generated one, except if we never generated one or when we
         * are rehashing an entire hash table because we reached a
         * fill level */

        if (!current_initialized || !reuse_is_ok) {
                random_bytes(current, sizeof(current));
                current_initialized = true;
        }

        memcpy(hash_key, current, sizeof(current));
}

Hashmap *hashmap_new(hash_func_t hash_func, compare_func_t compare_func) {
        bool b;
        Hashmap *h;
        size_t size;

        b = is_main_thread();

        size = ALIGN(sizeof(Hashmap)) + INITIAL_N_BUCKETS * sizeof(struct hashmap_entry*);

        if (b) {
                h = allocate_tile(&first_hashmap_pool, &first_hashmap_tile, size, 8);
                if (!h)
                        return NULL;

                memzero(h, size);
        } else {
                h = malloc0(size);

                if (!h)
                        return NULL;
        }

        h->hash_func = hash_func ? hash_func : trivial_hash_func;
        h->compare_func = compare_func ? compare_func : trivial_compare_func;

        h->n_buckets = INITIAL_N_BUCKETS;
        h->n_entries = 0;
        h->iterate_list_head = h->iterate_list_tail = NULL;

        h->buckets = (struct hashmap_entry**) ((uint8_t*) h + ALIGN(sizeof(Hashmap)));

        h->from_pool = b;

        get_hash_key(h->hash_key, true);

        return h;
}

static void link_entry(Hashmap *h, struct hashmap_entry *e, unsigned hash) {
        assert(h);
        assert(e);

        /* Insert into hash table */
        e->bucket_next = h->buckets[hash];
        e->bucket_previous = NULL;
        if (h->buckets[hash])
                h->buckets[hash]->bucket_previous = e;
        h->buckets[hash] = e;

        /* Insert into iteration list */
        e->iterate_previous = h->iterate_list_tail;
        e->iterate_next = NULL;
        if (h->iterate_list_tail) {
                assert(h->iterate_list_head);
                h->iterate_list_tail->iterate_next = e;
        } else {
                assert(!h->iterate_list_head);
                h->iterate_list_head = e;
        }
        h->iterate_list_tail = e;

        h->n_entries++;
        assert(h->n_entries >= 1);
}

static void unlink_entry(Hashmap *h, struct hashmap_entry *e, unsigned hash) {
        assert(h);
        assert(e);

        /* Remove from iteration list */
        if (e->iterate_next)
                e->iterate_next->iterate_previous = e->iterate_previous;
        else
                h->iterate_list_tail = e->iterate_previous;

        if (e->iterate_previous)
                e->iterate_previous->iterate_next = e->iterate_next;
        else
                h->iterate_list_head = e->iterate_next;

        /* Remove from hash table bucket list */
        if (e->bucket_next)
                e->bucket_next->bucket_previous = e->bucket_previous;

        if (e->bucket_previous)
                e->bucket_previous->bucket_next = e->bucket_next;
        else
                h->buckets[hash] = e->bucket_next;

        assert(h->n_entries >= 1);
        h->n_entries--;
}

static void remove_entry(Hashmap *h, struct hashmap_entry *e) {
        unsigned hash;

        assert(h);
        assert(e);

        hash = bucket_hash(h, e->key);
        unlink_entry(h, e, hash);

        if (h->from_pool)
                deallocate_tile(&first_entry_tile, e);
        else
                free(e);
}

void hashmap_free(Hashmap*h) {

        /* Free the hashmap, but nothing in it */

        if (!h)
                return;

        hashmap_clear(h);

        if (h->buckets != (struct hashmap_entry**) ((uint8_t*) h + ALIGN(sizeof(Hashmap))))
                free(h->buckets);

        if (h->from_pool)
                deallocate_tile(&first_hashmap_tile, h);
        else
                free(h);
}

void hashmap_free_free(Hashmap *h) {

        /* Free the hashmap and all data objects in it, but not the
         * keys */

        if (!h)
                return;

        hashmap_clear_free(h);
        hashmap_free(h);
}

void hashmap_clear(Hashmap *h) {
        if (!h)
                return;

        while (h->iterate_list_head)
                remove_entry(h, h->iterate_list_head);
}

void hashmap_clear_free(Hashmap *h) {
        void *p;

        if (!h)
                return;

        while ((p = hashmap_steal_first(h)))
                free(p);
}

static struct hashmap_entry *hash_scan(Hashmap *h, unsigned hash, const void *key) {
        struct hashmap_entry *e;
        assert(h);
        assert(hash < h->n_buckets);

        for (e = h->buckets[hash]; e; e = e->bucket_next)
                if (h->compare_func(e->key, key) == 0)
                        return e;

        return NULL;
}

static bool resize_buckets(Hashmap *h) {
        struct hashmap_entry **n, *i;
        unsigned m;
        uint8_t nkey[HASH_KEY_SIZE];

        assert(h);

        if (_likely_(h->n_entries*4 < h->n_buckets*3))
                return false;

        /* Increase by four */
        m = (h->n_entries+1)*4-1;

        /* If we hit OOM we simply risk packed hashmaps... */
        n = new0(struct hashmap_entry*, m);
        if (!n)
                return false;

        /* Let's use a different randomized hash key for the
         * extension, so that people cannot guess what we are using
         * here forever */
        get_hash_key(nkey, false);

        for (i = h->iterate_list_head; i; i = i->iterate_next) {
                unsigned long old_bucket, new_bucket;

                old_bucket = h->hash_func(i->key, h->hash_key) % h->n_buckets;

                /* First, drop from old bucket table */
                if (i->bucket_next)
                        i->bucket_next->bucket_previous = i->bucket_previous;

                if (i->bucket_previous)
                        i->bucket_previous->bucket_next = i->bucket_next;
                else
                        h->buckets[old_bucket] = i->bucket_next;

                /* Then, add to new backet table */
                new_bucket = h->hash_func(i->key, nkey)  % m;

                i->bucket_next = n[new_bucket];
                i->bucket_previous = NULL;
                if (n[new_bucket])
                        n[new_bucket]->bucket_previous = i;
                n[new_bucket] = i;
        }

        if (h->buckets != (struct hashmap_entry**) ((uint8_t*) h + ALIGN(sizeof(Hashmap))))
                free(h->buckets);

        h->buckets = n;
        h->n_buckets = m;

        memcpy(h->hash_key, nkey, HASH_KEY_SIZE);

        return true;
}

int hashmap_put(Hashmap *h, const void *key, void *value) {
        struct hashmap_entry *e;
        unsigned hash;

        assert(h);

        hash = bucket_hash(h, key);
        e = hash_scan(h, hash, key);
        if (e) {
                if (e->value == value)
                        return 0;
                return -EEXIST;
        }

        if (resize_buckets(h))
                hash = bucket_hash(h, key);

        if (h->from_pool)
                e = allocate_tile(&first_entry_pool, &first_entry_tile, sizeof(struct hashmap_entry), 64U);
        else
                e = new(struct hashmap_entry, 1);

        if (!e)
                return -ENOMEM;

        e->key = key;
        e->value = value;

        link_entry(h, e, hash);

        return 1;
}

void* hashmap_get(Hashmap *h, const void *key) {
        unsigned hash;
        struct hashmap_entry *e;

        if (!h)
                return NULL;

        hash = bucket_hash(h, key);
        e = hash_scan(h, hash, key);
        if (!e)
                return NULL;

        return e->value;
}

bool hashmap_contains(Hashmap *h, const void *key) {
        unsigned hash;

        if (!h)
                return false;

        hash = bucket_hash(h, key);
        return !!hash_scan(h, hash, key);
}

void *hashmap_iterate(Hashmap *h, Iterator *i, const void **key) {
        struct hashmap_entry *e;

        assert(i);

        if (!h)
                goto at_end;

        if (*i == ITERATOR_LAST)
                goto at_end;

        if (*i == ITERATOR_FIRST && !h->iterate_list_head)
                goto at_end;

        e = *i == ITERATOR_FIRST ? h->iterate_list_head : (struct hashmap_entry*) *i;

        if (e->iterate_next)
                *i = (Iterator) e->iterate_next;
        else
                *i = ITERATOR_LAST;

        if (key)
                *key = e->key;

        return e->value;

at_end:
        *i = ITERATOR_LAST;

        if (key)
                *key = NULL;

        return NULL;
}

void *hashmap_iterate_backwards(Hashmap *h, Iterator *i, const void **key) {
        struct hashmap_entry *e;

        assert(i);

        if (!h)
                goto at_beginning;

        if (*i == ITERATOR_FIRST)
                goto at_beginning;

        if (*i == ITERATOR_LAST && !h->iterate_list_tail)
                goto at_beginning;

        e = *i == ITERATOR_LAST ? h->iterate_list_tail : (struct hashmap_entry*) *i;

        if (e->iterate_previous)
                *i = (Iterator) e->iterate_previous;
        else
                *i = ITERATOR_FIRST;

        if (key)
                *key = e->key;

        return e->value;

at_beginning:
        *i = ITERATOR_FIRST;

        if (key)
                *key = NULL;

        return NULL;
}

void* hashmap_steal_first(Hashmap *h) {
        void *data;

        if (!h)
                return NULL;

        if (!h->iterate_list_head)
                return NULL;

        data = h->iterate_list_head->value;
        remove_entry(h, h->iterate_list_head);

        return data;
}

unsigned hashmap_size(Hashmap *h) {

        if (!h)
                return 0;

        return h->n_entries;
}

char **hashmap_get_strv(Hashmap *h) {
        char **sv;
        Iterator it;
        char *item;
        int n;

        sv = new(char*, h->n_entries+1);
        if (!sv)
                return NULL;

        n = 0;
        HASHMAP_FOREACH(item, h, it)
                sv[n++] = item;
        sv[n] = NULL;

        return sv;
}
