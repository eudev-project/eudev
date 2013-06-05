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
#include <stdarg.h>
#include <string.h>
#include <errno.h>

#include "util.h"
#include "strv.h"

char *strv_find(char **l, const char *name) {
        char **i;

        assert(name);

        STRV_FOREACH(i, l)
                if (streq(*i, name))
                        return *i;

        return NULL;
}

void strv_free(char **l) {
        char **k;

        if (!l)
                return;

        for (k = l; *k; k++)
                free(*k);

        free(l);
}

char **strv_copy(char * const *l) {
        char **r, **k;

        k = r = new(char*, strv_length(l) + 1);
        if (!r)
                return NULL;

        if (l)
                for (; *l; k++, l++) {
                        *k = strdup(*l);
                        if (!*k) {
                                strv_free(r);
                                return NULL;
                        }
                }

        *k = NULL;
        return r;
}

unsigned strv_length(char * const *l) {
        unsigned n = 0;

        if (!l)
                return 0;

        for (; *l; l++)
                n++;

        return n;
}

char **strv_new_ap(const char *x, va_list ap) {
        const char *s;
        char **a;
        unsigned n = 0, i = 0;
        va_list aq;

        /* As a special trick we ignore all listed strings that equal
         * (const char*) -1. This is supposed to be used with the
         * STRV_IFNOTNULL() macro to include possibly NULL strings in
         * the string list. */

        if (x) {
                n = x == (const char*) -1 ? 0 : 1;

                va_copy(aq, ap);
                while ((s = va_arg(aq, const char*))) {
                        if (s == (const char*) -1)
                                continue;

                        n++;
                }

                va_end(aq);
        }

        a = new(char*, n+1);
        if (!a)
                return NULL;

        if (x) {
                if (x != (const char*) -1) {
                        a[i] = strdup(x);
                        if (!a[i])
                                goto fail;
                        i++;
                }

                while ((s = va_arg(ap, const char*))) {

                        if (s == (const char*) -1)
                                continue;

                        a[i] = strdup(s);
                        if (!a[i])
                                goto fail;

                        i++;
                }
        }

        a[i] = NULL;

        return a;

fail:
        strv_free(a);
        return NULL;
}

char **strv_new(const char *x, ...) {
        char **r;
        va_list ap;

        va_start(ap, x);
        r = strv_new_ap(x, ap);
        va_end(ap);

        return r;
}

char **strv_merge(char **a, char **b) {
        char **r, **k;

        if (!a)
                return strv_copy(b);

        if (!b)
                return strv_copy(a);

        r = new(char*, strv_length(a) + strv_length(b) + 1);
        if (!r)
                return NULL;

        for (k = r; *a; k++, a++) {
                *k = strdup(*a);
                if (!*k)
                        goto fail;
        }

        for (; *b; k++, b++) {
                *k = strdup(*b);
                if (!*k)
                        goto fail;
        }

        *k = NULL;
        return r;

fail:
        strv_free(r);
        return NULL;
}

char **strv_split(const char *s, const char *separator) {
        char *state;
        char *w;
        size_t l;
        unsigned n, i;
        char **r;

        assert(s);

        n = 0;
        FOREACH_WORD_SEPARATOR(w, l, s, separator, state)
                n++;

        r = new(char*, n+1);
        if (!r)
                return NULL;

        i = 0;
        FOREACH_WORD_SEPARATOR(w, l, s, separator, state) {
                r[i] = strndup(w, l);
                if (!r[i]) {
                        strv_free(r);
                        return NULL;
                }

                i++;
        }

        r[i] = NULL;
        return r;
}

char **strv_split_quoted(const char *s) {
        char *state;
        char *w;
        size_t l;
        unsigned n, i;
        char **r;

        assert(s);

        n = 0;
        FOREACH_WORD_QUOTED(w, l, s, state)
                n++;

        r = new(char*, n+1);
        if (!r)
                return NULL;

        i = 0;
        FOREACH_WORD_QUOTED(w, l, s, state) {
                r[i] = cunescape_length(w, l);
                if (!r[i]) {
                        strv_free(r);
                        return NULL;
                }
                i++;
        }

        r[i] = NULL;
        return r;
}

char **strv_append(char **l, const char *s) {
        char **r, **k;

        if (!l)
                return strv_new(s, NULL);

        if (!s)
                return strv_copy(l);

        r = new(char*, strv_length(l)+2);
        if (!r)
                return NULL;

        for (k = r; *l; k++, l++) {
                *k = strdup(*l);
                if (!*k)
                        goto fail;
        }

        k[0] = strdup(s);
        if (!k[0])
                goto fail;

        k[1] = NULL;
        return r;

fail:
        strv_free(r);
        return NULL;
}

int strv_push(char ***l, char *value) {
        char **c;
        unsigned n;

        if (!value)
                return 0;

        n = strv_length(*l);
        c = realloc(*l, sizeof(char*) * (n + 2));
        if (!c)
                return -ENOMEM;

        c[n] = value;
        c[n+1] = NULL;

        *l = c;
        return 0;
}

int strv_extend(char ***l, const char *value) {
        char *v;
        int r;

        if (!value)
                return 0;

        v = strdup(value);
        if (!v)
                return -ENOMEM;

        r = strv_push(l, v);
        if (r < 0)
                free(v);

        return r;
}

char **strv_uniq(char **l) {
        char **i;

        /* Drops duplicate entries. The first identical string will be
         * kept, the others dropped */

        STRV_FOREACH(i, l)
                strv_remove(i+1, *i);

        return l;
}

char **strv_remove(char **l, const char *s) {
        char **f, **t;

        if (!l)
                return NULL;

        assert(s);

        /* Drops every occurrence of s in the string list, edits
         * in-place. */

        for (f = t = l; *f; f++) {

                if (streq(*f, s)) {
                        free(*f);
                        continue;
                }

                *(t++) = *f;
        }

        *t = NULL;
        return l;
}

char **strv_split_nulstr(const char *s) {
        const char *i;
        char **r = NULL;

        NULSTR_FOREACH(i, s)
                if (strv_extend(&r, i) < 0) {
                        strv_free(r);
                        return NULL;
                }

        if (!r)
                return strv_new(NULL, NULL);

        return r;
}

static int str_compare(const void *_a, const void *_b) {
        const char **a = (const char**) _a, **b = (const char**) _b;

        return strcmp(*a, *b);
}
