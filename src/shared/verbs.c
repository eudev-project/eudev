/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <string.h>
#include <sys/types.h>

#include "log.h"
#include "strv.h"
#include "util.h"
#include "verbs.h"

/* Like strlevenshtein() of systemd: the Damerau-Levenshtein distance of x and y, or -ENOMEM. */
static ssize_t strlevenshtein(const char *x, const char *y) {
        _cleanup_free_ size_t *t0 = NULL, *t1 = NULL, *t2 = NULL;
        size_t xl, yl, i, j, *dummy;

        if (streq(x, y))
                return 0;

        xl = strlen(x);
        yl = strlen(y);

        if (xl == 0)
                return yl;
        if (yl == 0)
                return xl;

        t0 = new0(size_t, yl + 1);
        t1 = new0(size_t, yl + 1);
        t2 = new0(size_t, yl + 1);
        if (!t0 || !t1 || !t2)
                return -ENOMEM;

        for (i = 0; i <= yl; i++)
                t1[i] = i;

        for (i = 0; i < xl; i++) {
                t2[0] = i + 1;

                for (j = 0; j < yl; j++) {
                        /* Substitution */
                        t2[j+1] = t1[j] + (x[i] != y[j]);

                        /* Swap */
                        if (i > 0 && j > 0 && x[i-1] == y[j] && x[i] == y[j-1] && t2[j+1] > t0[j-1] + 1)
                                t2[j+1] = t0[j-1] + 1;

                        /* Deletion */
                        if (t2[j+1] > t1[j+1] + 1)
                                t2[j+1] = t1[j+1] + 1;

                        /* Insertion */
                        if (t2[j+1] > t2[j] + 1)
                                t2[j+1] = t2[j] + 1;
                }

                dummy = t0;
                t0 = t1;
                t1 = t2;
                t2 = dummy;
        }

        return t1[yl];
}

/* Like strv_find_closest() of systemd: the string of l that begins with name, the shortest one if there are
 * several, or else the one with the smallest Levenshtein distance to name, if that is at most 5; the first one
 * if there are several, or NULL. */
static const char *strv_find_closest(char * const *l, const char *name) {
        const char *best = NULL;
        size_t best_length = SIZE_MAX;
        ssize_t best_distance = SSIZE_MAX;
        char * const *s;

        STRV_FOREACH(s, l) {
                const char *e = startswith(*s, name);

                if (e && strlen(e) < best_length) {
                        best_length = strlen(e);
                        best = *s;
                }
        }
        if (best)
                return best;

        STRV_FOREACH(s, l) {
                ssize_t distance = strlevenshtein(*s, name);

                if (distance < 0) {
                        log_debug_errno(distance, "Failed to determine Levenshtein distance between %s and %s: %m",
                                        *s, name);
                        return NULL;
                }

                /* If the distance is just too far off, don't make a bad suggestion */
                if (distance > 5)
                        continue;

                if (distance < best_distance) {
                        best_distance = distance;
                        best = *s;
                }
        }

        return best;
}

void log_verb_required(char * const *verbs) {
        _cleanup_free_ char *list = NULL;
        size_t n = 0;
        char * const *s;
        char *p;

        assert(!strv_isempty(verbs));

        if (strv_length(verbs) == 1) {
                log_error("Command verb '%s' required.", verbs[0]);
                return;
        }

        STRV_FOREACH(s, verbs)
                n += strlen(", ") + strlen(*s);

        list = new(char, n + 1);
        if (!list) {
                log_oom();
                return;
        }

        p = list;
        STRV_FOREACH(s, verbs)
                p = stpcpy(stpcpy(p, p == list ? "" : ", "), *s);
        *p = '\0';

        log_error("Command verb required (one of %s).", list);
}

void log_unknown_verb(char * const *verbs, const char *name) {
        const char *closest;

        assert(name);

        /* Be more helpful to the user, and give a hint what the user might have wanted to type. */
        closest = strv_find_closest(verbs, name);
        if (closest)
                log_error("Unknown command verb '%s', did you mean '%s'?", name, closest);
        else
                log_error("Unknown command verb '%s'.", name);
}
