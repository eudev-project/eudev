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

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>

#include "time-util.h"
#include "macro.h"

usec_t now(clockid_t clock_id) {
        struct timespec ts;

        assert_se(clock_gettime(clock_id, &ts) == 0);

        return timespec_load(&ts);
}

usec_t timespec_load(const struct timespec *ts) {
        assert(ts);

        if (ts->tv_sec == (time_t) -1 &&
            ts->tv_nsec == (long) -1)
                return USEC_INFINITY;

        if ((usec_t) ts->tv_sec > (UINT64_MAX - (ts->tv_nsec / NSEC_PER_USEC)) / USEC_PER_SEC)
                return USEC_INFINITY;

        return
                (usec_t) ts->tv_sec * USEC_PER_SEC +
                (usec_t) ts->tv_nsec / NSEC_PER_USEC;
}

struct timespec *timespec_store(struct timespec *ts, usec_t u)  {
        assert(ts);

        if (u == USEC_INFINITY) {
                ts->tv_sec = (time_t) -1;
                ts->tv_nsec = (long) -1;
                return ts;
        }

        ts->tv_sec = (time_t) (u / USEC_PER_SEC);
        ts->tv_nsec = (long int) ((u % USEC_PER_SEC) * NSEC_PER_USEC);

        return ts;
}
struct timeval *timeval_store(struct timeval *tv, usec_t u) {
        assert(tv);

        if (u == USEC_INFINITY) {
                tv->tv_sec = (time_t) -1;
                tv->tv_usec = (suseconds_t) -1;
        } else {
                tv->tv_sec = (time_t) (u / USEC_PER_SEC);
                tv->tv_usec = (suseconds_t) (u % USEC_PER_SEC);
        }

        return tv;
}

char *format_timespan(char *buf, size_t l, usec_t t, usec_t accuracy) {
        static const struct {
                const char *suffix;
                usec_t usec;
        } table[] = {
                { "y", USEC_PER_YEAR },
                { "month", USEC_PER_MONTH },
                { "w", USEC_PER_WEEK },
                { "d", USEC_PER_DAY },
                { "h", USEC_PER_HOUR },
                { "min", USEC_PER_MINUTE },
                { "s", USEC_PER_SEC },
                { "ms", USEC_PER_MSEC },
                { "us", 1 },
        };

        unsigned i;
        char *p = buf;
        bool something = false;

        assert(buf);
        assert(l > 0);

        if (t == USEC_INFINITY) {
                strncpy(p, "infinity", l-1);
                p[l-1] = 0;
                return p;
        }

        if (t <= 0) {
                strncpy(p, "0", l-1);
                p[l-1] = 0;
                return p;
        }

        /* The result of this function can be parsed with parse_sec */

        for (i = 0; i < ELEMENTSOF(table); i++) {
                int k = 0;
                size_t n;
                bool done = false;
                usec_t a, b;

                if (t <= 0)
                        break;

                if (t < accuracy && something)
                        break;

                if (t < table[i].usec)
                        continue;

                if (l <= 1)
                        break;

                a = t / table[i].usec;
                b = t % table[i].usec;

                /* Let's see if we should shows this in dot notation */
                if (t < USEC_PER_MINUTE && b > 0) {
                        usec_t cc;
                        int j;

                        j = 0;
                        for (cc = table[i].usec; cc > 1; cc /= 10)
                                j++;

                        for (cc = accuracy; cc > 1; cc /= 10) {
                                b /= 10;
                                j--;
                        }

                        if (j > 0) {
                                k = snprintf(p, l,
                                             "%s"USEC_FMT".%0*llu%s",
                                             p > buf ? " " : "",
                                             a,
                                             j,
                                             (unsigned long long) b,
                                             table[i].suffix);

                                t = 0;
                                done = true;
                        }
                }

                /* No? Then let's show it normally */
                if (!done) {
                        k = snprintf(p, l,
                                     "%s"USEC_FMT"%s",
                                     p > buf ? " " : "",
                                     a,
                                     table[i].suffix);

                        t = b;
                }

                n = MIN((size_t) k, l);

                l -= n;
                p += n;

                something = true;
        }

        *p = 0;

        return buf;
}

static const char* extract_multiplier(const char *p, usec_t *ret) {
        static const struct {
                const char *suffix;
                usec_t usec;
        } table[] = {
                { "seconds",   USEC_PER_SEC    },
                { "second",    USEC_PER_SEC    },
                { "sec",       USEC_PER_SEC    },
                { "s",         USEC_PER_SEC    },
                { "minutes",   USEC_PER_MINUTE },
                { "minute",    USEC_PER_MINUTE },
                { "min",       USEC_PER_MINUTE },
                { "months",    USEC_PER_MONTH  },
                { "month",     USEC_PER_MONTH  },
                { "M",         USEC_PER_MONTH  },
                { "msec",      USEC_PER_MSEC   },
                { "ms",        USEC_PER_MSEC   },
                { "m",         USEC_PER_MINUTE },
                { "hours",     USEC_PER_HOUR   },
                { "hour",      USEC_PER_HOUR   },
                { "hr",        USEC_PER_HOUR   },
                { "h",         USEC_PER_HOUR   },
                { "days",      USEC_PER_DAY    },
                { "day",       USEC_PER_DAY    },
                { "d",         USEC_PER_DAY    },
                { "weeks",     USEC_PER_WEEK   },
                { "week",      USEC_PER_WEEK   },
                { "w",         USEC_PER_WEEK   },
                { "years",     USEC_PER_YEAR   },
                { "year",      USEC_PER_YEAR   },
                { "y",         USEC_PER_YEAR   },
                { "usec",      1ULL            },
                { "us",        1ULL            },
                { "\xce\xbcs", 1ULL            }, /* U+03bc (aka GREEK SMALL LETTER MU) */
                { "\xc2\xb5s", 1ULL            }, /* U+b5 (aka MICRO SIGN) */
        };
        unsigned i;

        for (i = 0; i < ELEMENTSOF(table); i++) {
                size_t l = strlen(table[i].suffix);

                if (strncmp(p, table[i].suffix, l) == 0) {
                        *ret = table[i].usec;
                        return p + l;
                }
        }

        return p;
}

#define TIME_WHITESPACE " \t\n\r"
#define TIME_DIGITS "0123456789"

/* The number of leading characters of s that strtoll() skips: those for which isspace() is true. */
static size_t strspn_isspace(const char *s) {
        size_t n = 0;

        while (isspace((unsigned char) s[n]))
                n++;

        return n;
}

/* Parses a time span such as "5", "1.5s", "2min 30s" or "infinity", like systemd's
 * parse_time(). A number without a unit is taken in default_unit. */
int parse_time(const char *t, usec_t *ret, usec_t default_unit) {
        const char *p, *s;
        usec_t usec = 0;
        bool something = false;

        assert(t);
        assert(default_unit > 0);

        p = t + strspn(t, TIME_WHITESPACE);
        if (strncmp(p, "infinity", strlen("infinity")) == 0) {
                s = p + strlen("infinity");
                if (s[strspn(s, TIME_WHITESPACE)] != '\0')
                        return -EINVAL;

                if (ret)
                        *ret = USEC_INFINITY;
                return 0;
        }

        for (;;) {
                usec_t multiplier = default_unit, k;
                long long l;
                char *e;

                p += strspn(p, TIME_WHITESPACE);
                if (*p == 0) {
                        if (!something)
                                return -EINVAL;

                        break;
                }

                /* Don't allow "-0". Unlike systemd, look for the sign after all the characters that strtoll()
                 * skips, i.e. those for which isspace() is true, \v and \f too, so that e.g. "\v-0.5" is
                 * refused as well. */
                if (p[strspn_isspace(p)] == '-')
                        return -ERANGE;

                errno = 0;
                l = strtoll(p, &e, 10);
                if (errno > 0)
                        return -errno;
                if (l < 0)
                        return -ERANGE;

                if (*e == '.') {
                        p = e + 1;
                        p += strspn(p, TIME_DIGITS);
                } else if (e == p)
                        return -EINVAL;
                else
                        p = e;

                s = extract_multiplier(p + strspn(p, TIME_WHITESPACE), &multiplier);
                if (s == p && *s != '\0')
                        /* Don't allow '12.34.56', but accept '12.34 .56' or '12.34s.56' */
                        return -EINVAL;

                p = s;

                if ((usec_t) l >= USEC_INFINITY / multiplier)
                        return -ERANGE;

                k = (usec_t) l * multiplier;
                if (k >= USEC_INFINITY - usec)
                        return -ERANGE;

                usec += k;

                something = true;

                if (*e == '.') {
                        usec_t m = multiplier / 10;
                        const char *b;

                        for (b = e + 1; *b >= '0' && *b <= '9'; b++, m /= 10) {
                                k = (usec_t) (*b - '0') * m;
                                if (k >= USEC_INFINITY - usec)
                                        return -ERANGE;

                                usec += k;
                        }

                        /* Don't allow "0.-0", "3.+1", "3. 1", "3.sec" or "3.hoge" */
                        if (b == e + 1)
                                return -EINVAL;
                }
        }

        if (ret)
                *ret = usec;
        return 0;
}

int parse_sec(const char *t, usec_t *ret) {
        return parse_time(t, ret, USEC_PER_SEC);
}
