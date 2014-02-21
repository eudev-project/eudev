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

#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/socket.h>

#include "macro.h"

/* Note: the time definitions are from upstream's
 * src/shared/time-util.h which I have put here
 * for now.  We may need to beak these out later.
 * <blueness@gentoo.org>
 */
typedef uint64_t usec_t;
typedef uint64_t nsec_t;

typedef struct dual_timestamp {
        usec_t realtime;
        usec_t monotonic;
} dual_timestamp;

union dirent_storage {
        struct dirent de;
        uint8_t storage[offsetof(struct dirent, d_name) +
                        ((NAME_MAX + 1 + sizeof(long)) & ~(sizeof(long) - 1))];
};

#define MSEC_PER_SEC  1000ULL
#define USEC_PER_SEC  1000000ULL
#define USEC_PER_MSEC 1000ULL
#define NSEC_PER_SEC  1000000000ULL
#define NSEC_PER_MSEC 1000000ULL
#define NSEC_PER_USEC 1000ULL

#define USEC_PER_MINUTE (60ULL*USEC_PER_SEC)
#define NSEC_PER_MINUTE (60ULL*NSEC_PER_SEC)
#define USEC_PER_HOUR (60ULL*USEC_PER_MINUTE)
#define NSEC_PER_HOUR (60ULL*NSEC_PER_MINUTE)
#define USEC_PER_DAY (24ULL*USEC_PER_HOUR)
#define NSEC_PER_DAY (24ULL*NSEC_PER_HOUR)
#define USEC_PER_WEEK (7ULL*USEC_PER_DAY)
#define NSEC_PER_WEEK (7ULL*NSEC_PER_DAY)
#define USEC_PER_MONTH (2629800ULL*USEC_PER_SEC)
#define NSEC_PER_MONTH (2629800ULL*NSEC_PER_SEC)
#define USEC_PER_YEAR (31557600ULL*USEC_PER_SEC)
#define NSEC_PER_YEAR (31557600ULL*NSEC_PER_SEC)

#define FORMAT_TIMESPAN_MAX 64

/* What is interpreted as whitespace? */
#define WHITESPACE " \t\n\r"
#define NEWLINE    "\n\r"
#define QUOTES     "\"\'"
#define COMMENTS   "#;"
#define GLOB_CHARS "*?["

#define FORMAT_BYTES_MAX 8

#define ANSI_HIGHLIGHT_ON "\x1B[1;39m"
#define ANSI_RED_ON "\x1B[31m"
#define ANSI_HIGHLIGHT_RED_ON "\x1B[1;31m"
#define ANSI_GREEN_ON "\x1B[32m"
#define ANSI_HIGHLIGHT_GREEN_ON "\x1B[1;32m"
#define ANSI_HIGHLIGHT_YELLOW_ON "\x1B[1;33m"
#define ANSI_HIGHLIGHT_BLUE_ON "\x1B[1;34m"
#define ANSI_HIGHLIGHT_OFF "\x1B[0m"
#define ANSI_ERASE_TO_END_OF_LINE "\x1B[K"

usec_t now(clockid_t clock);
usec_t timespec_load(const struct timespec *ts);
char *format_timespan(char *buf, size_t l, usec_t t, usec_t accuracy);

size_t page_size(void);
#define PAGE_ALIGN(l) ALIGN_TO((l), page_size())

#define streq(a,b) (strcmp((a),(b)) == 0)
#define strneq(a, b, n) (strncmp((a), (b), (n)) == 0)
#define strcaseeq(a,b) (strcasecmp((a),(b)) == 0)
#define strncaseeq(a, b, n) (strncasecmp((a), (b), (n)) == 0)

bool streq_ptr(const char *a, const char *b) _pure_;

#define new(t, n) ((t*) malloc_multiply(sizeof(t), (n)))

#define new0(t, n) ((t*) calloc((n), sizeof(t)))
#define malloc0(n) (calloc((n), 1))

static inline bool isempty(const char *p) {
        return !p || !p[0];
}

static inline const char *startswith(const char *s, const char *prefix) {
        if (strncmp(s, prefix, strlen(prefix)) == 0)
                return s + strlen(prefix);
        return NULL;
}

char *endswith(const char *s, const char *postfix) _pure_;

int close_nointr(int fd);
void close_nointr_nofail(int fd);

int safe_atou(const char *s, unsigned *ret_u);
int safe_atoi(const char *s, int *ret_i);

int safe_atollu(const char *s, unsigned long long *ret_u);
int safe_atolli(const char *s, long long int *ret_i);

char *split(const char *c, size_t *l, const char *separator, char **state);
char *split_quoted(const char *c, size_t *l, char **state);

#define FOREACH_WORD_QUOTED(word, length, s, state)                     \
        for ((state) = NULL, (word) = split_quoted((s), &(length), &(state)); (word); (word) = split_quoted((s), &(length), &(state)))

char *strappend(const char *s, const char *suffix);
char *strnappend(const char *s, const char *suffix, size_t length);

char *truncate_nl(char *s);

char octchar(int x) _const_;
char hexchar(int x) _const_;

char *cescape(const char *s);
char *xescape(const char *s, const char *bad);

bool dirent_is_file_with_suffix(const struct dirent *de, const char *suffix) _pure_;

bool ignore_file(const char *filename) _pure_;

void random_bytes(void *p, size_t n);

/* For basic lookup tables with strictly enumerated entries */
#define __DEFINE_STRING_TABLE_LOOKUP(name,type,scope)                   \
        scope const char *name##_to_string(type i) {                    \
                if (i < 0 || i >= (type) ELEMENTSOF(name##_table))      \
                        return NULL;                                    \
                return name##_table[i];                                 \
        }                                                               \
        scope type name##_from_string(const char *s) {                  \
                type i;                                                 \
                assert(s);                                              \
                for (i = 0; i < (type)ELEMENTSOF(name##_table); i++)    \
                        if (name##_table[i] &&                          \
                            streq(name##_table[i], s))                  \
                                return i;                               \
                return (type) -1;                                       \
        }                                                               \
        struct __useless_struct_to_allow_trailing_semicolon__

#define DEFINE_STRING_TABLE_LOOKUP(name,type) __DEFINE_STRING_TABLE_LOOKUP(name,type,)
#define DEFINE_PRIVATE_STRING_TABLE_LOOKUP(name,type) __DEFINE_STRING_TABLE_LOOKUP(name,type,static)

/* For string conversions where numbers are also acceptable */
#define DEFINE_STRING_TABLE_LOOKUP_WITH_FALLBACK(name,type,max)         \
        int name##_to_string_alloc(type i, char **str) {                \
                char *s;                                                \
                int r;                                                  \
                if (i < 0 || i > max)                                   \
                        return -ERANGE;                                 \
                if (i < (type) ELEMENTSOF(name##_table)) {              \
                        s = strdup(name##_table[i]);                    \
                        if (!s)                                         \
                                return log_oom();                       \
                } else {                                                \
                        r = asprintf(&s, "%u", i);                      \
                        if (r < 0)                                      \
                                return log_oom();                       \
                }                                                       \
                *str = s;                                               \
                return 0;                                               \
        }                                                               \
        type name##_from_string(const char *s) {                        \
                type i;                                                 \
                unsigned u = 0;                                         \
                assert(s);                                              \
                for (i = 0; i < (type)ELEMENTSOF(name##_table); i++)    \
                        if (name##_table[i] &&                          \
                            streq(name##_table[i], s))                  \
                                return i;                               \
                if (safe_atou(s, &u) >= 0 && u <= max)                  \
                        return (type) u;                                \
                return (type) -1;                                       \
        }                                                               \
        struct __useless_struct_to_allow_trailing_semicolon__

int open_terminal(const char *name, int mode);

int fopen_temporary(const char *path, FILE **_f, char **_temp_path);

ssize_t loop_read(int fd, void *buf, size_t nbytes, bool do_poll);
int chmod_and_chown(const char *path, mode_t mode, uid_t uid, gid_t gid);

bool null_or_empty(struct stat *st) _pure_;
int null_or_empty_path(const char *fn);

int execute_command(const char *command, char *const argv[]);

bool nulstr_contains(const char*nulstr, const char *needle);

char *strjoin(const char *x, ...) _sentinel_;

bool is_main_thread(void);

#define NULSTR_FOREACH(i, l)                                    \
        for ((i) = (l); (i) && *(i); (i) = strchr((i), 0)+1)

#define NULSTR_FOREACH_PAIR(i, j, l)                             \
        for ((i) = (l), (j) = strchr((i), 0)+1; (i) && *(i); (i) = strchr((j), 0)+1, (j) = *(i) ? strchr((i), 0)+1 : (i))

int ioprio_class_to_string_alloc(int i, char **s);
int ioprio_class_from_string(const char *s);

const char *sigchld_code_to_string(int i) _const_;
int sigchld_code_from_string(const char *s) _pure_;

int log_facility_unshifted_to_string_alloc(int i, char **s);
int log_facility_unshifted_from_string(const char *s);

int log_level_to_string_alloc(int i, char **s);
int log_level_from_string(const char *s);

int sched_policy_to_string_alloc(int i, char **s);
int sched_policy_from_string(const char *s);

const char *rlimit_to_string(int i) _const_;
int rlimit_from_string(const char *s) _pure_;

int ip_tos_to_string_alloc(int i, char **s);
int ip_tos_from_string(const char *s);

const char *signal_to_string(int i) _const_;

extern int saved_argc;
extern char **saved_argv;

int fd_inc_sndbuf(int fd, size_t n);

bool in_initrd(void);

static inline void freep(void *p) {
        free(*(void**) p);
}

#define DEFINE_TRIVIAL_CLEANUP_FUNC(type, func)                 \
        static inline void func##p(type *p) {                   \
                if (*p)                                         \
                        func(*p);                               \
        }                                                       \
        struct __useless_struct_to_allow_trailing_semicolon__

static inline void fclosep(FILE **f) {
        if (*f)
                fclose(*f);
}

static inline void closep(int *fd) {
        if (*fd >= 0)
                close_nointr_nofail(*fd);
}

static inline void closedirp(DIR **d) {
        if (*d)
                closedir(*d);
}

#define _cleanup_free_ _cleanup_(freep)
#define _cleanup_fclose_ _cleanup_(fclosep)
#define _cleanup_close_ _cleanup_(closep)
#define _cleanup_closedir_ _cleanup_(closedirp)

_malloc_  _alloc_(1, 2) static inline void *malloc_multiply(size_t a, size_t b) {
        if (_unlikely_(b == 0 || a > ((size_t) -1) / b))
                return NULL;

        return malloc(a * b);
}

/**
 * Check if a string contains any glob patterns.
 */
_pure_ static inline bool string_is_glob(const char *p) {
        return !!strpbrk(p, GLOB_CHARS);
}

void *xbsearch_r(const void *key, const void *base, size_t nmemb, size_t size,
                 int (*compar) (const void *, const void *, void *),
                 void *arg);

#define FOREACH_LINE(line, f, on_error)                         \
        for (;;)                                                \
                if (!fgets(line, sizeof(line), f)) {            \
                        if (ferror(f)) {                        \
                                on_error;                       \
                        }                                       \
                        break;                                  \
                } else

static inline void _reset_errno_(int *saved_errno) {
        errno = *saved_errno;
}

#define PROTECT_ERRNO _cleanup_(_reset_errno_) __attribute__((unused)) int _saved_errno_ = errno

int unlink_noerrno(const char *path);
static inline void qsort_safe(void *base, size_t nmemb, size_t size,
                              int (*compar)(const void *, const void *)) {
        if (nmemb) {
                assert(base);
                qsort(base, nmemb, size, compar);
        }
}

int proc_cmdline(char **ret);
int getpeercred(int fd, struct ucred *ucred);
