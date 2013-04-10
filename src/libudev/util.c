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
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <syslog.h>
#include <sched.h>
#include <sys/resource.h>
#include <linux/sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <linux/vt.h>
#include <linux/tiocl.h>
#include <termios.h>
#include <stdarg.h>
#include <sys/inotify.h>
#include <sys/poll.h>
#include <libgen.h>
#include <ctype.h>
#include <sys/prctl.h>
#include <sys/utsname.h>
#include <pwd.h>
#include <netinet/ip.h>
#include <linux/kd.h>
#include <dlfcn.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <glob.h>
#include <grp.h>
#include <sys/mman.h>
#include <sys/vfs.h>
#include <linux/magic.h>
#include <limits.h>
#include <langinfo.h>
#include <locale.h>

#include "macro.h"
#include "util.h"
#include "ioprio.h"
#include "missing.h"
#include "log.h"
#include "strv.h"
#include "label.h"
#include "path-util.h"
#include "exit-status.h"
#include "hashmap.h"

int saved_argc = 0;
char **saved_argv = NULL;

static volatile unsigned cached_columns = 0;
static volatile unsigned cached_lines = 0;

bool is_efiboot(void) {
        return access("/sys/firmware/efi", F_OK) >= 0;
}

size_t page_size(void) {
        static __thread size_t pgsz = 0;
        long r;

        if (_likely_(pgsz > 0))
                return pgsz;

        r = sysconf(_SC_PAGESIZE);
        assert(r > 0);

        pgsz = (size_t) r;
        return pgsz;
}

bool streq_ptr(const char *a, const char *b) {

        /* Like streq(), but tries to make sense of NULL pointers */

        if (a && b)
                return streq(a, b);

        if (!a && !b)
                return true;

        return false;
}

usec_t now(clockid_t clock_id) {
        struct timespec ts;

        assert_se(clock_gettime(clock_id, &ts) == 0);

        return timespec_load(&ts);
}

dual_timestamp* dual_timestamp_get(dual_timestamp *ts) {
        assert(ts);

        ts->realtime = now(CLOCK_REALTIME);
        ts->monotonic = now(CLOCK_MONOTONIC);

        return ts;
}

dual_timestamp* dual_timestamp_from_realtime(dual_timestamp *ts, usec_t u) {
        int64_t delta;
        assert(ts);

        ts->realtime = u;

        if (u == 0)
                ts->monotonic = 0;
        else {
                delta = (int64_t) now(CLOCK_REALTIME) - (int64_t) u;

                ts->monotonic = now(CLOCK_MONOTONIC);

                if ((int64_t) ts->monotonic > delta)
                        ts->monotonic -= delta;
                else
                        ts->monotonic = 0;
        }

        return ts;
}

usec_t timespec_load(const struct timespec *ts) {
        assert(ts);

        if (ts->tv_sec == (time_t) -1 &&
            ts->tv_nsec == (long) -1)
                return (usec_t) -1;

        if ((usec_t) ts->tv_sec > (UINT64_MAX - (ts->tv_nsec / NSEC_PER_USEC)) / USEC_PER_SEC)
                return (usec_t) -1;

        return
                (usec_t) ts->tv_sec * USEC_PER_SEC +
                (usec_t) ts->tv_nsec / NSEC_PER_USEC;
}

struct timespec *timespec_store(struct timespec *ts, usec_t u)  {
        assert(ts);

        if (u == (usec_t) -1) {
                ts->tv_sec = (time_t) -1;
                ts->tv_nsec = (long) -1;
                return ts;
        }

        ts->tv_sec = (time_t) (u / USEC_PER_SEC);
        ts->tv_nsec = (long int) ((u % USEC_PER_SEC) * NSEC_PER_USEC);

        return ts;
}

usec_t timeval_load(const struct timeval *tv) {
        assert(tv);

        if (tv->tv_sec == (time_t) -1 &&
            tv->tv_usec == (suseconds_t) -1)
                return (usec_t) -1;

        if ((usec_t) tv->tv_sec > (UINT64_MAX - tv->tv_usec) / USEC_PER_SEC)
                return (usec_t) -1;

        return
                (usec_t) tv->tv_sec * USEC_PER_SEC +
                (usec_t) tv->tv_usec;
}

struct timeval *timeval_store(struct timeval *tv, usec_t u) {
        assert(tv);

        if (u == (usec_t) -1) {
                tv->tv_sec = (time_t) -1;
                tv->tv_usec = (suseconds_t) -1;
                return tv;
        }

        tv->tv_sec = (time_t) (u / USEC_PER_SEC);
        tv->tv_usec = (suseconds_t) (u % USEC_PER_SEC);

        return tv;
}

char* endswith(const char *s, const char *postfix) {
        size_t sl, pl;

        assert(s);
        assert(postfix);

        sl = strlen(s);
        pl = strlen(postfix);

        if (pl == 0)
                return (char*) s + sl;

        if (sl < pl)
                return NULL;

        if (memcmp(s + sl - pl, postfix, pl) != 0)
                return NULL;

        return (char*) s + sl - pl;
}

char* startswith(const char *s, const char *prefix) {
        assert(s);
        assert(prefix);

	return !strncmp(s, prefix, strlen(prefix)) ? (char*) s : NULL;
}

char* startswith_no_case(const char *s, const char *prefix) {
        const char *a, *b;

        assert(s);
        assert(prefix);

        a = s, b = prefix;
	
	for (; *b; a++, b++){
		if (tolower(*a) != tolower(*b))
			return NULL;
	}
	return (char*) a;
}

bool first_word(const char *s, const char *word) {
        size_t sl, wl;

        assert(s);
        assert(word);

        sl = strlen(s);
        wl = strlen(word);

        if (sl < wl)
                return false;

        if (wl == 0)
                return true;

        if (memcmp(s, word, wl) != 0)
                return false;

        return s[wl] == 0 ||
                strchr(WHITESPACE, s[wl]);
}

int close_nointr(int fd) {
        assert(fd >= 0);

        for (;;) {
                int r;

                r = close(fd);
                if (r >= 0)
                        return r;

                if (errno != EINTR)
                        return -errno;
        }
}

void close_nointr_nofail(int fd) {
        int saved_errno = errno;

        /* like close_nointr() but cannot fail, and guarantees errno
         * is unchanged */

        assert_se(close_nointr(fd) == 0);

        errno = saved_errno;
}

void close_many(const int fds[], unsigned n_fd) {
        unsigned i;

        for (i = 0; i < n_fd; i++)
                close_nointr_nofail(fds[i]);
}

int parse_boolean(const char *v) {
        assert(v);

        if (streq(v, "1") || v[0] == 'y' || v[0] == 'Y' || v[0] == 't' || v[0] == 'T' || !strcasecmp(v, "on"))
                return 1;
        else if (streq(v, "0") || v[0] == 'n' || v[0] == 'N' || v[0] == 'f' || v[0] == 'F' || !strcasecmp(v, "off"))
                return 0;

        return -EINVAL;
}

int parse_pid(const char *s, pid_t* ret_pid) {
        unsigned long ul = 0;
        pid_t pid;
        int r;

        assert(s);
        assert(ret_pid);

        r = safe_atolu(s, &ul);
        if (r < 0)
                return r;

        pid = (pid_t) ul;

        if ((unsigned long) pid != ul)
                return -ERANGE;

        if (pid <= 0)
                return -ERANGE;

        *ret_pid = pid;
        return 0;
}

int parse_uid(const char *s, uid_t* ret_uid) {
        unsigned long ul = 0;
        uid_t uid;
        int r;

        assert(s);
        assert(ret_uid);

        r = safe_atolu(s, &ul);
        if (r < 0)
                return r;

        uid = (uid_t) ul;

        if ((unsigned long) uid != ul)
                return -ERANGE;

        *ret_uid = uid;
        return 0;
}

int safe_atou(const char *s, unsigned *ret_u) {
        char *x = NULL;
        unsigned long l;

        assert(s);
        assert(ret_u);

        errno = 0;
        l = strtoul(s, &x, 0);

        if (!x || x == s || *x || errno)
                return errno ? -errno : -EINVAL;

        if ((unsigned long) (unsigned) l != l)
                return -ERANGE;

        *ret_u = (unsigned) l;
        return 0;
}

int safe_atoi(const char *s, int *ret_i) {
        char *x = NULL;
        long l;

        assert(s);
        assert(ret_i);

        errno = 0;
        l = strtol(s, &x, 0);

        if (!x || x == s || *x || errno)
                return errno ? -errno : -EINVAL;

        if ((long) (int) l != l)
                return -ERANGE;

        *ret_i = (int) l;
        return 0;
}

int safe_atollu(const char *s, long long unsigned *ret_llu) {
        char *x = NULL;
        unsigned long long l;

        assert(s);
        assert(ret_llu);

        errno = 0;
        l = strtoull(s, &x, 0);

        if (!x || x == s || *x || errno)
                return errno ? -errno : -EINVAL;

        *ret_llu = l;
        return 0;
}

int safe_atolli(const char *s, long long int *ret_lli) {
        char *x = NULL;
        long long l;

        assert(s);
        assert(ret_lli);

        errno = 0;
        l = strtoll(s, &x, 0);

        if (!x || x == s || *x || errno)
                return errno ? -errno : -EINVAL;

        *ret_lli = l;
        return 0;
}

/* Split a string into words. */
char *split(const char *c, size_t *l, const char *separator, char **state) {
        char *current;

        current = *state ? *state : (char*) c;

        if (!*current || *c == 0)
                return NULL;

        current += strspn(current, separator);
        *l = strcspn(current, separator);
        *state = current+*l;

        return (char*) current;
}

/* Split a string into words, but consider strings enclosed in '' and
 * "" as words even if they include spaces. */
char *split_quoted(const char *c, size_t *l, char **state) {
        char *current, *e;
        bool escaped = false;

        current = *state ? *state : (char*) c;

        if (!*current || *c == 0)
                return NULL;

        current += strspn(current, WHITESPACE);

        if (*current == '\'') {
                current ++;

                for (e = current; *e; e++) {
                        if (escaped)
                                escaped = false;
                        else if (*e == '\\')
                                escaped = true;
                        else if (*e == '\'')
                                break;
                }

                *l = e-current;
                *state = *e == 0 ? e : e+1;
        } else if (*current == '\"') {
                current ++;

                for (e = current; *e; e++) {
                        if (escaped)
                                escaped = false;
                        else if (*e == '\\')
                                escaped = true;
                        else if (*e == '\"')
                                break;
                }

                *l = e-current;
                *state = *e == 0 ? e : e+1;
        } else {
                for (e = current; *e; e++) {
                        if (escaped)
                                escaped = false;
                        else if (*e == '\\')
                                escaped = true;
                        else if (strchr(WHITESPACE, *e))
                                break;
                }
                *l = e-current;
                *state = e;
        }

        return (char*) current;
}

int get_parent_of_pid(pid_t pid, pid_t *_ppid) {
        int r;
        _cleanup_fclose_ FILE *f = NULL;
        char fn[PATH_MAX], line[LINE_MAX], *p;
        long unsigned ppid;

        assert(pid > 0);
        assert(_ppid);

        assert_se(snprintf(fn, sizeof(fn)-1, "/proc/%lu/stat", (unsigned long) pid) < (int) (sizeof(fn)-1));
        char_array_0(fn);

        f = fopen(fn, "re");
        if (!f)
                return -errno;

        if (!fgets(line, sizeof(line), f)) {
                r = feof(f) ? -EIO : -errno;
                fclose(f);
                return r;
        }

        /* Let's skip the pid and comm fields. The latter is enclosed
         * in () but does not escape any () in its value, so let's
         * skip over it manually */

        p = strrchr(line, ')');
        if (!p)
                return -EIO;

        p++;

        if (sscanf(p, " "
                   "%*c "  /* state */
                   "%lu ", /* ppid */
                   &ppid) != 1)
                return -EIO;

        if ((long unsigned) (pid_t) ppid != ppid)
                return -ERANGE;

        *_ppid = (pid_t) ppid;

        return 0;
}

int get_starttime_of_pid(pid_t pid, unsigned long long *st) {
        _cleanup_fclose_ FILE *f = NULL;
        char fn[PATH_MAX], line[LINE_MAX], *p;

        assert(pid > 0);
        assert(st);

        assert_se(snprintf(fn, sizeof(fn)-1, "/proc/%lu/stat", (unsigned long) pid) < (int) (sizeof(fn)-1));
        char_array_0(fn);

        f = fopen(fn, "re");
        if (!f)
                return -errno;

        if (!fgets(line, sizeof(line), f)) {
                if (ferror(f))
                        return -errno;

                return -EIO;
        }

        /* Let's skip the pid and comm fields. The latter is enclosed
         * in () but does not escape any () in its value, so let's
         * skip over it manually */

        p = strrchr(line, ')');
        if (!p)
                return -EIO;

        p++;

        if (sscanf(p, " "
                   "%*c "  /* state */
                   "%*d "  /* ppid */
                   "%*d "  /* pgrp */
                   "%*d "  /* session */
                   "%*d "  /* tty_nr */
                   "%*d "  /* tpgid */
                   "%*u "  /* flags */
                   "%*u "  /* minflt */
                   "%*u "  /* cminflt */
                   "%*u "  /* majflt */
                   "%*u "  /* cmajflt */
                   "%*u "  /* utime */
                   "%*u "  /* stime */
                   "%*d "  /* cutime */
                   "%*d "  /* cstime */
                   "%*d "  /* priority */
                   "%*d "  /* nice */
                   "%*d "  /* num_threads */
                   "%*d "  /* itrealvalue */
                   "%llu "  /* starttime */,
                   st) != 1)
                return -EIO;

        return 0;
}

int write_one_line_file(const char *fn, const char *line) {
        _cleanup_fclose_ FILE *f = NULL;

        assert(fn);
        assert(line);

        f = fopen(fn, "we");
        if (!f)
                return -errno;

        errno = 0;
        if (fputs(line, f) < 0)
                return errno ? -errno : -EIO;

        if (!endswith(line, "\n"))
                fputc('\n', f);

        fflush(f);

        if (ferror(f))
                return errno ? -errno : -EIO;

        return 0;
}

int fchmod_umask(int fd, mode_t m) {
        mode_t u;
        int r;

        u = umask(0777);
        r = fchmod(fd, m & (~u)) < 0 ? -errno : 0;
        umask(u);

        return r;
}

int write_one_line_file_atomic(const char *fn, const char *line) {
        FILE *f;
        int r;
        char *p;

        assert(fn);
        assert(line);

        r = fopen_temporary(fn, &f, &p);
        if (r < 0)
                return r;

        fchmod_umask(fileno(f), 0644);

        errno = 0;
        if (fputs(line, f) < 0) {
                r = -errno;
                goto finish;
        }

        if (!endswith(line, "\n"))
                fputc('\n', f);

        fflush(f);

        if (ferror(f)) {
                if (errno != 0)
                        r = -errno;
                else
                        r = -EIO;
        } else {
                if (rename(p, fn) < 0)
                        r = -errno;
                else
                        r = 0;
        }

finish:
        if (r < 0)
                unlink(p);

        fclose(f);
        free(p);

        return r;
}

int read_one_line_file(const char *fn, char **line) {
        _cleanup_fclose_ FILE *f = NULL;
        char t[LINE_MAX], *c;

        assert(fn);
        assert(line);

        f = fopen(fn, "re");
        if (!f)
                return -errno;

        if (!fgets(t, sizeof(t), f)) {

                if (ferror(f))
                        return errno ? -errno : -EIO;

                t[0] = 0;
        }

        c = strdup(t);
        if (!c)
                return -ENOMEM;
        truncate_nl(c);

        *line = c;
        return 0;
}

int read_full_file(const char *fn, char **contents, size_t *size) {
        _cleanup_fclose_ FILE *f = NULL;
        size_t n, l;
        _cleanup_free_ char *buf = NULL;
        struct stat st;

        f = fopen(fn, "re");
        if (!f)
                return -errno;

        if (fstat(fileno(f), &st) < 0)
                return -errno;

        /* Safety check */
        if (st.st_size > 4*1024*1024)
                return -E2BIG;

        n = st.st_size > 0 ? st.st_size : LINE_MAX;
        l = 0;

        for (;;) {
                char *t;
                size_t k;

                t = realloc(buf, n+1);
                if (!t)
                        return -ENOMEM;

                buf = t;
                k = fread(buf + l, 1, n - l, f);

                if (k <= 0) {
                        if (ferror(f))
                                return -errno;

                        break;
                }

                l += k;
                n *= 2;

                /* Safety check */
                if (n > 4*1024*1024)
                        return -E2BIG;
        }

        buf[l] = 0;
        *contents = buf;
        buf = NULL;

        if (size)
                *size = l;

        return 0;
}

int parse_env_file(
                const char *fname,
                const char *separator, ...) {

        int r = 0;
        char *contents = NULL, *p;

        assert(fname);
        assert(separator);

        if ((r = read_full_file(fname, &contents, NULL)) < 0)
                return r;

        p = contents;
        for (;;) {
                const char *key = NULL;

                p += strspn(p, separator);
                p += strspn(p, WHITESPACE);

                if (!*p)
                        break;

                if (!strchr(COMMENTS, *p)) {
                        va_list ap;
                        char **value;

                        va_start(ap, separator);
                        while ((key = va_arg(ap, char *))) {
                                size_t n;
                                char *v;

                                value = va_arg(ap, char **);

                                n = strlen(key);
                                if (strncmp(p, key, n) != 0 ||
                                    p[n] != '=')
                                        continue;

                                p += n + 1;
                                n = strcspn(p, separator);

                                if (n >= 2 &&
                                    strchr(QUOTES, p[0]) &&
                                    p[n-1] == p[0])
                                        v = strndup(p+1, n-2);
                                else
                                        v = strndup(p, n);

                                if (!v) {
                                        r = -ENOMEM;
                                        va_end(ap);
                                        goto fail;
                                }

                                if (v[0] == '\0') {
                                        /* return empty value strings as NULL */
                                        free(v);
                                        v = NULL;
                                }

                                free(*value);
                                *value = v;

                                p += n;

                                r ++;
                                break;
                        }
                        va_end(ap);
                }

                if (!key)
                        p += strcspn(p, separator);
        }

fail:
        free(contents);
        return r;
}

int load_env_file(
                const char *fname,
                char ***rl) {

        FILE *f;
        char **m = NULL;
        int r;

        assert(fname);
        assert(rl);

        if (!(f = fopen(fname, "re")))
                return -errno;

        while (!feof(f)) {
                char l[LINE_MAX], *p, *u;
                char **t;

                if (!fgets(l, sizeof(l), f)) {
                        if (feof(f))
                                break;

                        r = -errno;
                        goto finish;
                }

                p = strstrip(l);

                if (!*p)
                        continue;

                if (strchr(COMMENTS, *p))
                        continue;

                if (!(u = normalize_env_assignment(p))) {
                        r = log_oom();
                        goto finish;
                }

                t = strv_append(m, u);
                free(u);

                if (!t) {
                        r = log_oom();
                        goto finish;
                }

                strv_free(m);
                m = t;
        }

        r = 0;

        *rl = m;
        m = NULL;

finish:
        if (f)
                fclose(f);

        strv_free(m);

        return r;
}

int write_env_file(const char *fname, char **l) {
        char **i, *p;
        FILE *f;
        int r;

        r = fopen_temporary(fname, &f, &p);
        if (r < 0)
                return r;

        fchmod_umask(fileno(f), 0644);

        errno = 0;
        STRV_FOREACH(i, l) {
                fputs(*i, f);
                fputc('\n', f);
        }

        fflush(f);

        if (ferror(f)) {
                if (errno != 0)
                        r = -errno;
                else
                        r = -EIO;
        } else {
                if (rename(p, fname) < 0)
                        r = -errno;
                else
                        r = 0;
        }

        if (r < 0)
                unlink(p);

        fclose(f);
        free(p);

        return r;
}

char *truncate_nl(char *s) {
        assert(s);

        s[strcspn(s, NEWLINE)] = 0;
        return s;
}

int get_process_comm(pid_t pid, char **name) {
        int r;

        assert(name);

        if (pid == 0)
                r = read_one_line_file("/proc/self/comm", name);
        else {
                char *p;
                if (asprintf(&p, "/proc/%lu/comm", (unsigned long) pid) < 0)
                        return -ENOMEM;

                r = read_one_line_file(p, name);
                free(p);
        }

        return r;
}

int get_process_cmdline(pid_t pid, size_t max_length, bool comm_fallback, char **line) {
        char *r, *k;
        int c;
        bool space = false;
        size_t left;
        FILE *f;

        assert(max_length > 0);
        assert(line);

        if (pid == 0)
                f = fopen("/proc/self/cmdline", "re");
        else {
                char *p;
                if (asprintf(&p, "/proc/%lu/cmdline", (unsigned long) pid) < 0)
                        return -ENOMEM;

                f = fopen(p, "re");
                free(p);
        }

        if (!f)
                return -errno;

        r = new(char, max_length);
        if (!r) {
                fclose(f);
                return -ENOMEM;
        }

        k = r;
        left = max_length;
        while ((c = getc(f)) != EOF) {

                if (isprint(c)) {
                        if (space) {
                                if (left <= 4)
                                        break;

                                *(k++) = ' ';
                                left--;
                                space = false;
                        }

                        if (left <= 4)
                                break;

                        *(k++) = (char) c;
                        left--;
                }  else
                        space = true;
        }

        if (left <= 4) {
                size_t n = MIN(left-1, 3U);
                memcpy(k, "...", n);
                k[n] = 0;
        } else
                *k = 0;

        fclose(f);

        /* Kernel threads have no argv[] */
        if (r[0] == 0) {
                char *t;
                int h;

                free(r);

                if (!comm_fallback)
                        return -ENOENT;

                h = get_process_comm(pid, &t);
                if (h < 0)
                        return h;

                r = strjoin("[", t, "]", NULL);
                free(t);

                if (!r)
                        return -ENOMEM;
        }

        *line = r;
        return 0;
}

int is_kernel_thread(pid_t pid) {
        char *p;
        size_t count;
        char c;
        bool eof;
        FILE *f;

        if (pid == 0)
                return 0;

        if (asprintf(&p, "/proc/%lu/cmdline", (unsigned long) pid) < 0)
                return -ENOMEM;

        f = fopen(p, "re");
        free(p);

        if (!f)
                return -errno;

        count = fread(&c, 1, 1, f);
        eof = feof(f);
        fclose(f);

        /* Kernel threads have an empty cmdline */

        if (count <= 0)
                return eof ? 1 : -errno;

        return 0;
}

int get_process_exe(pid_t pid, char **name) {
        int r;

        assert(name);

        if (pid == 0)
                r = readlink_malloc("/proc/self/exe", name);
        else {
                char *p;
                if (asprintf(&p, "/proc/%lu/exe", (unsigned long) pid) < 0)
                        return -ENOMEM;

                r = readlink_malloc(p, name);
                free(p);
        }

        return r;
}

static int get_process_id(pid_t pid, const char *field, uid_t *uid) {
        char *p;
        FILE *f;
        int r;

        assert(uid);

        if (pid == 0)
                return getuid();

        if (asprintf(&p, "/proc/%lu/status", (unsigned long) pid) < 0)
                return -ENOMEM;

        f = fopen(p, "re");
        free(p);

        if (!f)
                return -errno;

        while (!feof(f)) {
                char line[LINE_MAX], *l;

                if (!fgets(line, sizeof(line), f)) {
                        if (feof(f))
                                break;

                        r = -errno;
                        goto finish;
                }

                l = strstrip(line);

                if (startswith(l, field)) {
                        l += strlen(field);
                        l += strspn(l, WHITESPACE);

                        l[strcspn(l, WHITESPACE)] = 0;

                        r = parse_uid(l, uid);
                        goto finish;
                }
        }

        r = -EIO;

finish:
        fclose(f);

        return r;
}

int get_process_uid(pid_t pid, uid_t *uid) {
        return get_process_id(pid, "Uid:", uid);
}

int get_process_gid(pid_t pid, gid_t *gid) {
        return get_process_id(pid, "Gid:", gid);
}

char *strnappend(const char *s, const char *suffix, size_t b) {
        size_t a;
        char *r;

        if (!s && !suffix)
                return strdup("");

        if (!s)
                return strndup(suffix, b);

        if (!suffix)
                return strdup(s);

        assert(s);
        assert(suffix);

        a = strlen(s);
        if (b > ((size_t) -1) - a)
                return NULL;

        r = new(char, a+b+1);
        if (!r)
                return NULL;

        memcpy(r, s, a);
        memcpy(r+a, suffix, b);
        r[a+b] = 0;

        return r;
}

char *strappend(const char *s, const char *suffix) {
        return strnappend(s, suffix, suffix ? strlen(suffix) : 0);
}

int readlink_malloc(const char *p, char **r) {
        size_t l = 100;

        assert(p);
        assert(r);

        for (;;) {
                char *c;
                ssize_t n;

                if (!(c = new(char, l)))
                        return -ENOMEM;

                if ((n = readlink(p, c, l-1)) < 0) {
                        int ret = -errno;
                        free(c);
                        return ret;
                }

                if ((size_t) n < l-1) {
                        c[n] = 0;
                        *r = c;
                        return 0;
                }

                free(c);
                l *= 2;
        }
}

int readlink_and_make_absolute(const char *p, char **r) {
        char *target, *k;
        int j;

        assert(p);
        assert(r);

        if ((j = readlink_malloc(p, &target)) < 0)
                return j;

        k = file_in_same_dir(p, target);
        free(target);

        if (!k)
                return -ENOMEM;

        *r = k;
        return 0;
}

int readlink_and_canonicalize(const char *p, char **r) {
        char *t, *s;
        int j;

        assert(p);
        assert(r);

        j = readlink_and_make_absolute(p, &t);
        if (j < 0)
                return j;

        s = canonicalize_file_name(t);
        if (s) {
                free(t);
                *r = s;
        } else
                *r = t;

        path_kill_slashes(*r);

        return 0;
}

int reset_all_signal_handlers(void) {
        int sig;

        for (sig = 1; sig < _NSIG; sig++) {
                struct sigaction sa;

                if (sig == SIGKILL || sig == SIGSTOP)
                        continue;

                zero(sa);
                sa.sa_handler = SIG_DFL;
                sa.sa_flags = SA_RESTART;

                /* On Linux the first two RT signals are reserved by
                 * glibc, and sigaction() will return EINVAL for them. */
                if ((sigaction(sig, &sa, NULL) < 0))
                        if (errno != EINVAL)
                                return -errno;
        }

        return 0;
}

char *strstrip(char *s) {
        char *e;

        /* Drops trailing whitespace. Modifies the string in
         * place. Returns pointer to first non-space character */

        s += strspn(s, WHITESPACE);

        for (e = strchr(s, 0); e > s; e --)
                if (!strchr(WHITESPACE, e[-1]))
                        break;

        *e = 0;

        return s;
}

char *delete_chars(char *s, const char *bad) {
        char *f, *t;

        /* Drops all whitespace, regardless where in the string */

        for (f = s, t = s; *f; f++) {
                if (strchr(bad, *f))
                        continue;

                *(t++) = *f;
        }

        *t = 0;

        return s;
}

bool in_charset(const char *s, const char* charset) {
        const char *i;

        assert(s);
        assert(charset);

        for (i = s; *i; i++)
                if (!strchr(charset, *i))
                        return false;

        return true;
}

char *file_in_same_dir(const char *path, const char *filename) {
        char *e, *r;
        size_t k;

        assert(path);
        assert(filename);

        /* This removes the last component of path and appends
         * filename, unless the latter is absolute anyway or the
         * former isn't */

        if (path_is_absolute(filename))
                return strdup(filename);

        if (!(e = strrchr(path, '/')))
                return strdup(filename);

        k = strlen(filename);
        if (!(r = new(char, e-path+1+k+1)))
                return NULL;

        memcpy(r, path, e-path+1);
        memcpy(r+(e-path)+1, filename, k+1);

        return r;
}

int rmdir_parents(const char *path, const char *stop) {
        size_t l;
        int r = 0;

        assert(path);
        assert(stop);

        l = strlen(path);

        /* Skip trailing slashes */
        while (l > 0 && path[l-1] == '/')
                l--;

        while (l > 0) {
                char *t;

                /* Skip last component */
                while (l > 0 && path[l-1] != '/')
                        l--;

                /* Skip trailing slashes */
                while (l > 0 && path[l-1] == '/')
                        l--;

                if (l <= 0)
                        break;

                if (!(t = strndup(path, l)))
                        return -ENOMEM;

                if (path_startswith(stop, t)) {
                        free(t);
                        return 0;
                }

                r = rmdir(t);
                free(t);

                if (r < 0)
                        if (errno != ENOENT)
                                return -errno;
        }

        return 0;
}


char hexchar(int x) {
        static const char table[16] = "0123456789abcdef";

        return table[x & 15];
}

int unhexchar(char c) {

        if (c >= '0' && c <= '9')
                return c - '0';

        if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;

        if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;

        return -1;
}

char octchar(int x) {
        return '0' + (x & 7);
}

int unoctchar(char c) {

        if (c >= '0' && c <= '7')
                return c - '0';

        return -1;
}

char decchar(int x) {
        return '0' + (x % 10);
}

int undecchar(char c) {

        if (c >= '0' && c <= '9')
                return c - '0';

        return -1;
}

char *cescape(const char *s) {
        char *r, *t;
        const char *f;

        assert(s);

        /* Does C style string escaping. */

        r = new(char, strlen(s)*4 + 1);
        if (!r)
                return NULL;

        for (f = s, t = r; *f; f++)

                switch (*f) {

                case '\a':
                        *(t++) = '\\';
                        *(t++) = 'a';
                        break;
                case '\b':
                        *(t++) = '\\';
                        *(t++) = 'b';
                        break;
                case '\f':
                        *(t++) = '\\';
                        *(t++) = 'f';
                        break;
                case '\n':
                        *(t++) = '\\';
                        *(t++) = 'n';
                        break;
                case '\r':
                        *(t++) = '\\';
                        *(t++) = 'r';
                        break;
                case '\t':
                        *(t++) = '\\';
                        *(t++) = 't';
                        break;
                case '\v':
                        *(t++) = '\\';
                        *(t++) = 'v';
                        break;
                case '\\':
                        *(t++) = '\\';
                        *(t++) = '\\';
                        break;
                case '"':
                        *(t++) = '\\';
                        *(t++) = '"';
                        break;
                case '\'':
                        *(t++) = '\\';
                        *(t++) = '\'';
                        break;

                default:
                        /* For special chars we prefer octal over
                         * hexadecimal encoding, simply because glib's
                         * g_strescape() does the same */
                        if ((*f < ' ') || (*f >= 127)) {
                                *(t++) = '\\';
                                *(t++) = octchar((unsigned char) *f >> 6);
                                *(t++) = octchar((unsigned char) *f >> 3);
                                *(t++) = octchar((unsigned char) *f);
                        } else
                                *(t++) = *f;
                        break;
                }

        *t = 0;

        return r;
}

char *cunescape_length_with_prefix(const char *s, size_t length, const char *prefix) {
        char *r, *t;
        const char *f;
        size_t pl;

        assert(s);

        /* Undoes C style string escaping, and optionally prefixes it. */

        pl = prefix ? strlen(prefix) : 0;

        r = new(char, pl+length+1);
        if (!r)
                return r;

        if (prefix)
                memcpy(r, prefix, pl);

        for (f = s, t = r + pl; f < s + length; f++) {

                if (*f != '\\') {
                        *(t++) = *f;
                        continue;
                }

                f++;

                switch (*f) {

                case 'a':
                        *(t++) = '\a';
                        break;
                case 'b':
                        *(t++) = '\b';
                        break;
                case 'f':
                        *(t++) = '\f';
                        break;
                case 'n':
                        *(t++) = '\n';
                        break;
                case 'r':
                        *(t++) = '\r';
                        break;
                case 't':
                        *(t++) = '\t';
                        break;
                case 'v':
                        *(t++) = '\v';
                        break;
                case '\\':
                        *(t++) = '\\';
                        break;
                case '"':
                        *(t++) = '"';
                        break;
                case '\'':
                        *(t++) = '\'';
                        break;

                case 's':
                        /* This is an extension of the XDG syntax files */
                        *(t++) = ' ';
                        break;

                case 'x': {
                        /* hexadecimal encoding */
                        int a, b;

                        a = unhexchar(f[1]);
                        b = unhexchar(f[2]);

                        if (a < 0 || b < 0) {
                                /* Invalid escape code, let's take it literal then */
                                *(t++) = '\\';
                                *(t++) = 'x';
                        } else {
                                *(t++) = (char) ((a << 4) | b);
                                f += 2;
                        }

                        break;
                }

                case '0':
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7': {
                        /* octal encoding */
                        int a, b, c;

                        a = unoctchar(f[0]);
                        b = unoctchar(f[1]);
                        c = unoctchar(f[2]);

                        if (a < 0 || b < 0 || c < 0) {
                                /* Invalid escape code, let's take it literal then */
                                *(t++) = '\\';
                                *(t++) = f[0];
                        } else {
                                *(t++) = (char) ((a << 6) | (b << 3) | c);
                                f += 2;
                        }

                        break;
                }

                case 0:
                        /* premature end of string.*/
                        *(t++) = '\\';
                        goto finish;

                default:
                        /* Invalid escape code, let's take it literal then */
                        *(t++) = '\\';
                        *(t++) = *f;
                        break;
                }
        }

finish:
        *t = 0;
        return r;
}

char *cunescape_length(const char *s, size_t length) {
        return cunescape_length_with_prefix(s, length, NULL);
}

char *cunescape(const char *s) {
        assert(s);

        return cunescape_length(s, strlen(s));
}

char *xescape(const char *s, const char *bad) {
        char *r, *t;
        const char *f;

        /* Escapes all chars in bad, in addition to \ and all special
         * chars, in \xFF style escaping. May be reversed with
         * cunescape. */

        r = new(char, strlen(s) * 4 + 1);
        if (!r)
                return NULL;

        for (f = s, t = r; *f; f++) {

                if ((*f < ' ') || (*f >= 127) ||
                    (*f == '\\') || strchr(bad, *f)) {
                        *(t++) = '\\';
                        *(t++) = 'x';
                        *(t++) = hexchar(*f >> 4);
                        *(t++) = hexchar(*f);
                } else
                        *(t++) = *f;
        }

        *t = 0;

        return r;
}

char *bus_path_escape(const char *s) {
        char *r, *t;
        const char *f;

        assert(s);

        /* Escapes all chars that D-Bus' object path cannot deal
         * with. Can be reverse with bus_path_unescape() */

        if (!(r = new(char, strlen(s)*3+1)))
                return NULL;

        for (f = s, t = r; *f; f++) {

                if (!(*f >= 'A' && *f <= 'Z') &&
                    !(*f >= 'a' && *f <= 'z') &&
                    !(*f >= '0' && *f <= '9')) {
                        *(t++) = '_';
                        *(t++) = hexchar(*f >> 4);
                        *(t++) = hexchar(*f);
                } else
                        *(t++) = *f;
        }

        *t = 0;

        return r;
}

char *bus_path_unescape(const char *f) {
        char *r, *t;

        assert(f);

        if (!(r = strdup(f)))
                return NULL;

        for (t = r; *f; f++) {

                if (*f == '_') {
                        int a, b;

                        if ((a = unhexchar(f[1])) < 0 ||
                            (b = unhexchar(f[2])) < 0) {
                                /* Invalid escape code, let's take it literal then */
                                *(t++) = '_';
                        } else {
                                *(t++) = (char) ((a << 4) | b);
                                f += 2;
                        }
                } else
                        *(t++) = *f;
        }

        *t = 0;

        return r;
}

char *ascii_strlower(char *t) {
        char *p;

        assert(t);

        for (p = t; *p; p++)
                if (*p >= 'A' && *p <= 'Z')
                        *p = *p - 'A' + 'a';

        return t;
}

static bool ignore_file_allow_backup(const char *filename) {
        assert(filename);

        return
                filename[0] == '.' ||
                streq(filename, "lost+found") ||
                streq(filename, "aquota.user") ||
                streq(filename, "aquota.group") ||
                endswith(filename, ".rpmnew") ||
                endswith(filename, ".rpmsave") ||
                endswith(filename, ".rpmorig") ||
                endswith(filename, ".dpkg-old") ||
                endswith(filename, ".dpkg-new") ||
                endswith(filename, ".swp");
}

bool ignore_file(const char *filename) {
        assert(filename);

        if (endswith(filename, "~"))
                return false;

        return ignore_file_allow_backup(filename);
}

int fd_nonblock(int fd, bool nonblock) {
        int flags;

        assert(fd >= 0);

        if ((flags = fcntl(fd, F_GETFL, 0)) < 0)
                return -errno;

        if (nonblock)
                flags |= O_NONBLOCK;
        else
                flags &= ~O_NONBLOCK;

        if (fcntl(fd, F_SETFL, flags) < 0)
                return -errno;

        return 0;
}

int fd_cloexec(int fd, bool cloexec) {
        int flags;

        assert(fd >= 0);

        if ((flags = fcntl(fd, F_GETFD, 0)) < 0)
                return -errno;

        if (cloexec)
                flags |= FD_CLOEXEC;
        else
                flags &= ~FD_CLOEXEC;

        if (fcntl(fd, F_SETFD, flags) < 0)
                return -errno;

        return 0;
}

static bool fd_in_set(int fd, const int fdset[], unsigned n_fdset) {
        unsigned i;

        assert(n_fdset == 0 || fdset);

        for (i = 0; i < n_fdset; i++)
                if (fdset[i] == fd)
                        return true;

        return false;
}

int close_all_fds(const int except[], unsigned n_except) {
        DIR *d;
        struct dirent *de;
        int r = 0;

        assert(n_except == 0 || except);

        d = opendir("/proc/self/fd");
        if (!d) {
                int fd;
                struct rlimit rl;

                /* When /proc isn't available (for example in chroots)
                 * the fallback is brute forcing through the fd
                 * table */

                assert_se(getrlimit(RLIMIT_NOFILE, &rl) >= 0);
                for (fd = 3; fd < (int) rl.rlim_max; fd ++) {

                        if (fd_in_set(fd, except, n_except))
                                continue;

                        if (close_nointr(fd) < 0)
                                if (errno != EBADF && r == 0)
                                        r = -errno;
                }

                return r;
        }

        while ((de = readdir(d))) {
                int fd = -1;

                if (ignore_file(de->d_name))
                        continue;

                if (safe_atoi(de->d_name, &fd) < 0)
                        /* Let's better ignore this, just in case */
                        continue;

                if (fd < 3)
                        continue;

                if (fd == dirfd(d))
                        continue;

                if (fd_in_set(fd, except, n_except))
                        continue;

                if (close_nointr(fd) < 0) {
                        /* Valgrind has its own FD and doesn't want to have it closed */
                        if (errno != EBADF && r == 0)
                                r = -errno;
                }
        }

        closedir(d);
        return r;
}

bool chars_intersect(const char *a, const char *b) {
        const char *p;

        /* Returns true if any of the chars in a are in b. */
        for (p = a; *p; p++)
                if (strchr(b, *p))
                        return true;

        return false;
}

char *format_timestamp(char *buf, size_t l, usec_t t) {
        struct tm tm;
        time_t sec;

        assert(buf);
        assert(l > 0);

        if (t <= 0)
                return NULL;

        sec = (time_t) (t / USEC_PER_SEC);

        if (strftime(buf, l, "%a, %Y-%m-%d %H:%M:%S %Z", localtime_r(&sec, &tm)) <= 0)
                return NULL;

        return buf;
}

char *format_timestamp_pretty(char *buf, size_t l, usec_t t) {
        usec_t n, d;

        n = now(CLOCK_REALTIME);

        if (t <= 0 || t > n || t + USEC_PER_DAY*7 <= t)
                return NULL;

        d = n - t;

        if (d >= USEC_PER_YEAR)
                snprintf(buf, l, "%llu years and %llu months ago",
                         (unsigned long long) (d / USEC_PER_YEAR),
                         (unsigned long long) ((d % USEC_PER_YEAR) / USEC_PER_MONTH));
        else if (d >= USEC_PER_MONTH)
                snprintf(buf, l, "%llu months and %llu days ago",
                         (unsigned long long) (d / USEC_PER_MONTH),
                         (unsigned long long) ((d % USEC_PER_MONTH) / USEC_PER_DAY));
        else if (d >= USEC_PER_WEEK)
                snprintf(buf, l, "%llu weeks and %llu days ago",
                         (unsigned long long) (d / USEC_PER_WEEK),
                         (unsigned long long) ((d % USEC_PER_WEEK) / USEC_PER_DAY));
        else if (d >= 2*USEC_PER_DAY)
                snprintf(buf, l, "%llu days ago", (unsigned long long) (d / USEC_PER_DAY));
        else if (d >= 25*USEC_PER_HOUR)
                snprintf(buf, l, "1 day and %lluh ago",
                         (unsigned long long) ((d - USEC_PER_DAY) / USEC_PER_HOUR));
        else if (d >= 6*USEC_PER_HOUR)
                snprintf(buf, l, "%lluh ago",
                         (unsigned long long) (d / USEC_PER_HOUR));
        else if (d >= USEC_PER_HOUR)
                snprintf(buf, l, "%lluh %llumin ago",
                         (unsigned long long) (d / USEC_PER_HOUR),
                         (unsigned long long) ((d % USEC_PER_HOUR) / USEC_PER_MINUTE));
        else if (d >= 5*USEC_PER_MINUTE)
                snprintf(buf, l, "%llumin ago",
                         (unsigned long long) (d / USEC_PER_MINUTE));
        else if (d >= USEC_PER_MINUTE)
                snprintf(buf, l, "%llumin %llus ago",
                         (unsigned long long) (d / USEC_PER_MINUTE),
                         (unsigned long long) ((d % USEC_PER_MINUTE) / USEC_PER_SEC));
        else if (d >= USEC_PER_SEC)
                snprintf(buf, l, "%llus ago",
                         (unsigned long long) (d / USEC_PER_SEC));
        else if (d >= USEC_PER_MSEC)
                snprintf(buf, l, "%llums ago",
                         (unsigned long long) (d / USEC_PER_MSEC));
        else if (d > 0)
                snprintf(buf, l, "%lluus ago",
                         (unsigned long long) d);
        else
                snprintf(buf, l, "now");

        buf[l-1] = 0;
        return buf;
}

char *format_timespan(char *buf, size_t l, usec_t t) {
        static const struct {
                const char *suffix;
                usec_t usec;
        } table[] = {
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

        assert(buf);
        assert(l > 0);

        if (t == (usec_t) -1)
                return NULL;

        if (t == 0) {
                snprintf(p, l, "0");
                p[l-1] = 0;
                return p;
        }

        /* The result of this function can be parsed with parse_usec */

        for (i = 0; i < ELEMENTSOF(table); i++) {
                int k;
                size_t n;

                if (t < table[i].usec)
                        continue;

                if (l <= 1)
                        break;

                k = snprintf(p, l, "%s%llu%s", p > buf ? " " : "", (unsigned long long) (t / table[i].usec), table[i].suffix);
                n = MIN((size_t) k, l);

                l -= n;
                p += n;

                t %= table[i].usec;
        }

        *p = 0;

        return buf;
}

bool fstype_is_network(const char *fstype) {
        static const char table[] =
                "cifs\0"
                "smbfs\0"
                "ncpfs\0"
                "nfs\0"
                "nfs4\0"
                "gfs\0"
                "gfs2\0";

        return nulstr_contains(table, fstype);
}

int chvt(int vt) {
        _cleanup_close_ int fd;

        fd = open_terminal("/dev/tty0", O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        if (vt < 0) {
                int tiocl[2] = {
                        TIOCL_GETKMSGREDIRECT,
                        0
                };

                if (ioctl(fd, TIOCLINUX, tiocl) < 0)
                        return -errno;

                vt = tiocl[0] <= 0 ? 1 : tiocl[0];
        }

        if (ioctl(fd, VT_ACTIVATE, vt) < 0)
                return -errno;

        return 0;
}

int read_one_char(FILE *f, char *ret, usec_t t, bool *need_nl) {
        struct termios old_termios, new_termios;
        char c;
        char line[LINE_MAX];

        assert(f);
        assert(ret);

        if (tcgetattr(fileno(f), &old_termios) >= 0) {
                new_termios = old_termios;

                new_termios.c_lflag &= ~ICANON;
                new_termios.c_cc[VMIN] = 1;
                new_termios.c_cc[VTIME] = 0;

                if (tcsetattr(fileno(f), TCSADRAIN, &new_termios) >= 0) {
                        size_t k;

                        if (t != (usec_t) -1) {
                                if (fd_wait_for_event(fileno(f), POLLIN, t) <= 0) {
                                        tcsetattr(fileno(f), TCSADRAIN, &old_termios);
                                        return -ETIMEDOUT;
                                }
                        }

                        k = fread(&c, 1, 1, f);

                        tcsetattr(fileno(f), TCSADRAIN, &old_termios);

                        if (k <= 0)
                                return -EIO;

                        if (need_nl)
                                *need_nl = c != '\n';

                        *ret = c;
                        return 0;
                }
        }

        if (t != (usec_t) -1)
                if (fd_wait_for_event(fileno(f), POLLIN, t) <= 0)
                        return -ETIMEDOUT;

        if (!fgets(line, sizeof(line), f))
                return -EIO;

        truncate_nl(line);

        if (strlen(line) != 1)
                return -EBADMSG;

        if (need_nl)
                *need_nl = false;

        *ret = line[0];
        return 0;
}

int ask(char *ret, const char *replies, const char *text, ...) {

        assert(ret);
        assert(replies);
        assert(text);

        for (;;) {
                va_list ap;
                char c;
                int r;
                bool need_nl = true;

                if (on_tty())
                        fputs(ANSI_HIGHLIGHT_ON, stdout);

                va_start(ap, text);
                vprintf(text, ap);
                va_end(ap);

                if (on_tty())
                        fputs(ANSI_HIGHLIGHT_OFF, stdout);

                fflush(stdout);

                r = read_one_char(stdin, &c, (usec_t) -1, &need_nl);
                if (r < 0) {

                        if (r == -EBADMSG) {
                                puts("Bad input, please try again.");
                                continue;
                        }

                        putchar('\n');
                        return r;
                }

                if (need_nl)
                        putchar('\n');

                if (strchr(replies, c)) {
                        *ret = c;
                        return 0;
                }

                puts("Read unexpected character, please try again.");
        }
}

int reset_terminal_fd(int fd, bool switch_to_text) {
        struct termios termios;
        int r = 0;

        /* Set terminal to some sane defaults */

        assert(fd >= 0);

        /* We leave locked terminal attributes untouched, so that
         * Plymouth may set whatever it wants to set, and we don't
         * interfere with that. */

        /* Disable exclusive mode, just in case */
        ioctl(fd, TIOCNXCL);

        /* Switch to text mode */
        if (switch_to_text)
                ioctl(fd, KDSETMODE, KD_TEXT);

        /* Enable console unicode mode */
        ioctl(fd, KDSKBMODE, K_UNICODE);

        if (tcgetattr(fd, &termios) < 0) {
                r = -errno;
                goto finish;
        }

        /* We only reset the stuff that matters to the software. How
         * hardware is set up we don't touch assuming that somebody
         * else will do that for us */

        termios.c_iflag &= ~(IGNBRK | BRKINT | ISTRIP | INLCR | IGNCR | IUCLC);
        termios.c_iflag |= ICRNL | IMAXBEL | IUTF8;
        termios.c_oflag |= ONLCR;
        termios.c_cflag |= CREAD;
        termios.c_lflag = ISIG | ICANON | IEXTEN | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOPRT | ECHOKE;

        termios.c_cc[VINTR]    =   03;  /* ^C */
        termios.c_cc[VQUIT]    =  034;  /* ^\ */
        termios.c_cc[VERASE]   = 0177;
        termios.c_cc[VKILL]    =  025;  /* ^X */
        termios.c_cc[VEOF]     =   04;  /* ^D */
        termios.c_cc[VSTART]   =  021;  /* ^Q */
        termios.c_cc[VSTOP]    =  023;  /* ^S */
        termios.c_cc[VSUSP]    =  032;  /* ^Z */
        termios.c_cc[VLNEXT]   =  026;  /* ^V */
        termios.c_cc[VWERASE]  =  027;  /* ^W */
        termios.c_cc[VREPRINT] =  022;  /* ^R */
        termios.c_cc[VEOL]     =    0;
        termios.c_cc[VEOL2]    =    0;

        termios.c_cc[VTIME]  = 0;
        termios.c_cc[VMIN]   = 1;

        if (tcsetattr(fd, TCSANOW, &termios) < 0)
                r = -errno;

finish:
        /* Just in case, flush all crap out */
        tcflush(fd, TCIOFLUSH);

        return r;
}

int reset_terminal(const char *name) {
        int fd, r;

        fd = open_terminal(name, O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return fd;

        r = reset_terminal_fd(fd, true);
        close_nointr_nofail(fd);

        return r;
}

int open_terminal(const char *name, int mode) {
        int fd, r;
        unsigned c = 0;

        /*
         * If a TTY is in the process of being closed opening it might
         * cause EIO. This is horribly awful, but unlikely to be
         * changed in the kernel. Hence we work around this problem by
         * retrying a couple of times.
         *
         * https://bugs.launchpad.net/ubuntu/+source/linux/+bug/554172/comments/245
         */

        for (;;) {
                fd = open(name, mode);
                if (fd >= 0)
                        break;

                if (errno != EIO)
                        return -errno;

                /* Max 1s in total */
                if (c >= 20)
                        return -errno;

                usleep(50 * USEC_PER_MSEC);
                c++;
        }

        if (fd < 0)
                return -errno;

        r = isatty(fd);
        if (r < 0) {
                close_nointr_nofail(fd);
                return -errno;
        }

        if (!r) {
                close_nointr_nofail(fd);
                return -ENOTTY;
        }

        return fd;
}

int flush_fd(int fd) {
        struct pollfd pollfd;

        zero(pollfd);
        pollfd.fd = fd;
        pollfd.events = POLLIN;

        for (;;) {
                char buf[LINE_MAX];
                ssize_t l;
                int r;

                if ((r = poll(&pollfd, 1, 0)) < 0) {

                        if (errno == EINTR)
                                continue;

                        return -errno;
                }

                if (r == 0)
                        return 0;

                if ((l = read(fd, buf, sizeof(buf))) < 0) {

                        if (errno == EINTR)
                                continue;

                        if (errno == EAGAIN)
                                return 0;

                        return -errno;
                }

                if (l <= 0)
                        return 0;
        }
}

int acquire_terminal(
                const char *name,
                bool fail,
                bool force,
                bool ignore_tiocstty_eperm,
                usec_t timeout) {

        int fd = -1, notify = -1, r = 0, wd = -1;
        usec_t ts = 0;
        struct sigaction sa_old, sa_new;

        assert(name);

        /* We use inotify to be notified when the tty is closed. We
         * create the watch before checking if we can actually acquire
         * it, so that we don't lose any event.
         *
         * Note: strictly speaking this actually watches for the
         * device being closed, it does *not* really watch whether a
         * tty loses its controlling process. However, unless some
         * rogue process uses TIOCNOTTY on /dev/tty *after* closing
         * its tty otherwise this will not become a problem. As long
         * as the administrator makes sure not configure any service
         * on the same tty as an untrusted user this should not be a
         * problem. (Which he probably should not do anyway.) */

        if (timeout != (usec_t) -1)
                ts = now(CLOCK_MONOTONIC);

        if (!fail && !force) {
                notify = inotify_init1(IN_CLOEXEC | (timeout != (usec_t) -1 ? IN_NONBLOCK : 0));
                if (notify < 0) {
                        r = -errno;
                        goto fail;
                }

                wd = inotify_add_watch(notify, name, IN_CLOSE);
                if (wd < 0) {
                        r = -errno;
                        goto fail;
                }
        }

        for (;;) {
                if (notify >= 0) {
                        r = flush_fd(notify);
                        if (r < 0)
                                goto fail;
                }

                /* We pass here O_NOCTTY only so that we can check the return
                 * value TIOCSCTTY and have a reliable way to figure out if we
                 * successfully became the controlling process of the tty */
                fd = open_terminal(name, O_RDWR|O_NOCTTY|O_CLOEXEC);
                if (fd < 0)
                        return fd;

                /* Temporarily ignore SIGHUP, so that we don't get SIGHUP'ed
                 * if we already own the tty. */
                zero(sa_new);
                sa_new.sa_handler = SIG_IGN;
                sa_new.sa_flags = SA_RESTART;
                assert_se(sigaction(SIGHUP, &sa_new, &sa_old) == 0);

                /* First, try to get the tty */
                if (ioctl(fd, TIOCSCTTY, force) < 0)
                        r = -errno;

                assert_se(sigaction(SIGHUP, &sa_old, NULL) == 0);

                /* Sometimes it makes sense to ignore TIOCSCTTY
                 * returning EPERM, i.e. when very likely we already
                 * are have this controlling terminal. */
                if (r < 0 && r == -EPERM && ignore_tiocstty_eperm)
                        r = 0;

                if (r < 0 && (force || fail || r != -EPERM)) {
                        goto fail;
                }

                if (r >= 0)
                        break;

                assert(!fail);
                assert(!force);
                assert(notify >= 0);

                for (;;) {
                        uint8_t inotify_buffer[sizeof(struct inotify_event) + FILENAME_MAX];
                        ssize_t l;
                        struct inotify_event *e;

                        if (timeout != (usec_t) -1) {
                                usec_t n;

                                n = now(CLOCK_MONOTONIC);
                                if (ts + timeout < n) {
                                        r = -ETIMEDOUT;
                                        goto fail;
                                }

                                r = fd_wait_for_event(fd, POLLIN, ts + timeout - n);
                                if (r < 0)
                                        goto fail;

                                if (r == 0) {
                                        r = -ETIMEDOUT;
                                        goto fail;
                                }
                        }

                        l = read(notify, inotify_buffer, sizeof(inotify_buffer));
                        if (l < 0) {

                                if (errno == EINTR || errno == EAGAIN)
                                        continue;

                                r = -errno;
                                goto fail;
                        }

                        e = (struct inotify_event*) inotify_buffer;

                        while (l > 0) {
                                size_t step;

                                if (e->wd != wd || !(e->mask & IN_CLOSE)) {
                                        r = -EIO;
                                        goto fail;
                                }

                                step = sizeof(struct inotify_event) + e->len;
                                assert(step <= (size_t) l);

                                e = (struct inotify_event*) ((uint8_t*) e + step);
                                l -= step;
                        }

                        break;
                }

                /* We close the tty fd here since if the old session
                 * ended our handle will be dead. It's important that
                 * we do this after sleeping, so that we don't enter
                 * an endless loop. */
                close_nointr_nofail(fd);
        }

        if (notify >= 0)
                close_nointr_nofail(notify);

        r = reset_terminal_fd(fd, true);
        if (r < 0)
                log_warning("Failed to reset terminal: %s", strerror(-r));

        return fd;

fail:
        if (fd >= 0)
                close_nointr_nofail(fd);

        if (notify >= 0)
                close_nointr_nofail(notify);

        return r;
}

int release_terminal(void) {
        int r = 0, fd;
        struct sigaction sa_old, sa_new;

        if ((fd = open("/dev/tty", O_RDWR|O_NOCTTY|O_NDELAY|O_CLOEXEC)) < 0)
                return -errno;

        /* Temporarily ignore SIGHUP, so that we don't get SIGHUP'ed
         * by our own TIOCNOTTY */

        zero(sa_new);
        sa_new.sa_handler = SIG_IGN;
        sa_new.sa_flags = SA_RESTART;
        assert_se(sigaction(SIGHUP, &sa_new, &sa_old) == 0);

        if (ioctl(fd, TIOCNOTTY) < 0)
                r = -errno;

        assert_se(sigaction(SIGHUP, &sa_old, NULL) == 0);

        close_nointr_nofail(fd);
        return r;
}

int sigaction_many(const struct sigaction *sa, ...) {
        va_list ap;
        int r = 0, sig;

        va_start(ap, sa);
        while ((sig = va_arg(ap, int)) > 0)
                if (sigaction(sig, sa, NULL) < 0)
                        r = -errno;
        va_end(ap);

        return r;
}

int ignore_signals(int sig, ...) {
        struct sigaction sa;
        va_list ap;
        int r = 0;

        zero(sa);
        sa.sa_handler = SIG_IGN;
        sa.sa_flags = SA_RESTART;

        if (sigaction(sig, &sa, NULL) < 0)
                r = -errno;

        va_start(ap, sig);
        while ((sig = va_arg(ap, int)) > 0)
                if (sigaction(sig, &sa, NULL) < 0)
                        r = -errno;
        va_end(ap);

        return r;
}

int default_signals(int sig, ...) {
        struct sigaction sa;
        va_list ap;
        int r = 0;

        zero(sa);
        sa.sa_handler = SIG_DFL;
        sa.sa_flags = SA_RESTART;

        if (sigaction(sig, &sa, NULL) < 0)
                r = -errno;

        va_start(ap, sig);
        while ((sig = va_arg(ap, int)) > 0)
                if (sigaction(sig, &sa, NULL) < 0)
                        r = -errno;
        va_end(ap);

        return r;
}

int close_pipe(int p[]) {
        int a = 0, b = 0;

        assert(p);

        if (p[0] >= 0) {
                a = close_nointr(p[0]);
                p[0] = -1;
        }

        if (p[1] >= 0) {
                b = close_nointr(p[1]);
                p[1] = -1;
        }

        return a < 0 ? a : b;
}

ssize_t loop_read(int fd, void *buf, size_t nbytes, bool do_poll) {
        uint8_t *p;
        ssize_t n = 0;

        assert(fd >= 0);
        assert(buf);

        p = buf;

        while (nbytes > 0) {
                ssize_t k;

                if ((k = read(fd, p, nbytes)) <= 0) {

                        if (k < 0 && errno == EINTR)
                                continue;

                        if (k < 0 && errno == EAGAIN && do_poll) {
                                struct pollfd pollfd;

                                zero(pollfd);
                                pollfd.fd = fd;
                                pollfd.events = POLLIN;

                                if (poll(&pollfd, 1, -1) < 0) {
                                        if (errno == EINTR)
                                                continue;

                                        return n > 0 ? n : -errno;
                                }

                                if (pollfd.revents != POLLIN)
                                        return n > 0 ? n : -EIO;

                                continue;
                        }

                        return n > 0 ? n : (k < 0 ? -errno : 0);
                }

                p += k;
                nbytes -= k;
                n += k;
        }

        return n;
}

ssize_t loop_write(int fd, const void *buf, size_t nbytes, bool do_poll) {
        const uint8_t *p;
        ssize_t n = 0;

        assert(fd >= 0);
        assert(buf);

        p = buf;

        while (nbytes > 0) {
                ssize_t k;

                k = write(fd, p, nbytes);
                if (k <= 0) {

                        if (k < 0 && errno == EINTR)
                                continue;

                        if (k < 0 && errno == EAGAIN && do_poll) {
                                struct pollfd pollfd;

                                zero(pollfd);
                                pollfd.fd = fd;
                                pollfd.events = POLLOUT;

                                if (poll(&pollfd, 1, -1) < 0) {
                                        if (errno == EINTR)
                                                continue;

                                        return n > 0 ? n : -errno;
                                }

                                if (pollfd.revents != POLLOUT)
                                        return n > 0 ? n : -EIO;

                                continue;
                        }

                        return n > 0 ? n : (k < 0 ? -errno : 0);
                }

                p += k;
                nbytes -= k;
                n += k;
        }

        return n;
}

int parse_usec(const char *t, usec_t *usec) {
        static const struct {
                const char *suffix;
                usec_t usec;
        } table[] = {
                { "seconds", USEC_PER_SEC },
                { "second", USEC_PER_SEC },
                { "sec", USEC_PER_SEC },
                { "s", USEC_PER_SEC },
                { "minutes", USEC_PER_MINUTE },
                { "minute", USEC_PER_MINUTE },
                { "min", USEC_PER_MINUTE },
                { "months", USEC_PER_MONTH },
                { "month", USEC_PER_MONTH },
                { "msec", USEC_PER_MSEC },
                { "ms", USEC_PER_MSEC },
                { "m", USEC_PER_MINUTE },
                { "hours", USEC_PER_HOUR },
                { "hour", USEC_PER_HOUR },
                { "hr", USEC_PER_HOUR },
                { "h", USEC_PER_HOUR },
                { "days", USEC_PER_DAY },
                { "day", USEC_PER_DAY },
                { "d", USEC_PER_DAY },
                { "weeks", USEC_PER_WEEK },
                { "week", USEC_PER_WEEK },
                { "w", USEC_PER_WEEK },
                { "years", USEC_PER_YEAR },
                { "year", USEC_PER_YEAR },
                { "y", USEC_PER_YEAR },
                { "usec", 1ULL },
                { "us", 1ULL },
                { "", USEC_PER_SEC }, /* default is sec */
        };

        const char *p;
        usec_t r = 0;

        assert(t);
        assert(usec);

        p = t;
        do {
                long long l;
                char *e;
                unsigned i;

                errno = 0;
                l = strtoll(p, &e, 10);

                if (errno != 0)
                        return -errno;

                if (l < 0)
                        return -ERANGE;

                if (e == p)
                        return -EINVAL;

                e += strspn(e, WHITESPACE);

                for (i = 0; i < ELEMENTSOF(table); i++)
                        if (startswith(e, table[i].suffix)) {
                                r += (usec_t) l * table[i].usec;
                                p = e + strlen(table[i].suffix);
                                break;
                        }

                if (i >= ELEMENTSOF(table))
                        return -EINVAL;

        } while (*p != 0);

        *usec = r;

        return 0;
}

int parse_nsec(const char *t, nsec_t *nsec) {
        static const struct {
                const char *suffix;
                nsec_t nsec;
        } table[] = {
                { "seconds", NSEC_PER_SEC },
                { "second", NSEC_PER_SEC },
                { "sec", NSEC_PER_SEC },
                { "s", NSEC_PER_SEC },
                { "minutes", NSEC_PER_MINUTE },
                { "minute", NSEC_PER_MINUTE },
                { "min", NSEC_PER_MINUTE },
                { "months", NSEC_PER_MONTH },
                { "month", NSEC_PER_MONTH },
                { "msec", NSEC_PER_MSEC },
                { "ms", NSEC_PER_MSEC },
                { "m", NSEC_PER_MINUTE },
                { "hours", NSEC_PER_HOUR },
                { "hour", NSEC_PER_HOUR },
                { "hr", NSEC_PER_HOUR },
                { "h", NSEC_PER_HOUR },
                { "days", NSEC_PER_DAY },
                { "day", NSEC_PER_DAY },
                { "d", NSEC_PER_DAY },
                { "weeks", NSEC_PER_WEEK },
                { "week", NSEC_PER_WEEK },
                { "w", NSEC_PER_WEEK },
                { "years", NSEC_PER_YEAR },
                { "year", NSEC_PER_YEAR },
                { "y", NSEC_PER_YEAR },
                { "usec", NSEC_PER_USEC },
                { "us", NSEC_PER_USEC },
                { "nsec", 1ULL },
                { "ns", 1ULL },
                { "", 1ULL }, /* default is nsec */
        };

        const char *p;
        nsec_t r = 0;

        assert(t);
        assert(nsec);

        p = t;
        do {
                long long l;
                char *e;
                unsigned i;

                errno = 0;
                l = strtoll(p, &e, 10);

                if (errno != 0)
                        return -errno;

                if (l < 0)
                        return -ERANGE;

                if (e == p)
                        return -EINVAL;

                e += strspn(e, WHITESPACE);

                for (i = 0; i < ELEMENTSOF(table); i++)
                        if (startswith(e, table[i].suffix)) {
                                r += (nsec_t) l * table[i].nsec;
                                p = e + strlen(table[i].suffix);
                                break;
                        }

                if (i >= ELEMENTSOF(table))
                        return -EINVAL;

        } while (*p != 0);

        *nsec = r;

        return 0;
}

int parse_bytes(const char *t, off_t *bytes) {
        static const struct {
                const char *suffix;
                off_t factor;
        } table[] = {
                { "B", 1 },
                { "K", 1024ULL },
                { "M", 1024ULL*1024ULL },
                { "G", 1024ULL*1024ULL*1024ULL },
                { "T", 1024ULL*1024ULL*1024ULL*1024ULL },
                { "P", 1024ULL*1024ULL*1024ULL*1024ULL*1024ULL },
                { "E", 1024ULL*1024ULL*1024ULL*1024ULL*1024ULL*1024ULL },
                { "", 1 },
        };

        const char *p;
        off_t r = 0;

        assert(t);
        assert(bytes);

        p = t;
        do {
                long long l;
                char *e;
                unsigned i;

                errno = 0;
                l = strtoll(p, &e, 10);

                if (errno != 0)
                        return -errno;

                if (l < 0)
                        return -ERANGE;

                if (e == p)
                        return -EINVAL;

                e += strspn(e, WHITESPACE);

                for (i = 0; i < ELEMENTSOF(table); i++)
                        if (startswith(e, table[i].suffix)) {
                                r += (off_t) l * table[i].factor;
                                p = e + strlen(table[i].suffix);
                                break;
                        }

                if (i >= ELEMENTSOF(table))
                        return -EINVAL;

        } while (*p != 0);

        *bytes = r;

        return 0;
}

int make_stdio(int fd) {
        int r, s, t;

        assert(fd >= 0);

        r = dup2(fd, STDIN_FILENO);
        s = dup2(fd, STDOUT_FILENO);
        t = dup2(fd, STDERR_FILENO);

        if (fd >= 3)
                close_nointr_nofail(fd);

        if (r < 0 || s < 0 || t < 0)
                return -errno;

        /* We rely here that the new fd has O_CLOEXEC not set */

        return 0;
}

int make_null_stdio(void) {
        int null_fd;

        null_fd = open("/dev/null", O_RDWR|O_NOCTTY);
        if (null_fd < 0)
                return -errno;

        return make_stdio(null_fd);
}

bool is_device_path(const char *path) {

        /* Returns true on paths that refer to a device, either in
         * sysfs or in /dev */

        return
                path_startswith(path, "/dev/") ||
                path_startswith(path, "/sys/");
}

int dir_is_empty(const char *path) {
        _cleanup_closedir_ DIR *d;
        int r;

        d = opendir(path);
        if (!d)
                return -errno;

        for (;;) {
                struct dirent *de;
                union dirent_storage buf;

                r = readdir_r(d, &buf.de, &de);
                if (r > 0)
                        return -r;

                if (!de)
                        return 1;

                if (!ignore_file(de->d_name))
                        return 0;
        }
}

unsigned long long random_ull(void) {
        _cleanup_close_ int fd;
        uint64_t ull;
        ssize_t r;

        fd = open("/dev/urandom", O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0)
                goto fallback;

        r = loop_read(fd, &ull, sizeof(ull), true);
        if (r != sizeof(ull))
                goto fallback;

        return ull;

fallback:
        return random() * RAND_MAX + random();
}

void rename_process(const char name[8]) {
        assert(name);

        /* This is a like a poor man's setproctitle(). It changes the
         * comm field, argv[0], and also the glibc's internally used
         * name of the process. For the first one a limit of 16 chars
         * applies, to the second one usually one of 10 (i.e. length
         * of "/sbin/init"), to the third one one of 7 (i.e. length of
         * "systemd"). If you pass a longer string it will be
         * truncated */

        prctl(PR_SET_NAME, name);

        if (program_invocation_name)
                strncpy(program_invocation_name, name, strlen(program_invocation_name));

        if (saved_argc > 0) {
                int i;

                if (saved_argv[0])
                        strncpy(saved_argv[0], name, strlen(saved_argv[0]));

                for (i = 1; i < saved_argc; i++) {
                        if (!saved_argv[i])
                                break;

                        memset(saved_argv[i], 0, strlen(saved_argv[i]));
                }
        }
}

void sigset_add_many(sigset_t *ss, ...) {
        va_list ap;
        int sig;

        assert(ss);

        va_start(ap, ss);
        while ((sig = va_arg(ap, int)) > 0)
                assert_se(sigaddset(ss, sig) == 0);
        va_end(ap);
}

char* gethostname_malloc(void) {
        struct utsname u;

        assert_se(uname(&u) >= 0);

        if (!isempty(u.nodename) && !streq(u.nodename, "(none)"))
                return strdup(u.nodename);

        return strdup(u.sysname);
}

bool hostname_is_set(void) {
        struct utsname u;

        assert_se(uname(&u) >= 0);

        return !isempty(u.nodename) && !streq(u.nodename, "(none)");
}

static char *lookup_uid(uid_t uid) {
        long bufsize;
        char *name;
        _cleanup_free_ char *buf = NULL;
        struct passwd pwbuf, *pw = NULL;

        /* Shortcut things to avoid NSS lookups */
        if (uid == 0)
                return strdup("root");

        bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
        if (bufsize <= 0)
                bufsize = 4096;

        buf = malloc(bufsize);
        if (!buf)
                return NULL;

        if (getpwuid_r(uid, &pwbuf, buf, bufsize, &pw) == 0 && pw)
                return strdup(pw->pw_name);

        if (asprintf(&name, "%lu", (unsigned long) uid) < 0)
                return NULL;

        return name;
}

char* getlogname_malloc(void) {
        uid_t uid;
        struct stat st;

        if (isatty(STDIN_FILENO) && fstat(STDIN_FILENO, &st) >= 0)
                uid = st.st_uid;
        else
                uid = getuid();

        return lookup_uid(uid);
}

char *getusername_malloc(void) {
        const char *e;

        e = getenv("USER");
        if (e)
                return strdup(e);

        return lookup_uid(getuid());
}

int getttyname_malloc(int fd, char **r) {
        char path[PATH_MAX], *c;
        int k;

        assert(r);

        k = ttyname_r(fd, path, sizeof(path));
        if (k != 0)
                return -k;

        char_array_0(path);

        c = strdup(startswith(path, "/dev/") ? path + 5 : path);
        if (!c)
                return -ENOMEM;

        *r = c;
        return 0;
}

int getttyname_harder(int fd, char **r) {
        int k;
        char *s;

        k = getttyname_malloc(fd, &s);
        if (k < 0)
                return k;

        if (streq(s, "tty")) {
                free(s);
                return get_ctty(0, NULL, r);
        }

        *r = s;
        return 0;
}

int get_ctty_devnr(pid_t pid, dev_t *d) {
        int k;
        char line[LINE_MAX], *p, *fn;
        unsigned long ttynr;
        FILE *f;

        if (asprintf(&fn, "/proc/%lu/stat", (unsigned long) (pid <= 0 ? getpid() : pid)) < 0)
                return -ENOMEM;

        f = fopen(fn, "re");
        free(fn);
        if (!f)
                return -errno;

        if (!fgets(line, sizeof(line), f)) {
                k = feof(f) ? -EIO : -errno;
                fclose(f);
                return k;
        }

        fclose(f);

        p = strrchr(line, ')');
        if (!p)
                return -EIO;

        p++;

        if (sscanf(p, " "
                   "%*c "  /* state */
                   "%*d "  /* ppid */
                   "%*d "  /* pgrp */
                   "%*d "  /* session */
                   "%lu ", /* ttynr */
                   &ttynr) != 1)
                return -EIO;

        *d = (dev_t) ttynr;
        return 0;
}

int get_ctty(pid_t pid, dev_t *_devnr, char **r) {
        int k;
        char fn[PATH_MAX], *s, *b, *p;
        dev_t devnr;

        assert(r);

        k = get_ctty_devnr(pid, &devnr);
        if (k < 0)
                return k;

        snprintf(fn, sizeof(fn), "/dev/char/%u:%u", major(devnr), minor(devnr));
        char_array_0(fn);

        if ((k = readlink_malloc(fn, &s)) < 0) {

                if (k != -ENOENT)
                        return k;

                /* This is an ugly hack */
                if (major(devnr) == 136) {
                        if (asprintf(&b, "pts/%lu", (unsigned long) minor(devnr)) < 0)
                                return -ENOMEM;

                        *r = b;
                        if (_devnr)
                                *_devnr = devnr;

                        return 0;
                }

                /* Probably something like the ptys which have no
                 * symlink in /dev/char. Let's return something
                 * vaguely useful. */

                if (!(b = strdup(fn + 5)))
                        return -ENOMEM;

                *r = b;
                if (_devnr)
                        *_devnr = devnr;

                return 0;
        }

        if (startswith(s, "/dev/"))
                p = s + 5;
        else if (startswith(s, "../"))
                p = s + 3;
        else
                p = s;

        b = strdup(p);
        free(s);

        if (!b)
                return -ENOMEM;

        *r = b;
        if (_devnr)
                *_devnr = devnr;

        return 0;
}

int rm_rf_children_dangerous(int fd, bool only_dirs, bool honour_sticky, struct stat *root_dev) {
        DIR *d;
        int ret = 0;

        assert(fd >= 0);

        /* This returns the first error we run into, but nevertheless
         * tries to go on. This closes the passed fd. */

        d = fdopendir(fd);
        if (!d) {
                close_nointr_nofail(fd);

                return errno == ENOENT ? 0 : -errno;
        }

        for (;;) {
                struct dirent *de;
                union dirent_storage buf;
                bool is_dir, keep_around;
                struct stat st;
                int r;

                r = readdir_r(d, &buf.de, &de);
                if (r != 0 && ret == 0) {
                        ret = -r;
                        break;
                }

                if (!de)
                        break;

                if (streq(de->d_name, ".") || streq(de->d_name, ".."))
                        continue;

                if (de->d_type == DT_UNKNOWN ||
                    honour_sticky ||
                    (de->d_type == DT_DIR && root_dev)) {
                        if (fstatat(fd, de->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0) {
                                if (ret == 0 && errno != ENOENT)
                                        ret = -errno;
                                continue;
                        }

                        is_dir = S_ISDIR(st.st_mode);
                        keep_around =
                                honour_sticky &&
                                (st.st_uid == 0 || st.st_uid == getuid()) &&
                                (st.st_mode & S_ISVTX);
                } else {
                        is_dir = de->d_type == DT_DIR;
                        keep_around = false;
                }

                if (is_dir) {
                        int subdir_fd;

                        /* if root_dev is set, remove subdirectories only, if device is same as dir */
                        if (root_dev && st.st_dev != root_dev->st_dev)
                                continue;

                        subdir_fd = openat(fd, de->d_name,
                                           O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW|O_NOATIME);
                        if (subdir_fd < 0) {
                                if (ret == 0 && errno != ENOENT)
                                        ret = -errno;
                                continue;
                        }

                        r = rm_rf_children_dangerous(subdir_fd, only_dirs, honour_sticky, root_dev);
                        if (r < 0 && ret == 0)
                                ret = r;

                        if (!keep_around)
                                if (unlinkat(fd, de->d_name, AT_REMOVEDIR) < 0) {
                                        if (ret == 0 && errno != ENOENT)
                                                ret = -errno;
                                }

                } else if (!only_dirs && !keep_around) {

                        if (unlinkat(fd, de->d_name, 0) < 0) {
                                if (ret == 0 && errno != ENOENT)
                                        ret = -errno;
                        }
                }
        }

        closedir(d);

        return ret;
}

int rm_rf_children(int fd, bool only_dirs, bool honour_sticky, struct stat *root_dev) {
        struct statfs s;

        assert(fd >= 0);

        if (fstatfs(fd, &s) < 0) {
                close_nointr_nofail(fd);
                return -errno;
        }

        /* We refuse to clean disk file systems with this call. This
         * is extra paranoia just to be sure we never ever remove
         * non-state data */

        if (s.f_type != TMPFS_MAGIC &&
            s.f_type != RAMFS_MAGIC) {
                log_error("Attempted to remove disk file system, and we can't allow that.");
                close_nointr_nofail(fd);
                return -EPERM;
        }

        return rm_rf_children_dangerous(fd, only_dirs, honour_sticky, root_dev);
}

static int rm_rf_internal(const char *path, bool only_dirs, bool delete_root, bool honour_sticky, bool dangerous) {
        int fd, r;
        struct statfs s;

        assert(path);

        /* We refuse to clean the root file system with this
         * call. This is extra paranoia to never cause a really
         * seriously broken system. */
        if (path_equal(path, "/")) {
                log_error("Attempted to remove entire root file system, and we can't allow that.");
                return -EPERM;
        }

        fd = open(path, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW|O_NOATIME);
        if (fd < 0) {

                if (errno != ENOTDIR)
                        return -errno;

                if (!dangerous) {
                        if (statfs(path, &s) < 0)
                                return -errno;

                        if (s.f_type != TMPFS_MAGIC &&
                            s.f_type != RAMFS_MAGIC) {
                                log_error("Attempted to remove disk file system, and we can't allow that.");
                                return -EPERM;
                        }
                }

                if (delete_root && !only_dirs)
                        if (unlink(path) < 0 && errno != ENOENT)
                                return -errno;

                return 0;
        }

        if (!dangerous) {
                if (fstatfs(fd, &s) < 0) {
                        close_nointr_nofail(fd);
                        return -errno;
                }

                if (s.f_type != TMPFS_MAGIC &&
                    s.f_type != RAMFS_MAGIC) {
                        log_error("Attempted to remove disk file system, and we can't allow that.");
                        close_nointr_nofail(fd);
                        return -EPERM;
                }
        }

        r = rm_rf_children_dangerous(fd, only_dirs, honour_sticky, NULL);
        if (delete_root) {

                if (honour_sticky && file_is_priv_sticky(path) > 0)
                        return r;

                if (rmdir(path) < 0 && errno != ENOENT) {
                        if (r == 0)
                                r = -errno;
                }
        }

        return r;
}

int rm_rf(const char *path, bool only_dirs, bool delete_root, bool honour_sticky) {
        return rm_rf_internal(path, only_dirs, delete_root, honour_sticky, false);
}

int rm_rf_dangerous(const char *path, bool only_dirs, bool delete_root, bool honour_sticky) {
        return rm_rf_internal(path, only_dirs, delete_root, honour_sticky, true);
}

int chmod_and_chown(const char *path, mode_t mode, uid_t uid, gid_t gid) {
        assert(path);

        /* Under the assumption that we are running privileged we
         * first change the access mode and only then hand out
         * ownership to avoid a window where access is too open. */

        if (mode != (mode_t) -1)
                if (chmod(path, mode) < 0)
                        return -errno;

        if (uid != (uid_t) -1 || gid != (gid_t) -1)
                if (chown(path, uid, gid) < 0)
                        return -errno;

        return 0;
}

int fchmod_and_fchown(int fd, mode_t mode, uid_t uid, gid_t gid) {
        assert(fd >= 0);

        /* Under the assumption that we are running privileged we
         * first change the access mode and only then hand out
         * ownership to avoid a window where access is too open. */

        if (fchmod(fd, mode) < 0)
                return -errno;

        if (fchown(fd, uid, gid) < 0)
                return -errno;

        return 0;
}

cpu_set_t* cpu_set_malloc(unsigned *ncpus) {
        cpu_set_t *r;
        unsigned n = 1024;

        /* Allocates the cpuset in the right size */

        for (;;) {
                if (!(r = CPU_ALLOC(n)))
                        return NULL;

                if (sched_getaffinity(0, CPU_ALLOC_SIZE(n), r) >= 0) {
                        CPU_ZERO_S(CPU_ALLOC_SIZE(n), r);

                        if (ncpus)
                                *ncpus = n;

                        return r;
                }

                CPU_FREE(r);

                if (errno != EINVAL)
                        return NULL;

                n *= 2;
        }
}

int status_vprintf(const char *status, bool ellipse, const char *format, va_list ap) {
        static const char status_indent[] = "         "; /* "[" STATUS "] " */
        _cleanup_free_ char *s = NULL;
        _cleanup_close_ int fd = -1;
        struct iovec iovec[5];
        int n = 0;

        assert(format);

        /* This is independent of logging, as status messages are
         * optional and go exclusively to the console. */

        if (vasprintf(&s, format, ap) < 0)
                return log_oom();

        fd = open_terminal("/dev/console", O_WRONLY|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return fd;

        if (ellipse) {
                char *e;
                size_t emax, sl;
                int c;

                c = fd_columns(fd);
                if (c <= 0)
                        c = 80;

                sl = status ? sizeof(status_indent)-1 : 0;

                emax = c - sl - 1;
                if (emax < 3)
                        emax = 3;

                e = ellipsize(s, emax, 75);
                if (e) {
                        free(s);
                        s = e;
                }
        }

        zero(iovec);

        if (status) {
                if (!isempty(status)) {
                        IOVEC_SET_STRING(iovec[n++], "[");
                        IOVEC_SET_STRING(iovec[n++], status);
                        IOVEC_SET_STRING(iovec[n++], "] ");
                } else
                        IOVEC_SET_STRING(iovec[n++], status_indent);
        }

        IOVEC_SET_STRING(iovec[n++], s);
        IOVEC_SET_STRING(iovec[n++], "\n");

        if (writev(fd, iovec, n) < 0)
                return -errno;

        return 0;
}

int status_printf(const char *status, bool ellipse, const char *format, ...) {
        va_list ap;
        int r;

        assert(format);

        va_start(ap, format);
        r = status_vprintf(status, ellipse, format, ap);
        va_end(ap);

        return r;
}

int status_welcome(void) {
        int r;
        _cleanup_free_ char *pretty_name = NULL, *ansi_color = NULL;

        r = parse_env_file("/etc/os-release", NEWLINE,
                           "PRETTY_NAME", &pretty_name,
                           "ANSI_COLOR", &ansi_color,
                           NULL);
        if (r < 0 && r != -ENOENT)
                log_warning("Failed to read /etc/os-release: %s", strerror(-r));

        return status_printf(NULL, false,
                             "\nWelcome to \x1B[%sm%s\x1B[0m!\n",
                             isempty(ansi_color) ? "1" : ansi_color,
                             isempty(pretty_name) ? "Linux" : pretty_name);
}

char *replace_env(const char *format, char **env) {
        enum {
                WORD,
                CURLY,
                VARIABLE
        } state = WORD;

        const char *e, *word = format;
        char *r = NULL, *k;

        assert(format);

        for (e = format; *e; e ++) {

                switch (state) {

                case WORD:
                        if (*e == '$')
                                state = CURLY;
                        break;

                case CURLY:
                        if (*e == '{') {
                                if (!(k = strnappend(r, word, e-word-1)))
                                        goto fail;

                                free(r);
                                r = k;

                                word = e-1;
                                state = VARIABLE;

                        } else if (*e == '$') {
                                if (!(k = strnappend(r, word, e-word)))
                                        goto fail;

                                free(r);
                                r = k;

                                word = e+1;
                                state = WORD;
                        } else
                                state = WORD;
                        break;

                case VARIABLE:
                        if (*e == '}') {
                                const char *t;

                                if (!(t = strv_env_get_with_length(env, word+2, e-word-2)))
                                        t = "";

                                if (!(k = strappend(r, t)))
                                        goto fail;

                                free(r);
                                r = k;

                                word = e+1;
                                state = WORD;
                        }
                        break;
                }
        }

        if (!(k = strnappend(r, word, e-word)))
                goto fail;

        free(r);
        return k;

fail:
        free(r);
        return NULL;
}

char **replace_env_argv(char **argv, char **env) {
        char **r, **i;
        unsigned k = 0, l = 0;

        l = strv_length(argv);

        if (!(r = new(char*, l+1)))
                return NULL;

        STRV_FOREACH(i, argv) {

                /* If $FOO appears as single word, replace it by the split up variable */
                if ((*i)[0] == '$' && (*i)[1] != '{') {
                        char *e;
                        char **w, **m;
                        unsigned q;

                        if ((e = strv_env_get(env, *i+1))) {

                                if (!(m = strv_split_quoted(e))) {
                                        r[k] = NULL;
                                        strv_free(r);
                                        return NULL;
                                }
                        } else
                                m = NULL;

                        q = strv_length(m);
                        l = l + q - 1;

                        if (!(w = realloc(r, sizeof(char*) * (l+1)))) {
                                r[k] = NULL;
                                strv_free(r);
                                strv_free(m);
                                return NULL;
                        }

                        r = w;
                        if (m) {
                                memcpy(r + k, m, q * sizeof(char*));
                                free(m);
                        }

                        k += q;
                        continue;
                }

                /* If ${FOO} appears as part of a word, replace it by the variable as-is */
                if (!(r[k++] = replace_env(*i, env))) {
                        strv_free(r);
                        return NULL;
                }
        }

        r[k] = NULL;
        return r;
}

int fd_columns(int fd) {
        struct winsize ws;
        zero(ws);

        if (ioctl(fd, TIOCGWINSZ, &ws) < 0)
                return -errno;

        if (ws.ws_col <= 0)
                return -EIO;

        return ws.ws_col;
}

unsigned columns(void) {
        const char *e;
        unsigned c;

        if (_likely_(cached_columns > 0))
                return cached_columns;

        c = 0;
        e = getenv("COLUMNS");
        if (e)
                safe_atou(e, &c);

        if (c <= 0)
                c = fd_columns(STDOUT_FILENO);

        if (c <= 0)
                c = 80;

        cached_columns = c;
        return c;
}

int fd_lines(int fd) {
        struct winsize ws;
        zero(ws);

        if (ioctl(fd, TIOCGWINSZ, &ws) < 0)
                return -errno;

        if (ws.ws_row <= 0)
                return -EIO;

        return ws.ws_row;
}

unsigned lines(void) {
        const char *e;
        unsigned l;

        if (_likely_(cached_lines > 0))
                return cached_lines;

        l = 0;
        e = getenv("LINES");
        if (e)
                safe_atou(e, &l);

        if (l <= 0)
                l = fd_lines(STDOUT_FILENO);

        if (l <= 0)
                l = 24;

        cached_lines = l;
        return cached_lines;
}

/* intended to be used as a SIGWINCH sighandler */
void columns_lines_cache_reset(int signum) {
        cached_columns = 0;
        cached_lines = 0;
}

bool on_tty(void) {
        static int cached_on_tty = -1;

        if (_unlikely_(cached_on_tty < 0))
                cached_on_tty = isatty(STDOUT_FILENO) > 0;

        return cached_on_tty;
}

int running_in_chroot(void) {
        struct stat a, b;

        zero(a);
        zero(b);

        /* Only works as root */

        if (stat("/proc/1/root", &a) < 0)
                return -errno;

        if (stat("/", &b) < 0)
                return -errno;

        return
                a.st_dev != b.st_dev ||
                a.st_ino != b.st_ino;
}

char *ellipsize_mem(const char *s, size_t old_length, size_t new_length, unsigned percent) {
        size_t x;
        char *r;

        assert(s);
        assert(percent <= 100);
        assert(new_length >= 3);

        if (old_length <= 3 || old_length <= new_length)
                return strndup(s, old_length);

        r = new0(char, new_length+1);
        if (!r)
                return r;

        x = (new_length * percent) / 100;

        if (x > new_length - 3)
                x = new_length - 3;

        memcpy(r, s, x);
        r[x] = '.';
        r[x+1] = '.';
        r[x+2] = '.';
        memcpy(r + x + 3,
               s + old_length - (new_length - x - 3),
               new_length - x - 3);

        return r;
}

char *ellipsize(const char *s, size_t length, unsigned percent) {
        return ellipsize_mem(s, strlen(s), length, percent);
}

int touch(const char *path) {
        int fd;

        assert(path);

        /* This just opens the file for writing, ensuring it
         * exists. It doesn't call utimensat() the way /usr/bin/touch
         * does it. */

        fd = open(path, O_WRONLY|O_CREAT|O_CLOEXEC|O_NOCTTY, 0644);
        if (fd < 0)
                return -errno;

        close_nointr_nofail(fd);
        return 0;
}

char *unquote(const char *s, const char* quotes) {
        size_t l;
        assert(s);

        /* This is rather stupid, simply removes the heading and
         * trailing quotes if there is one. Doesn't care about
         * escaping or anything. We should make this smarter one
         * day...*/

        l = strlen(s);
        if (l < 2)
                return strdup(s);

        if (strchr(quotes, s[0]) && s[l-1] == s[0])
                return strndup(s+1, l-2);

        return strdup(s);
}

char *normalize_env_assignment(const char *s) {
        _cleanup_free_ char *name = NULL, *value = NULL, *p = NULL;
        char *eq, *r;

        eq = strchr(s, '=');
        if (!eq) {
                char *t;

                r = strdup(s);
                if (!r)
                        return NULL;

                t = strstrip(r);
                if (t == r)
                        return r;

                memmove(r, t, strlen(t) + 1);
                return r;
        }

        name = strndup(s, eq - s);
        if (!name)
                return NULL;

        p = strdup(eq + 1);
        if (!p)
                return NULL;

        value = unquote(strstrip(p), QUOTES);
        if (!value)
                return NULL;

        if (asprintf(&r, "%s=%s", strstrip(name), value) < 0)
                r = NULL;

        return r;
}

int wait_for_terminate(pid_t pid, siginfo_t *status) {
        siginfo_t dummy;

        assert(pid >= 1);

        if (!status)
                status = &dummy;

        for (;;) {
                zero(*status);

                if (waitid(P_PID, pid, status, WEXITED) < 0) {

                        if (errno == EINTR)
                                continue;

                        return -errno;
                }

                return 0;
        }
}

int wait_for_terminate_and_warn(const char *name, pid_t pid) {
        int r;
        siginfo_t status;

        assert(name);
        assert(pid > 1);

        r = wait_for_terminate(pid, &status);
        if (r < 0) {
                log_warning("Failed to wait for %s: %s", name, strerror(-r));
                return r;
        }

        if (status.si_code == CLD_EXITED) {
                if (status.si_status != 0) {
                        log_warning("%s failed with error code %i.", name, status.si_status);
                        return status.si_status;
                }

                log_debug("%s succeeded.", name);
                return 0;

        } else if (status.si_code == CLD_KILLED ||
                   status.si_code == CLD_DUMPED) {

                log_warning("%s terminated by signal %s.", name, signal_to_string(status.si_status));
                return -EPROTO;
        }

        log_warning("%s failed due to unknown reason.", name);
        return -EPROTO;
}

_noreturn_ void freeze(void) {

        /* Make sure nobody waits for us on a socket anymore */
        close_all_fds(NULL, 0);

        sync();

        for (;;)
                pause();
}

bool null_or_empty(struct stat *st) {
        assert(st);

        if (S_ISREG(st->st_mode) && st->st_size <= 0)
                return true;

        if (S_ISCHR(st->st_mode) || S_ISBLK(st->st_mode))
                return true;

        return false;
}

int null_or_empty_path(const char *fn) {
        struct stat st;

        assert(fn);

        if (stat(fn, &st) < 0)
                return -errno;

        return null_or_empty(&st);
}

DIR *xopendirat(int fd, const char *name, int flags) {
        int nfd;
        DIR *d;

        nfd = openat(fd, name, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC|flags);
        if (nfd < 0)
                return NULL;

        d = fdopendir(nfd);
        if (!d) {
                close_nointr_nofail(nfd);
                return NULL;
        }

        return d;
}

int signal_from_string_try_harder(const char *s) {
        int signo;
        assert(s);

        signo = signal_from_string(s);
        if (signo <= 0)
                if (startswith(s, "SIG"))
                        return signal_from_string(s+3);

        return signo;
}

void dual_timestamp_serialize(FILE *f, const char *name, dual_timestamp *t) {

        assert(f);
        assert(name);
        assert(t);

        if (!dual_timestamp_is_set(t))
                return;

        fprintf(f, "%s=%llu %llu\n",
                name,
                (unsigned long long) t->realtime,
                (unsigned long long) t->monotonic);
}

void dual_timestamp_deserialize(const char *value, dual_timestamp *t) {
        unsigned long long a, b;

        assert(value);
        assert(t);

        if (sscanf(value, "%lli %llu", &a, &b) != 2)
                log_debug("Failed to parse finish timestamp value %s", value);
        else {
                t->realtime = a;
                t->monotonic = b;
        }
}

static char *tag_to_udev_node(const char *tagvalue, const char *by) {
        char *dn, *t, *u;
        int r;

        /* FIXME: to follow udev's logic 100% we need to leave valid
         * UTF8 chars unescaped */

        u = unquote(tagvalue, "\"\'");
        if (u == NULL)
                return NULL;

        t = xescape(u, "/ ");
        free(u);

        if (t == NULL)
                return NULL;

        r = asprintf(&dn, "/dev/disk/by-%s/%s", by, t);
        free(t);

        if (r < 0)
                return NULL;

        return dn;
}

char *fstab_node_to_udev_node(const char *p) {
        assert(p);

        if (startswith(p, "LABEL="))
                return tag_to_udev_node(p+6, "label");

        if (startswith(p, "UUID="))
                return tag_to_udev_node(p+5, "uuid");

        if (startswith(p, "PARTUUID="))
                return tag_to_udev_node(p+9, "partuuid");

        if (startswith(p, "PARTLABEL="))
                return tag_to_udev_node(p+10, "partlabel");

        return strdup(p);
}

bool tty_is_vc(const char *tty) {
        assert(tty);

        if (startswith(tty, "/dev/"))
                tty += 5;

        return vtnr_from_tty(tty) >= 0;
}

bool tty_is_console(const char *tty) {
        assert(tty);

        if (startswith(tty, "/dev/"))
                tty += 5;

        return streq(tty, "console");
}

int vtnr_from_tty(const char *tty) {
        int i, r;

        assert(tty);

        if (startswith(tty, "/dev/"))
                tty += 5;

        if (!startswith(tty, "tty") )
                return -EINVAL;

        if (tty[3] < '0' || tty[3] > '9')
                return -EINVAL;

        r = safe_atoi(tty+3, &i);
        if (r < 0)
                return r;

        if (i < 0 || i > 63)
                return -EINVAL;

        return i;
}

bool tty_is_vc_resolve(const char *tty) {
        char *active = NULL;
        bool b;

        assert(tty);

        if (startswith(tty, "/dev/"))
                tty += 5;

        /* Resolve where /dev/console is pointing to, if /sys is
         * actually ours (i.e. not read-only-mounted which is a sign
         * for container setups) */
        if (streq(tty, "console") && path_is_read_only_fs("/sys") <= 0)
                if (read_one_line_file("/sys/class/tty/console/active", &active) >= 0) {
                        /* If multiple log outputs are configured the
                         * last one is what /dev/console points to */
                        tty = strrchr(active, ' ');
                        if (tty)
                                tty++;
                        else
                                tty = active;
                }

        b = tty_is_vc(tty);
        free(active);

        return b;
}

const char *default_term_for_tty(const char *tty) {
        assert(tty);

        return tty_is_vc_resolve(tty) ? "TERM=linux" : "TERM=vt102";
}

bool dirent_is_file(const struct dirent *de) {
        assert(de);

        if (ignore_file(de->d_name))
                return false;

        if (de->d_type != DT_REG &&
            de->d_type != DT_LNK &&
            de->d_type != DT_UNKNOWN)
                return false;

        return true;
}

bool dirent_is_file_with_suffix(const struct dirent *de, const char *suffix) {
        assert(de);

        if (de->d_type != DT_REG &&
            de->d_type != DT_LNK &&
            de->d_type != DT_UNKNOWN)
                return false;

        if (ignore_file_allow_backup(de->d_name))
                return false;

        return endswith(de->d_name, suffix);
}

int execute_command(const char *command, char *const argv[])
{

        pid_t pid;
        int status;

        if ((status = access(command, X_OK)) != 0)
                return status;

        if ((pid = fork()) < 0) {
                log_error("Failed to fork: %m");
                return pid;
        }

        if (pid == 0) {

                execvp(command, argv);

                log_error("Failed to execute %s: %m", command);
                _exit(EXIT_FAILURE);
        }
        else while (1)
        {
                siginfo_t si;

                int r = waitid(P_PID, pid, &si, WEXITED);

                if (!is_clean_exit(si.si_code, si.si_status, NULL)) {
                        if (si.si_code == CLD_EXITED)
                                log_error("%s exited with exit status %i.", command, si.si_status);
                        else
                                log_error("%s terminated by signal %s.", command, signal_to_string(si.si_status));
                } else
                        log_debug("%s exited successfully.", command);

                return si.si_status; 

        }
}

void execute_directory(const char *directory, DIR *d, char *argv[]) {
        DIR *_d = NULL;
        struct dirent *de;
        Hashmap *pids = NULL;

        assert(directory);

        /* Executes all binaries in a directory in parallel and waits
         * until all they all finished. */

        if (!d) {
                if (!(_d = opendir(directory))) {

                        if (errno == ENOENT)
                                return;

                        log_error("Failed to enumerate directory %s: %m", directory);
                        return;
                }

                d = _d;
        }

        if (!(pids = hashmap_new(trivial_hash_func, trivial_compare_func))) {
                log_error("Failed to allocate set.");
                goto finish;
        }

        while ((de = readdir(d))) {
                char *path;
                pid_t pid;
                int k;

                if (!dirent_is_file(de))
                        continue;

                if (asprintf(&path, "%s/%s", directory, de->d_name) < 0) {
                        log_oom();
                        continue;
                }

                if ((pid = fork()) < 0) {
                        log_error("Failed to fork: %m");
                        free(path);
                        continue;
                }

                if (pid == 0) {
                        char *_argv[2];
                        /* Child */

                        if (!argv) {
                                _argv[0] = path;
                                _argv[1] = NULL;
                                argv = _argv;
                        } else
                                argv[0] = path;

                        execv(path, argv);

                        log_error("Failed to execute %s: %m", path);
                        _exit(EXIT_FAILURE);
                }

                log_debug("Spawned %s as %lu", path, (unsigned long) pid);

                if ((k = hashmap_put(pids, UINT_TO_PTR(pid), path)) < 0) {
                        log_error("Failed to add PID to set: %s", strerror(-k));
                        free(path);
                }
        }

        while (!hashmap_isempty(pids)) {
                pid_t pid = PTR_TO_UINT(hashmap_first_key(pids));
                siginfo_t si;
                char *path;

                zero(si);
                if (waitid(P_PID, pid, &si, WEXITED) < 0) {

                        if (errno == EINTR)
                                continue;

                        log_error("waitid() failed: %m");
                        goto finish;
                }

                if ((path = hashmap_remove(pids, UINT_TO_PTR(si.si_pid)))) {
                        if (!is_clean_exit(si.si_code, si.si_status, NULL)) {
                                if (si.si_code == CLD_EXITED)
                                        log_error("%s exited with exit status %i.", path, si.si_status);
                                else
                                        log_error("%s terminated by signal %s.", path, signal_to_string(si.si_status));
                        } else
                                log_debug("%s exited successfully.", path);

                        free(path);
                }
        }

finish:
        if (_d)
                closedir(_d);

        if (pids)
                hashmap_free_free(pids);
}

int kill_and_sigcont(pid_t pid, int sig) {
        int r;

        r = kill(pid, sig) < 0 ? -errno : 0;

        if (r >= 0)
                kill(pid, SIGCONT);

        return r;
}

bool nulstr_contains(const char*nulstr, const char *needle) {
        const char *i;

        if (!nulstr)
                return false;

        NULSTR_FOREACH(i, nulstr)
                if (streq(i, needle))
                        return true;

        return false;
}

bool plymouth_running(void) {
        return access("/run/plymouth/pid", F_OK) >= 0;
}

char* strshorten(char *s, size_t l) {
        assert(s);

        if (l < strlen(s))
                s[l] = 0;

        return s;
}

static bool hostname_valid_char(char c) {
        return
                (c >= 'a' && c <= 'z') ||
                (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') ||
                c == '-' ||
                c == '_' ||
                c == '.';
}

bool hostname_is_valid(const char *s) {
        const char *p;

        if (isempty(s))
                return false;

        for (p = s; *p; p++)
                if (!hostname_valid_char(*p))
                        return false;

        if (p-s > HOST_NAME_MAX)
                return false;

        return true;
}

char* hostname_cleanup(char *s) {
        char *p, *d;

        for (p = s, d = s; *p; p++)
                if ((*p >= 'a' && *p <= 'z') ||
                    (*p >= 'A' && *p <= 'Z') ||
                    (*p >= '0' && *p <= '9') ||
                    *p == '-' ||
                    *p == '_' ||
                    *p == '.')
                        *(d++) = *p;

        *d = 0;

        strshorten(s, HOST_NAME_MAX);
        return s;
}

int pipe_eof(int fd) {
        struct pollfd pollfd;
        int r;

        zero(pollfd);
        pollfd.fd = fd;
        pollfd.events = POLLIN|POLLHUP;

        r = poll(&pollfd, 1, 0);
        if (r < 0)
                return -errno;

        if (r == 0)
                return 0;

        return pollfd.revents & POLLHUP;
}

int fd_wait_for_event(int fd, int event, usec_t t) {
        struct pollfd pollfd;
        int r;

        zero(pollfd);
        pollfd.fd = fd;
        pollfd.events = event;

        r = poll(&pollfd, 1, t == (usec_t) -1 ? -1 : (int) (t / USEC_PER_MSEC));
        if (r < 0)
                return -errno;

        if (r == 0)
                return 0;

        return pollfd.revents;
}

int fopen_temporary(const char *path, FILE **_f, char **_temp_path) {
        FILE *f;
        char *t;
        const char *fn;
        size_t k;
        int fd;

        assert(path);
        assert(_f);
        assert(_temp_path);

        t = new(char, strlen(path) + 1 + 6 + 1);
        if (!t)
                return -ENOMEM;

        fn = path_get_file_name(path);
        k = fn-path;
        memcpy(t, path, k);
        t[k] = '.';
        stpcpy(stpcpy(t+k+1, fn), "XXXXXX");

#if HAVE_DECL_MKOSTEMP
        fd = mkostemp(t, O_WRONLY|O_CLOEXEC);
#else
        fd = mkstemp(t);
        fcntl(fd, F_SETFD, FD_CLOEXEC);
#endif
        if (fd < 0) {
                free(t);
                return -errno;
        }

        f = fdopen(fd, "we");
        if (!f) {
                unlink(t);
                free(t);
                return -errno;
        }

        *_f = f;
        *_temp_path = t;

        return 0;
}

int terminal_vhangup_fd(int fd) {
        assert(fd >= 0);

        if (ioctl(fd, TIOCVHANGUP) < 0)
                return -errno;

        return 0;
}

int terminal_vhangup(const char *name) {
        int fd, r;

        fd = open_terminal(name, O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return fd;

        r = terminal_vhangup_fd(fd);
        close_nointr_nofail(fd);

        return r;
}

int vt_disallocate(const char *name) {
        int fd, r;
        unsigned u;

        /* Deallocate the VT if possible. If not possible
         * (i.e. because it is the active one), at least clear it
         * entirely (including the scrollback buffer) */

        if (!startswith(name, "/dev/"))
                return -EINVAL;

        if (!tty_is_vc(name)) {
                /* So this is not a VT. I guess we cannot deallocate
                 * it then. But let's at least clear the screen */

                fd = open_terminal(name, O_RDWR|O_NOCTTY|O_CLOEXEC);
                if (fd < 0)
                        return fd;

                loop_write(fd,
                           "\033[r"    /* clear scrolling region */
                           "\033[H"    /* move home */
                           "\033[2J",  /* clear screen */
                           10, false);
                close_nointr_nofail(fd);

                return 0;
        }

        if (!startswith(name, "/dev/tty"))
                return -EINVAL;

        r = safe_atou(name+8, &u);
        if (r < 0)
                return r;

        if (u <= 0)
                return -EINVAL;

        /* Try to deallocate */
        fd = open_terminal("/dev/tty0", O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return fd;

        r = ioctl(fd, VT_DISALLOCATE, u);
        close_nointr_nofail(fd);

        if (r >= 0)
                return 0;

        if (errno != EBUSY)
                return -errno;

        /* Couldn't deallocate, so let's clear it fully with
         * scrollback */
        fd = open_terminal(name, O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return fd;

        loop_write(fd,
                   "\033[r"   /* clear scrolling region */
                   "\033[H"   /* move home */
                   "\033[3J", /* clear screen including scrollback, requires Linux 2.6.40 */
                   10, false);
        close_nointr_nofail(fd);

        return 0;
}

int copy_file(const char *from, const char *to) {
        int r, fdf, fdt;

        assert(from);
        assert(to);

        fdf = open(from, O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fdf < 0)
                return -errno;

        fdt = open(to, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOCTTY, 0644);
        if (fdt < 0) {
                close_nointr_nofail(fdf);
                return -errno;
        }

        for (;;) {
                char buf[PIPE_BUF];
                ssize_t n, k;

                n = read(fdf, buf, sizeof(buf));
                if (n < 0) {
                        r = -errno;

                        close_nointr_nofail(fdf);
                        close_nointr(fdt);
                        unlink(to);

                        return r;
                }

                if (n == 0)
                        break;

                errno = 0;
                k = loop_write(fdt, buf, n, false);
                if (n != k) {
                        r = k < 0 ? k : (errno ? -errno : -EIO);

                        close_nointr_nofail(fdf);
                        close_nointr(fdt);

                        unlink(to);
                        return r;
                }
        }

        close_nointr_nofail(fdf);
        r = close_nointr(fdt);

        if (r < 0) {
                unlink(to);
                return r;
        }

        return 0;
}

int symlink_atomic(const char *from, const char *to) {
        char *x;
        _cleanup_free_ char *t;
        const char *fn;
        size_t k;
        unsigned long long ull;
        unsigned i;
        int r;

        assert(from);
        assert(to);

        t = new(char, strlen(to) + 1 + 16 + 1);
        if (!t)
                return -ENOMEM;

        fn = path_get_file_name(to);
        k = fn-to;
        memcpy(t, to, k);
        t[k] = '.';
        x = stpcpy(t+k+1, fn);

        ull = random_ull();
        for (i = 0; i < 16; i++) {
                *(x++) = hexchar(ull & 0xF);
                ull >>= 4;
        }

        *x = 0;

        if (symlink(from, t) < 0)
                return -errno;

        if (rename(t, to) < 0) {
                r = -errno;
                unlink(t);
                return r;
        }

        return 0;
}

bool display_is_local(const char *display) {
        assert(display);

        return
                display[0] == ':' &&
                display[1] >= '0' &&
                display[1] <= '9';
}

int socket_from_display(const char *display, char **path) {
        size_t k;
        char *f, *c;

        assert(display);
        assert(path);

        if (!display_is_local(display))
                return -EINVAL;

        k = strspn(display+1, "0123456789");

        f = new(char, sizeof("/tmp/.X11-unix/X") + k);
        if (!f)
                return -ENOMEM;

        c = stpcpy(f, "/tmp/.X11-unix/X");
        memcpy(c, display+1, k);
        c[k] = 0;

        *path = f;

        return 0;
}

int get_user_creds(
                const char **username,
                uid_t *uid, gid_t *gid,
                const char **home,
                const char **shell) {

        struct passwd *p;
        uid_t u;

        assert(username);
        assert(*username);

        /* We enforce some special rules for uid=0: in order to avoid
         * NSS lookups for root we hardcode its data. */

        if (streq(*username, "root") || streq(*username, "0")) {
                *username = "root";

                if (uid)
                        *uid = 0;

                if (gid)
                        *gid = 0;

                if (home)
                        *home = "/root";

                if (shell)
                        *shell = "/bin/sh";

                return 0;
        }

        if (parse_uid(*username, &u) >= 0) {
                errno = 0;
                p = getpwuid(u);

                /* If there are multiple users with the same id, make
                 * sure to leave $USER to the configured value instead
                 * of the first occurrence in the database. However if
                 * the uid was configured by a numeric uid, then let's
                 * pick the real username from /etc/passwd. */
                if (p)
                        *username = p->pw_name;
        } else {
                errno = 0;
                p = getpwnam(*username);
        }

        if (!p)
                return errno != 0 ? -errno : -ESRCH;

        if (uid)
                *uid = p->pw_uid;

        if (gid)
                *gid = p->pw_gid;

        if (home)
                *home = p->pw_dir;

        if (shell)
                *shell = p->pw_shell;

        return 0;
}

int get_group_creds(const char **groupname, gid_t *gid) {
        struct group *g;
        gid_t id;

        assert(groupname);

        /* We enforce some special rules for gid=0: in order to avoid
         * NSS lookups for root we hardcode its data. */

        if (streq(*groupname, "root") || streq(*groupname, "0")) {
                *groupname = "root";

                if (gid)
                        *gid = 0;

                return 0;
        }

        if (parse_gid(*groupname, &id) >= 0) {
                errno = 0;
                g = getgrgid(id);

                if (g)
                        *groupname = g->gr_name;
        } else {
                errno = 0;
                g = getgrnam(*groupname);
        }

        if (!g)
                return errno != 0 ? -errno : -ESRCH;

        if (gid)
                *gid = g->gr_gid;

        return 0;
}

int in_group(const char *name) {
        gid_t gid, *gids;
        int ngroups_max, r, i;

        r = get_group_creds(&name, &gid);
        if (r < 0)
                return r;

        if (getgid() == gid)
                return 1;

        if (getegid() == gid)
                return 1;

        ngroups_max = sysconf(_SC_NGROUPS_MAX);
        assert(ngroups_max > 0);

        gids = alloca(sizeof(gid_t) * ngroups_max);

        r = getgroups(ngroups_max, gids);
        if (r < 0)
                return -errno;

        for (i = 0; i < r; i++)
                if (gids[i] == gid)
                        return 1;

        return 0;
}

int glob_exists(const char *path) {
        glob_t g;
        int r, k;

        assert(path);

        zero(g);
        errno = 0;
        k = glob(path, GLOB_NOSORT|GLOB_BRACE, NULL, &g);

        if (k == GLOB_NOMATCH)
                r = 0;
        else if (k == GLOB_NOSPACE)
                r = -ENOMEM;
        else if (k == 0)
                r = !strv_isempty(g.gl_pathv);
        else
                r = errno ? -errno : -EIO;

        globfree(&g);

        return r;
}

int dirent_ensure_type(DIR *d, struct dirent *de) {
        struct stat st;

        assert(d);
        assert(de);

        if (de->d_type != DT_UNKNOWN)
                return 0;

        if (fstatat(dirfd(d), de->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0)
                return -errno;

        de->d_type =
                S_ISREG(st.st_mode)  ? DT_REG  :
                S_ISDIR(st.st_mode)  ? DT_DIR  :
                S_ISLNK(st.st_mode)  ? DT_LNK  :
                S_ISFIFO(st.st_mode) ? DT_FIFO :
                S_ISSOCK(st.st_mode) ? DT_SOCK :
                S_ISCHR(st.st_mode)  ? DT_CHR  :
                S_ISBLK(st.st_mode)  ? DT_BLK  :
                                       DT_UNKNOWN;

        return 0;
}

int in_search_path(const char *path, char **search) {
        char **i, *parent;
        int r;

        r = path_get_parent(path, &parent);
        if (r < 0)
                return r;

        r = 0;

        STRV_FOREACH(i, search) {
                if (path_equal(parent, *i)) {
                        r = 1;
                        break;
                }
        }

        free(parent);

        return r;
}

int get_files_in_directory(const char *path, char ***list) {
        DIR *d;
        int r = 0;
        unsigned n = 0;
        char **l = NULL;

        assert(path);

        /* Returns all files in a directory in *list, and the number
         * of files as return value. If list is NULL returns only the
         * number */

        d = opendir(path);
        if (!d)
                return -errno;

        for (;;) {
                struct dirent *de;
                union dirent_storage buf;
                int k;

                k = readdir_r(d, &buf.de, &de);
                if (k != 0) {
                        r = -k;
                        goto finish;
                }

                if (!de)
                        break;

                dirent_ensure_type(d, de);

                if (!dirent_is_file(de))
                        continue;

                if (list) {
                        if ((unsigned) r >= n) {
                                char **t;

                                n = MAX(16, 2*r);
                                t = realloc(l, sizeof(char*) * n);
                                if (!t) {
                                        r = -ENOMEM;
                                        goto finish;
                                }

                                l = t;
                        }

                        assert((unsigned) r < n);

                        l[r] = strdup(de->d_name);
                        if (!l[r]) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        l[++r] = NULL;
                } else
                        r++;
        }

finish:
        if (d)
                closedir(d);

        if (r >= 0) {
                if (list)
                        *list = l;
        } else
                strv_free(l);

        return r;
}

char *strjoin(const char *x, ...) {
        va_list ap;
        size_t l;
        char *r, *p;

        va_start(ap, x);

        if (x) {
                l = strlen(x);

                for (;;) {
                        const char *t;
                        size_t n;

                        t = va_arg(ap, const char *);
                        if (!t)
                                break;

                        n = strlen(t);
                        if (n > ((size_t) -1) - l) {
                                va_end(ap);
                                return NULL;
                        }

                        l += n;
                }
        } else
                l = 0;

        va_end(ap);

        r = new(char, l+1);
        if (!r)
                return NULL;

        if (x) {
                p = stpcpy(r, x);

                va_start(ap, x);

                for (;;) {
                        const char *t;

                        t = va_arg(ap, const char *);
                        if (!t)
                                break;

                        p = stpcpy(p, t);
                }

                va_end(ap);
        } else
                r[0] = 0;

        return r;
}

bool is_main_thread(void) {
        static __thread int cached = 0;

        if (_unlikely_(cached == 0))
                cached = getpid() == gettid() ? 1 : -1;

        return cached > 0;
}

int block_get_whole_disk(dev_t d, dev_t *ret) {
        char *p, *s;
        int r;
        unsigned n, m;

        assert(ret);

        /* If it has a queue this is good enough for us */
        if (asprintf(&p, "/sys/dev/block/%u:%u/queue", major(d), minor(d)) < 0)
                return -ENOMEM;

        r = access(p, F_OK);
        free(p);

        if (r >= 0) {
                *ret = d;
                return 0;
        }

        /* If it is a partition find the originating device */
        if (asprintf(&p, "/sys/dev/block/%u:%u/partition", major(d), minor(d)) < 0)
                return -ENOMEM;

        r = access(p, F_OK);
        free(p);

        if (r < 0)
                return -ENOENT;

        /* Get parent dev_t */
        if (asprintf(&p, "/sys/dev/block/%u:%u/../dev", major(d), minor(d)) < 0)
                return -ENOMEM;

        r = read_one_line_file(p, &s);
        free(p);

        if (r < 0)
                return r;

        r = sscanf(s, "%u:%u", &m, &n);
        free(s);

        if (r != 2)
                return -EINVAL;

        /* Only return this if it is really good enough for us. */
        if (asprintf(&p, "/sys/dev/block/%u:%u/queue", m, n) < 0)
                return -ENOMEM;

        r = access(p, F_OK);
        free(p);

        if (r >= 0) {
                *ret = makedev(m, n);
                return 0;
        }

        return -ENOENT;
}

int file_is_priv_sticky(const char *p) {
        struct stat st;

        assert(p);

        if (lstat(p, &st) < 0)
                return -errno;

        return
                (st.st_uid == 0 || st.st_uid == getuid()) &&
                (st.st_mode & S_ISVTX);
}

static const char *const ioprio_class_table[] = {
        [IOPRIO_CLASS_NONE] = "none",
        [IOPRIO_CLASS_RT] = "realtime",
        [IOPRIO_CLASS_BE] = "best-effort",
        [IOPRIO_CLASS_IDLE] = "idle"
};

DEFINE_STRING_TABLE_LOOKUP_WITH_FALLBACK(ioprio_class, int, INT_MAX);

static const char *const sigchld_code_table[] = {
        [CLD_EXITED] = "exited",
        [CLD_KILLED] = "killed",
        [CLD_DUMPED] = "dumped",
        [CLD_TRAPPED] = "trapped",
        [CLD_STOPPED] = "stopped",
        [CLD_CONTINUED] = "continued",
};

DEFINE_STRING_TABLE_LOOKUP(sigchld_code, int);

static const char *const log_facility_unshifted_table[LOG_NFACILITIES] = {
        [LOG_FAC(LOG_KERN)] = "kern",
        [LOG_FAC(LOG_USER)] = "user",
        [LOG_FAC(LOG_MAIL)] = "mail",
        [LOG_FAC(LOG_DAEMON)] = "daemon",
        [LOG_FAC(LOG_AUTH)] = "auth",
        [LOG_FAC(LOG_SYSLOG)] = "syslog",
        [LOG_FAC(LOG_LPR)] = "lpr",
        [LOG_FAC(LOG_NEWS)] = "news",
        [LOG_FAC(LOG_UUCP)] = "uucp",
        [LOG_FAC(LOG_CRON)] = "cron",
        [LOG_FAC(LOG_AUTHPRIV)] = "authpriv",
        [LOG_FAC(LOG_FTP)] = "ftp",
        [LOG_FAC(LOG_LOCAL0)] = "local0",
        [LOG_FAC(LOG_LOCAL1)] = "local1",
        [LOG_FAC(LOG_LOCAL2)] = "local2",
        [LOG_FAC(LOG_LOCAL3)] = "local3",
        [LOG_FAC(LOG_LOCAL4)] = "local4",
        [LOG_FAC(LOG_LOCAL5)] = "local5",
        [LOG_FAC(LOG_LOCAL6)] = "local6",
        [LOG_FAC(LOG_LOCAL7)] = "local7"
};

DEFINE_STRING_TABLE_LOOKUP_WITH_FALLBACK(log_facility_unshifted, int, LOG_FAC(~0));

static const char *const log_level_table[] = {
        [LOG_EMERG] = "emerg",
        [LOG_ALERT] = "alert",
        [LOG_CRIT] = "crit",
        [LOG_ERR] = "err",
        [LOG_WARNING] = "warning",
        [LOG_NOTICE] = "notice",
        [LOG_INFO] = "info",
        [LOG_DEBUG] = "debug"
};

DEFINE_STRING_TABLE_LOOKUP_WITH_FALLBACK(log_level, int, LOG_DEBUG);

static const char* const sched_policy_table[] = {
        [SCHED_OTHER] = "other",
        [SCHED_BATCH] = "batch",
        [SCHED_IDLE] = "idle",
        [SCHED_FIFO] = "fifo",
        [SCHED_RR] = "rr"
};

DEFINE_STRING_TABLE_LOOKUP_WITH_FALLBACK(sched_policy, int, INT_MAX);

static const char* const rlimit_table[] = {
        [RLIMIT_CPU] = "LimitCPU",
        [RLIMIT_FSIZE] = "LimitFSIZE",
        [RLIMIT_DATA] = "LimitDATA",
        [RLIMIT_STACK] = "LimitSTACK",
        [RLIMIT_CORE] = "LimitCORE",
        [RLIMIT_RSS] = "LimitRSS",
        [RLIMIT_NOFILE] = "LimitNOFILE",
        [RLIMIT_AS] = "LimitAS",
        [RLIMIT_NPROC] = "LimitNPROC",
        [RLIMIT_MEMLOCK] = "LimitMEMLOCK",
        [RLIMIT_LOCKS] = "LimitLOCKS",
        [RLIMIT_SIGPENDING] = "LimitSIGPENDING",
        [RLIMIT_MSGQUEUE] = "LimitMSGQUEUE",
        [RLIMIT_NICE] = "LimitNICE",
        [RLIMIT_RTPRIO] = "LimitRTPRIO",
        [RLIMIT_RTTIME] = "LimitRTTIME"
};

DEFINE_STRING_TABLE_LOOKUP(rlimit, int);

static const char* const ip_tos_table[] = {
        [IPTOS_LOWDELAY] = "low-delay",
        [IPTOS_THROUGHPUT] = "throughput",
        [IPTOS_RELIABILITY] = "reliability",
        [IPTOS_LOWCOST] = "low-cost",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_FALLBACK(ip_tos, int, 0xff);

static const char *const __signal_table[] = {
        [SIGHUP] = "HUP",
        [SIGINT] = "INT",
        [SIGQUIT] = "QUIT",
        [SIGILL] = "ILL",
        [SIGTRAP] = "TRAP",
        [SIGABRT] = "ABRT",
        [SIGBUS] = "BUS",
        [SIGFPE] = "FPE",
        [SIGKILL] = "KILL",
        [SIGUSR1] = "USR1",
        [SIGSEGV] = "SEGV",
        [SIGUSR2] = "USR2",
        [SIGPIPE] = "PIPE",
        [SIGALRM] = "ALRM",
        [SIGTERM] = "TERM",
#ifdef SIGSTKFLT
        [SIGSTKFLT] = "STKFLT",  /* Linux on SPARC doesn't know SIGSTKFLT */
#endif
        [SIGCHLD] = "CHLD",
        [SIGCONT] = "CONT",
        [SIGSTOP] = "STOP",
        [SIGTSTP] = "TSTP",
        [SIGTTIN] = "TTIN",
        [SIGTTOU] = "TTOU",
        [SIGURG] = "URG",
        [SIGXCPU] = "XCPU",
        [SIGXFSZ] = "XFSZ",
        [SIGVTALRM] = "VTALRM",
        [SIGPROF] = "PROF",
        [SIGWINCH] = "WINCH",
        [SIGIO] = "IO",
        [SIGPWR] = "PWR",
        [SIGSYS] = "SYS"
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP(__signal, int);

const char *signal_to_string(int signo) {
        static __thread char buf[12];
        const char *name;

        name = __signal_to_string(signo);
        if (name)
                return name;

        if (signo >= SIGRTMIN && signo <= SIGRTMAX)
                snprintf(buf, sizeof(buf) - 1, "RTMIN+%d", signo - SIGRTMIN);
        else
                snprintf(buf, sizeof(buf) - 1, "%d", signo);
        char_array_0(buf);
        return buf;
}

int signal_from_string(const char *s) {
        int signo;
        int offset = 0;
        unsigned u;

        signo = __signal_from_string(s);
        if (signo > 0)
                return signo;

        if (startswith(s, "RTMIN+")) {
                s += 6;
                offset = SIGRTMIN;
        }
        if (safe_atou(s, &u) >= 0) {
                signo = (int) u + offset;
                if (signo > 0 && signo < _NSIG)
                        return signo;
        }
        return -1;
}

bool kexec_loaded(void) {
       bool loaded = false;
       char *s;

       if (read_one_line_file("/sys/kernel/kexec_loaded", &s) >= 0) {
               if (s[0] == '1')
                       loaded = true;
               free(s);
       }
       return loaded;
}

int strdup_or_null(const char *a, char **b) {
        char *c;

        assert(b);

        if (!a) {
                *b = NULL;
                return 0;
        }

        c = strdup(a);
        if (!c)
                return -ENOMEM;

        *b = c;
        return 0;
}

int prot_from_flags(int flags) {

        switch (flags & O_ACCMODE) {

        case O_RDONLY:
                return PROT_READ;

        case O_WRONLY:
                return PROT_WRITE;

        case O_RDWR:
                return PROT_READ|PROT_WRITE;

        default:
                return -EINVAL;
        }
}

char *format_bytes(char *buf, size_t l, off_t t) {
        unsigned i;

        static const struct {
                const char *suffix;
                off_t factor;
        } table[] = {
                { "E", 1024ULL*1024ULL*1024ULL*1024ULL*1024ULL*1024ULL },
                { "P", 1024ULL*1024ULL*1024ULL*1024ULL*1024ULL },
                { "T", 1024ULL*1024ULL*1024ULL*1024ULL },
                { "G", 1024ULL*1024ULL*1024ULL },
                { "M", 1024ULL*1024ULL },
                { "K", 1024ULL },
        };

        for (i = 0; i < ELEMENTSOF(table); i++) {

                if (t >= table[i].factor) {
                        snprintf(buf, l,
                                 "%llu.%llu%s",
                                 (unsigned long long) (t / table[i].factor),
                                 (unsigned long long) (((t*10ULL) / table[i].factor) % 10ULL),
                                 table[i].suffix);

                        goto finish;
                }
        }

        snprintf(buf, l, "%lluB", (unsigned long long) t);

finish:
        buf[l-1] = 0;
        return buf;

}

void* memdup(const void *p, size_t l) {
        void *r;

        assert(p);

        r = malloc(l);
        if (!r)
                return NULL;

        memcpy(r, p, l);
        return r;
}

int fd_inc_sndbuf(int fd, size_t n) {
        int r, value;
        socklen_t l = sizeof(value);

        r = getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &value, &l);
        if (r >= 0 &&
            l == sizeof(value) &&
            (size_t) value >= n*2)
                return 0;

        value = (int) n;
        r = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &value, sizeof(value));
        if (r < 0)
                return -errno;

        return 1;
}

int fd_inc_rcvbuf(int fd, size_t n) {
        int r, value;
        socklen_t l = sizeof(value);

        r = getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &value, &l);
        if (r >= 0 &&
            l == sizeof(value) &&
            (size_t) value >= n*2)
                return 0;

        value = (int) n;
        r = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &value, sizeof(value));
        if (r < 0)
                return -errno;

        return 1;
}

int fork_agent(pid_t *pid, const int except[], unsigned n_except, const char *path, ...) {
        pid_t parent_pid, agent_pid;
        int fd;
        bool stdout_is_tty, stderr_is_tty;
        unsigned n, i;
        va_list ap;
        char **l;

        assert(pid);
        assert(path);

        parent_pid = getpid();

        /* Spawns a temporary TTY agent, making sure it goes away when
         * we go away */

        agent_pid = fork();
        if (agent_pid < 0)
                return -errno;

        if (agent_pid != 0) {
                *pid = agent_pid;
                return 0;
        }

        /* In the child:
         *
         * Make sure the agent goes away when the parent dies */
        if (prctl(PR_SET_PDEATHSIG, SIGTERM) < 0)
                _exit(EXIT_FAILURE);

        /* Check whether our parent died before we were able
         * to set the death signal */
        if (getppid() != parent_pid)
                _exit(EXIT_SUCCESS);

        /* Don't leak fds to the agent */
        close_all_fds(except, n_except);

        stdout_is_tty = isatty(STDOUT_FILENO);
        stderr_is_tty = isatty(STDERR_FILENO);

        if (!stdout_is_tty || !stderr_is_tty) {
                /* Detach from stdout/stderr. and reopen
                 * /dev/tty for them. This is important to
                 * ensure that when systemctl is started via
                 * popen() or a similar call that expects to
                 * read EOF we actually do generate EOF and
                 * not delay this indefinitely by because we
                 * keep an unused copy of stdin around. */
                fd = open("/dev/tty", O_WRONLY);
                if (fd < 0) {
                        log_error("Failed to open /dev/tty: %m");
                        _exit(EXIT_FAILURE);
                }

                if (!stdout_is_tty)
                        dup2(fd, STDOUT_FILENO);

                if (!stderr_is_tty)
                        dup2(fd, STDERR_FILENO);

                if (fd > 2)
                        close(fd);
        }

        /* Count arguments */
        va_start(ap, path);
        for (n = 0; va_arg(ap, char*); n++)
                ;
        va_end(ap);

        /* Allocate strv */
        l = alloca(sizeof(char *) * (n + 1));

        /* Fill in arguments */
        va_start(ap, path);
        for (i = 0; i <= n; i++)
                l[i] = va_arg(ap, char*);
        va_end(ap);

        execv(path, l);
        _exit(EXIT_FAILURE);
}

int setrlimit_closest(int resource, const struct rlimit *rlim) {
        struct rlimit highest, fixed;

        assert(rlim);

        if (setrlimit(resource, rlim) >= 0)
                return 0;

        if (errno != EPERM)
                return -errno;

        /* So we failed to set the desired setrlimit, then let's try
         * to get as close as we can */
        assert_se(getrlimit(resource, &highest) == 0);

        fixed.rlim_cur = MIN(rlim->rlim_cur, highest.rlim_max);
        fixed.rlim_max = MIN(rlim->rlim_max, highest.rlim_max);

        if (setrlimit(resource, &fixed) < 0)
                return -errno;

        return 0;
}

int getenv_for_pid(pid_t pid, const char *field, char **_value) {
        char path[sizeof("/proc/")-1+10+sizeof("/environ")], *value = NULL;
        int r;
        FILE *f;
        bool done = false;
        size_t l;

        assert(field);
        assert(_value);

        if (pid == 0)
                pid = getpid();

        snprintf(path, sizeof(path), "/proc/%lu/environ", (unsigned long) pid);
        char_array_0(path);

        f = fopen(path, "re");
        if (!f)
                return -errno;

        l = strlen(field);
        r = 0;

        do {
                char line[LINE_MAX];
                unsigned i;

                for (i = 0; i < sizeof(line)-1; i++) {
                        int c;

                        c = getc(f);
                        if (_unlikely_(c == EOF)) {
                                done = true;
                                break;
                        } else if (c == 0)
                                break;

                        line[i] = c;
                }
                line[i] = 0;

                if (memcmp(line, field, l) == 0 && line[l] == '=') {
                        value = strdup(line + l + 1);
                        if (!value) {
                                r = -ENOMEM;
                                break;
                        }

                        r = 1;
                        break;
                }

        } while (!done);

        fclose(f);

        if (r >= 0)
                *_value = value;

        return r;
}

int can_sleep(const char *type) {
        char *w, *state;
        size_t l, k;
        int r;
        _cleanup_free_ char *p = NULL;

        assert(type);

        r = read_one_line_file("/sys/power/state", &p);
        if (r < 0)
                return r == -ENOENT ? 0 : r;

        k = strlen(type);
        FOREACH_WORD_SEPARATOR(w, l, p, WHITESPACE, state)
                if (l == k && memcmp(w, type, l) == 0)
                        return true;

        return false;
}

int can_sleep_disk(const char *type) {
        char *w, *state;
        size_t l, k;
        int r;
        _cleanup_free_ char *p = NULL;

        assert(type);

        r = read_one_line_file("/sys/power/disk", &p);
        if (r < 0)
                return r == -ENOENT ? 0 : r;

        k = strlen(type);
        FOREACH_WORD_SEPARATOR(w, l, p, WHITESPACE, state) {
                if (l == k && memcmp(w, type, l) == 0)
                        return true;

                if (l == k + 2 && w[0] == '[' && memcmp(w + 1, type, l - 2) == 0 && w[l-1] == ']')
                        return true;
        }

        return false;
}

bool is_valid_documentation_url(const char *url) {
        assert(url);

        if (startswith(url, "http://") && url[7])
                return true;

        if (startswith(url, "https://") && url[8])
                return true;

        if (startswith(url, "file:") && url[5])
                return true;

        if (startswith(url, "info:") && url[5])
                return true;

        if (startswith(url, "man:") && url[4])
                return true;

        return false;
}

bool in_initrd(void) {
        static __thread int saved = -1;
        struct statfs s;

        if (saved >= 0)
                return saved;

        /* We make two checks here:
         *
         * 1. the flag file /etc/initrd-release must exist
         * 2. the root file system must be a memory file system
         *
         * The second check is extra paranoia, since misdetecting an
         * initrd can have bad bad consequences due the initrd
         * emptying when transititioning to the main systemd.
         */

        saved = access("/etc/initrd-release", F_OK) >= 0 &&
                statfs("/", &s) >= 0 &&
                (s.f_type == TMPFS_MAGIC || s.f_type == RAMFS_MAGIC);

        return saved;
}

void warn_melody(void) {
        _cleanup_close_ int fd = -1;

        fd = open("/dev/console", O_WRONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0)
                return;

        /* Yeah, this is synchronous. Kinda sucks. But well... */

        ioctl(fd, KIOCSOUND, (int)(1193180/440));
        usleep(125*USEC_PER_MSEC);

        ioctl(fd, KIOCSOUND, (int)(1193180/220));
        usleep(125*USEC_PER_MSEC);

        ioctl(fd, KIOCSOUND, (int)(1193180/220));
        usleep(125*USEC_PER_MSEC);

        ioctl(fd, KIOCSOUND, 0);
}

int make_console_stdio(void) {
        int fd, r;

        /* Make /dev/console the controlling terminal and stdin/stdout/stderr */

        fd = acquire_terminal("/dev/console", false, true, true, (usec_t) -1);
        if (fd < 0) {
                log_error("Failed to acquire terminal: %s", strerror(-fd));
                return fd;
        }

        r = make_stdio(fd);
        if (r < 0) {
                log_error("Failed to duplicate terminal fd: %s", strerror(-r));
                return r;
        }

        return 0;
}

int get_home_dir(char **_h) {
        char *h;
        const char *e;
        uid_t u;
        struct passwd *p;

        assert(_h);

        /* Take the user specified one */
        e = getenv("HOME");
        if (e) {
                h = strdup(e);
                if (!h)
                        return -ENOMEM;

                *_h = h;
                return 0;
        }

        /* Hardcode home directory for root to avoid NSS */
        u = getuid();
        if (u == 0) {
                h = strdup("/root");
                if (!h)
                        return -ENOMEM;

                *_h = h;
                return 0;
        }

        /* Check the database... */
        errno = 0;
        p = getpwuid(u);
        if (!p)
                return errno ? -errno : -ESRCH;

        if (!path_is_absolute(p->pw_dir))
                return -EINVAL;

        h = strdup(p->pw_dir);
        if (!h)
                return -ENOMEM;

        *_h = h;
        return 0;
}

int get_shell(char **_sh) {
        char *sh;
        const char *e;
        uid_t u;
        struct passwd *p;

        assert(_sh);

        /* Take the user specified one */
        e = getenv("SHELL");
        if (e) {
                sh = strdup(e);
                if (!sh)
                        return -ENOMEM;

                *_sh = sh;
                return 0;
        }

        /* Hardcode home directory for root to avoid NSS */
        u = getuid();
        if (u == 0) {
                sh = strdup("/bin/sh");
                if (!sh)
                        return -ENOMEM;

                *_sh = sh;
                return 0;
        }

        /* Check the database... */
        errno = 0;
        p = getpwuid(u);
        if (!p)
                return errno ? -errno : -ESRCH;

        if (!path_is_absolute(p->pw_shell))
                return -EINVAL;

        sh = strdup(p->pw_shell);
        if (!sh)
                return -ENOMEM;

        *_sh = sh;
        return 0;
}

void freep(void *p) {
        free(*(void**) p);
}

void fclosep(FILE **f) {
        if (*f)
                fclose(*f);
}

void closep(int *fd) {
        if (*fd >= 0)
                close_nointr_nofail(*fd);
}

void closedirp(DIR **d) {
        if (*d)
                closedir(*d);
}

void umaskp(mode_t *u) {
        umask(*u);
}

bool filename_is_safe(const char *p) {

        if (isempty(p))
                return false;

        if (strchr(p, '/'))
                return false;

        if (streq(p, "."))
                return false;

        if (streq(p, ".."))
                return false;

        if (strlen(p) > FILENAME_MAX)
                return false;

        return true;
}

bool string_is_safe(const char *p) {
        const char *t;

        assert(p);

        for (t = p; *t; t++) {
                if (*t > 0 && *t < ' ')
                        return false;

                if (strchr("\\\"\'", *t))
                        return false;
        }

        return true;
}

int parse_timestamp(const char *t, usec_t *usec) {
        const char *k;
        struct tm tm, copy;
        time_t x;
        usec_t plus = 0, minus = 0, ret;
        int r;

        /*
         * Allowed syntaxes:
         *
         *   2012-09-22 16:34:22
         *   2012-09-22 16:34     (seconds will be set to 0)
         *   2012-09-22           (time will be set to 00:00:00)
         *   16:34:22             (date will be set to today)
         *   16:34                (date will be set to today, seconds to 0)
         *   now
         *   yesterday            (time is set to 00:00:00)
         *   today                (time is set to 00:00:00)
         *   tomorrow             (time is set to 00:00:00)
         *   +5min
         *   -5days
         *
         */

        assert(t);
        assert(usec);

        x = time(NULL);
        assert_se(localtime_r(&x, &tm));

        if (streq(t, "now"))
                goto finish;

        else if (streq(t, "today")) {
                tm.tm_sec = tm.tm_min = tm.tm_hour = 0;
                goto finish;

        } else if (streq(t, "yesterday")) {
                tm.tm_mday --;
                tm.tm_sec = tm.tm_min = tm.tm_hour = 0;
                goto finish;

        } else if (streq(t, "tomorrow")) {
                tm.tm_mday ++;
                tm.tm_sec = tm.tm_min = tm.tm_hour = 0;
                goto finish;

        } else if (t[0] == '+') {

                r = parse_usec(t+1, &plus);
                if (r < 0)
                        return r;

                goto finish;
        } else if (t[0] == '-') {

                r = parse_usec(t+1, &minus);
                if (r < 0)
                        return r;

                goto finish;
        }

        copy = tm;
        k = strptime(t, "%y-%m-%d %H:%M:%S", &tm);
        if (k && *k == 0)
                goto finish;

        tm = copy;
        k = strptime(t, "%Y-%m-%d %H:%M:%S", &tm);
        if (k && *k == 0)
                goto finish;

        tm = copy;
        k = strptime(t, "%y-%m-%d %H:%M", &tm);
        if (k && *k == 0) {
                tm.tm_sec = 0;
                goto finish;
        }

        tm = copy;
        k = strptime(t, "%Y-%m-%d %H:%M", &tm);
        if (k && *k == 0) {
                tm.tm_sec = 0;
                goto finish;
        }

        tm = copy;
        k = strptime(t, "%y-%m-%d", &tm);
        if (k && *k == 0) {
                tm.tm_sec = tm.tm_min = tm.tm_hour = 0;
                goto finish;
        }

        tm = copy;
        k = strptime(t, "%Y-%m-%d", &tm);
        if (k && *k == 0) {
                tm.tm_sec = tm.tm_min = tm.tm_hour = 0;
                goto finish;
        }

        tm = copy;
        k = strptime(t, "%H:%M:%S", &tm);
        if (k && *k == 0)
                goto finish;

        tm = copy;
        k = strptime(t, "%H:%M", &tm);
        if (k && *k == 0) {
                tm.tm_sec = 0;
                goto finish;
        }

        return -EINVAL;

finish:
        x = mktime(&tm);
        if (x == (time_t) -1)
                return -EINVAL;

        ret = (usec_t) x * USEC_PER_SEC;

        ret += plus;
        if (ret > minus)
                ret -= minus;
        else
                ret = 0;

        *usec = ret;

        return 0;
}

/* hey glibc, APIs with callbacks without a user pointer are so useless */
void *xbsearch_r(const void *key, const void *base, size_t nmemb, size_t size,
                 int (*compar) (const void *, const void *, void *), void *arg) {
        size_t l, u, idx;
        const void *p;
        int comparison;

        l = 0;
        u = nmemb;
        while (l < u) {
                idx = (l + u) / 2;
                p = (void *)(((const char *) base) + (idx * size));
                comparison = compar(key, p, arg);
                if (comparison < 0)
                        u = idx;
                else if (comparison > 0)
                        l = idx + 1;
                else
                        return (void *)p;
        }
        return NULL;
}

bool is_locale_utf8(void) {
        const char *set;
        static int cached_answer = -1;

        if (cached_answer >= 0)
                goto out;

        if (!setlocale(LC_ALL, "")) {
                cached_answer = true;
                goto out;
        }

        set = nl_langinfo(CODESET);
        if (!set) {
                cached_answer = true;
                goto out;
        }

        cached_answer = streq(set, "UTF-8");
out:
        return (bool)cached_answer;
}

const char *draw_special_char(DrawSpecialChar ch) {
        static const char *draw_table[2][_DRAW_SPECIAL_CHAR_MAX] = {
                /* UTF-8 */ {
                        [DRAW_TREE_VERT]          = "\342\224\202 ",            /* │  */
                        [DRAW_TREE_BRANCH]        = "\342\224\234\342\224\200", /* ├─ */
                        [DRAW_TREE_RIGHT]         = "\342\224\224\342\224\200", /* └─ */
                        [DRAW_TRIANGULAR_BULLET]  = "\342\200\243 ",            /* ‣  */
                },
                /* ASCII fallback */ {
                        [DRAW_TREE_VERT]          = "| ",
                        [DRAW_TREE_BRANCH]        = "|-",
                        [DRAW_TREE_RIGHT]         = "`-",
                        [DRAW_TRIANGULAR_BULLET]  = "> ",
                }
        };

        return draw_table[!is_locale_utf8()][ch];
}

char *strreplace(const char *text, const char *old_string, const char *new_string) {
        const char *f;
        char *t, *r;
        size_t l, old_len, new_len;

        assert(text);
        assert(old_string);
        assert(new_string);

        old_len = strlen(old_string);
        new_len = strlen(new_string);

        l = strlen(text);
        r = new(char, l+1);
        if (!r)
                return NULL;

        f = text;
        t = r;
        while (*f) {
                char *a;
                size_t d, nl;

                if (!startswith(f, old_string)) {
                        *(t++) = *(f++);
                        continue;
                }

                d = t - r;
                nl = l - old_len + new_len;
                a = realloc(r, nl + 1);
                if (!a)
                        goto oom;

                l = nl;
                r = a;
                t = r + d;

                t = stpcpy(t, new_string);
                f += old_len;
        }

        *t = 0;
        return r;

oom:
        free(r);
        return NULL;
}
