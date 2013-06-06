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
#include "env-util.h"

int saved_argc = 0;
char **saved_argv = NULL;

static volatile unsigned cached_columns = 0;
static volatile unsigned cached_lines = 0;

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
        const char *a, *b;

        assert(s);
        assert(prefix);

        a = s, b = prefix;
        for (;;) {
                if (*b == 0)
                        return (char*) a;
                if (*a != *b)
                        return NULL;

                a++, b++;
        }
}

int close_nointr(int fd) {
        int r;

        assert(fd >= 0);
        r = close(fd);

        /* Just ignore EINTR; a retry loop is the wrong
         * thing to do on Linux.
         *
         * http://lkml.indiana.edu/hypermail/linux/kernel/0509.1/0877.html
         * https://bugzilla.gnome.org/show_bug.cgi?id=682819
         * http://utcc.utoronto.ca/~cks/space/blog/unix/CloseEINTR
         * https://sites.google.com/site/michaelsafyan/software-engineering/checkforeintrwheninvokingclosethinkagain
         */
        if (_unlikely_(r < 0 && errno == EINTR))
                return 0;
        else if (r >= 0)
                return r;
        else
                return -errno;
}

void close_nointr_nofail(int fd) {
        PROTECT_ERRNO;

        /* like close_nointr() but cannot fail, and guarantees errno
         * is unchanged */

        assert_se(close_nointr(fd) == 0);
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
                return errno > 0 ? -errno : -EINVAL;

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
                return errno > 0 ? -errno : -EINVAL;

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

char *truncate_nl(char *s) {
        assert(s);

        s[strcspn(s, NEWLINE)] = 0;
        return s;
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

_pure_ static bool ignore_file_allow_backup(const char *filename) {
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

_pure_ static bool fd_in_set(int fd, const int fdset[], unsigned n_fdset) {
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
        struct pollfd pollfd = {
                .fd = fd,
                .events = POLLIN,
        };

        for (;;) {
                char buf[LINE_MAX];
                ssize_t l;
                int r;

                r = poll(&pollfd, 1, 0);
                if (r < 0) {
                        if (errno == EINTR)
                                continue;

                        return -errno;

                } else if (r == 0)
                        return 0;

                l = read(fd, buf, sizeof(buf));
                if (l < 0) {

                        if (errno == EINTR)
                                continue;

                        if (errno == EAGAIN)
                                return 0;

                        return -errno;
                } else if (l == 0)
                        return 0;
        }
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
                                struct pollfd pollfd = {
                                        .fd = fd,
                                        .events = POLLIN,
                                };

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

int get_ctty_devnr(pid_t pid, dev_t *d) {
        _cleanup_fclose_ FILE *f = NULL;
        char line[LINE_MAX], *p;
        unsigned long ttynr;
        const char *fn;
        int k;

        assert(pid >= 0);
        assert(d);

        if (pid == 0)
                fn = "/proc/self/stat";
        else
                fn = procfs_file_alloca(pid, "stat");

        f = fopen(fn, "re");
        if (!f)
                return -errno;

        if (!fgets(line, sizeof(line), f)) {
                k = feof(f) ? -EIO : -errno;
                return k;
        }

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

        if (major(ttynr) == 0 && minor(ttynr) == 0)
                return -ENOENT;

        *d = (dev_t) ttynr;
        return 0;
}

int get_ctty(pid_t pid, dev_t *_devnr, char **r) {
        int k;
        char fn[sizeof("/dev/char/")-1 + 2*DECIMAL_STR_MAX(unsigned) + 1 + 1], *s, *b, *p;
        dev_t devnr;

        assert(r);

        k = get_ctty_devnr(pid, &devnr);
        if (k < 0)
                return k;

        snprintf(fn, sizeof(fn), "/dev/char/%u:%u", major(devnr), minor(devnr));

        k = readlink_malloc(fn, &s);
        if (k < 0) {

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

                b = strdup(fn + 5);
                if (!b)
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

_pure_ static int is_temporary_fs(struct statfs *s) {
        assert(s);
        return
                F_TYPE_CMP(s->f_type, TMPFS_MAGIC) ||
                F_TYPE_CMP(s->f_type, RAMFS_MAGIC);
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
        if (!is_temporary_fs(&s)) {
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

                        if (!is_temporary_fs(&s)) {
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

                if (!is_temporary_fs(&s)) {
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

int status_vprintf(const char *status, bool ellipse, bool ephemeral, const char *format, va_list ap) {
        static const char status_indent[] = "         "; /* "[" STATUS "] " */
        _cleanup_free_ char *s = NULL;
        _cleanup_close_ int fd = -1;
        struct iovec iovec[6] = {};
        int n = 0;
        static bool prev_ephemeral;

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

        if (prev_ephemeral)
                IOVEC_SET_STRING(iovec[n++], "\r" ANSI_ERASE_TO_END_OF_LINE);
        prev_ephemeral = ephemeral;

        if (status) {
                if (!isempty(status)) {
                        IOVEC_SET_STRING(iovec[n++], "[");
                        IOVEC_SET_STRING(iovec[n++], status);
                        IOVEC_SET_STRING(iovec[n++], "] ");
                } else
                        IOVEC_SET_STRING(iovec[n++], status_indent);
        }

        IOVEC_SET_STRING(iovec[n++], s);
        if (!ephemeral)
                IOVEC_SET_STRING(iovec[n++], "\n");

        if (writev(fd, iovec, n) < 0)
                return -errno;

        return 0;
}

int fd_columns(int fd) {
        struct winsize ws = {};

        if (ioctl(fd, TIOCGWINSZ, &ws) < 0)
                return -errno;

        if (ws.ws_col <= 0)
                return -EIO;

        return ws.ws_col;
}

unsigned columns(void) {
        const char *e;
        int c;

        if (_likely_(cached_columns > 0))
                return cached_columns;

        c = 0;
        e = getenv("COLUMNS");
        if (e)
                safe_atoi(e, &c);

        if (c <= 0)
                c = fd_columns(STDOUT_FILENO);

        if (c <= 0)
                c = 80;

        cached_columns = c;
        return c;
}

int fd_lines(int fd) {
        struct winsize ws = {};

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

bool on_tty(void) {
        static int cached_on_tty = -1;

        if (_unlikely_(cached_on_tty < 0))
                cached_on_tty = isatty(STDOUT_FILENO) > 0;

        return cached_on_tty;
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

bool tty_is_vc(const char *tty) {
        assert(tty);

        if (startswith(tty, "/dev/"))
                tty += 5;

        return vtnr_from_tty(tty) >= 0;
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

char *resolve_dev_console(char **active) {
        char *tty;

        /* Resolve where /dev/console is pointing to, if /sys is actually ours
         * (i.e. not read-only-mounted which is a sign for container setups) */

        if (path_is_read_only_fs("/sys") > 0)
                return NULL;

        if (read_one_line_file("/sys/class/tty/console/active", active) < 0)
                return NULL;

        /* If multiple log outputs are configured the last one is what
         * /dev/console points to */
        tty = strrchr(*active, ' ');
        if (tty)
                tty++;
        else
                tty = *active;

        return tty;
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

int fd_wait_for_event(int fd, int event, usec_t t) {
        int r;
        struct pollfd pollfd = {
                .fd = fd,
                .events = event,
        };

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
        static __thread char buf[sizeof("RTMIN+")-1 + DECIMAL_STR_MAX(int) + 1];
        const char *name;

        name = __signal_to_string(signo);
        if (name)
                return name;

        if (signo >= SIGRTMIN && signo <= SIGRTMAX)
                snprintf(buf, sizeof(buf), "RTMIN+%d", signo - SIGRTMIN);
        else
                snprintf(buf, sizeof(buf), "%d", signo);

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
                is_temporary_fs(&s);

        return saved;
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

