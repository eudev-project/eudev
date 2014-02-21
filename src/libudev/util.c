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
#include <poll.h>
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
#include "fileio.h"

int saved_argc = 0;
char **saved_argv = NULL;

static volatile unsigned cached_columns = 0;
static volatile unsigned cached_lines = 0;

size_t page_size(void) {
        static thread_local size_t pgsz = 0;
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

        if (t == (usec_t) -1)
                return NULL;

        if (t <= 0) {
                snprintf(p, l, "0");
                p[l-1] = 0;
                return p;
        }

        /* The result of this function can be parsed with parse_sec */

        for (i = 0; i < ELEMENTSOF(table); i++) {
                int k;
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
                                             "%s%llu.%0*llu%s",
                                             p > buf ? " " : "",
                                             (unsigned long long) a,
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
                                     "%s%llu%s",
                                     p > buf ? " " : "",
                                     (unsigned long long) a,
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

int unlink_noerrno(const char *path) {
        PROTECT_ERRNO;
        int r;

        r = unlink(path);
        if (r < 0)
                return -errno;

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

char hexchar(int x) {
        static const char table[16] = "0123456789abcdef";

        return table[x & 15];
}

char octchar(int x) {
        return '0' + (x & 7);
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

void random_bytes(void *p, size_t n) {
        static bool srand_called = false;
        _cleanup_close_ int fd;
        ssize_t k;
        uint8_t *q;

        fd = open("/dev/urandom", O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0)
                goto fallback;

        k = loop_read(fd, p, n, true);
        if (k < 0 || (size_t) k != n)
                goto fallback;

        return;

fallback:

        if (!srand_called) {

#ifdef HAVE_SYS_AUXV_H
                /* The kernel provides us with a bit of entropy in
                 * auxv, so let's try to make use of that to seed the
                 * pseudo-random generator. It's better than
                 * nothing... */

                void *auxv;

                auxv = (void*) getauxval(AT_RANDOM);
                if (auxv)
                        srand(*(unsigned*) auxv);
                else
#endif
                        srand(time(NULL) + gettid());

                srand_called = true;
        }

        /* If some idiot made /dev/urandom unavailable to us, he'll
         * get a PRNG instead. */
        for (q = p; q < (uint8_t*) p + n; q ++)
                *q = rand();
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

        assert(!(mode & O_CREAT));

        for (;;) {
                fd = open(name, mode, 0);
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

_pure_ static int is_temporary_fs(struct statfs *s) {
        assert(s);

        return F_TYPE_EQUAL(s->f_type, TMPFS_MAGIC) ||
               F_TYPE_EQUAL(s->f_type, RAMFS_MAGIC);
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

bool nulstr_contains(const char*nulstr, const char *needle) {
        const char *i;

        if (!nulstr)
                return false;

        NULSTR_FOREACH(i, nulstr)
                if (streq(i, needle))
                        return true;

        return false;
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

                                /* We knowingly ignore the revents value here,
                                 * and expect that any error/EOF is reported
                                 * via read()/write()
                                 */

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

int proc_cmdline(char **ret) {
        int r;

	/* disable containers for now
        if (detect_container(NULL) > 0) {
                char *buf, *p;
                size_t sz = 0;

                r = read_full_file("/proc/1/cmdline", &buf, &sz);
                if (r < 0)
                        return r;

                for (p = buf; p + 1 < buf + sz; p++)
                        if (*p == 0)
                                *p = ' ';

                *p  = 0;
                *ret = buf;
                return 1;
        }
	*/

        r = read_one_line_file("/proc/cmdline", ret);
        if (r < 0)
                return r;

        return 1;
}

int getpeercred(int fd, struct ucred *ucred) {
        socklen_t n = sizeof(struct ucred);
        struct ucred u;
        int r;

        assert(fd >= 0);
        assert(ucred);

        r = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &u, &n);
        if (r < 0)
                return -errno;

        if (n != sizeof(struct ucred))
                return -EIO;

        /* Check if the data is actually useful and not suppressed due
         * to namespacing issues */
        if (u.pid <= 0)
                return -ENODATA;

        *ucred = u;
        return 0;
}
