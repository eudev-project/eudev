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
#include <stdarg.h>
#include <poll.h>
#include <ctype.h>
#include <sys/prctl.h>
#include <sys/utsname.h>
#include <netinet/ip.h>
#include <linux/kd.h>
#include <dlfcn.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <glob.h>
#include <sys/mman.h>
#include <sys/vfs.h>
#include <linux/magic.h>
#include <limits.h>
#include <locale.h>
#include <libgen.h>
#include <inttypes.h>

#include "macro.h"
#include "util.h"
#include "ioprio.h"
#include "missing.h"
#include "log.h"
#include "strv.h"
#include "mkdir.h"
#include "path-util.h"
#include "hashmap.h"
#include "fileio.h"
#include "utf8.h"
#include "virt.h"
#include "process-util.h"
#include "random-util.h"
#include "terminal-util.h"

/* Put this test here for a lack of better place */
assert_cc(EAGAIN == EWOULDBLOCK);

int saved_argc = 0;
char **saved_argv = NULL;

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

#ifndef CGROUP2_SUPER_MAGIC
#define CGROUP2_SUPER_MAGIC 0x63677270
#endif

/* Whether the comma separated list contains the word. */
static bool list_contains_word(const char *list, const char *word) {
        size_t n = strlen(word);

        for (;;) {
                if (strneq(list, word, n) && IN_SET(list[n], ',', '\0'))
                        return true;

                list = strchr(list, ',');
                if (!list)
                        return false;
                list++;
        }
}

/* Like cg_get_root_path() of systemd: the cgroup of PID 1, without a trailing "/init.scope". With controller
 * NULL in the unified hierarchy (cgroup v2), otherwise in the hierarchy of cgroup v1 that the controller is
 * attached to, like cg_pid_get_path() of systemd v257 for such a hierarchy. */
static int cg_get_root_path(const char *controller, char **ret) {
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(ret);

        f = fopen("/proc/1/cgroup", "re");
        if (!f)
                return errno == ENOENT ? -ESRCH : -errno;

        for (;;) {
                _cleanup_free_ char *line = NULL;
                char *e, *path;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -ENODATA;

                if (!controller) {
                        e = startswith(line, "0:");
                        if (!e)
                                continue;

                        e = strchr(e, ':');
                        if (!e)
                                continue;
                } else {
                        char *l;

                        /* "ID:CONTROLLER,CONTROLLER,...:PATH" */
                        l = strchr(line, ':');
                        if (!l)
                                continue;

                        l++;
                        e = strchr(l, ':');
                        if (!e)
                                continue;
                        *e = 0;

                        if (!list_contains_word(l, controller))
                                continue;
                }

                path = strdup(e + 1);
                if (!path)
                        return -ENOMEM;

                /* Refuse cgroup paths from outside our cgroup namespace */
                if (startswith(path, "/../")) {
                        free(path);
                        return -EUNATCH;
                }

                /* Truncate suffix indicating the process is a zombie */
                e = endswith(path, " (deleted)");
                if (e)
                        *e = 0;

                e = endswith(path, "/init.scope");
                if (e)
                        *e = 0;

                *ret = path;
                return 0;
        }
}

/* Whether the controllers are in cgroup v1: like cg_all_unified() of systemd v257, which is false when
 * /sys/fs/cgroup is a tmpfs, in the "legacy" and the "hybrid" setups, with the hierarchies of cgroup v1 mounted
 * below it; in the hybrid setup, cgroup v2 is mounted below it too, but without controllers. Unlike systemd
 * v257, which refused a tmpfs without its own hierarchy /sys/fs/cgroup/systemd or cgroup v2 on
 * /sys/fs/cgroup/unified, any tmpfs means cgroup v1 here, e.g. also as set up by OpenRC. Anything else,
 * cgroup v2 or nothing mounted, is handled as cgroup v2, like systemd a446e8ff2c does. */
static bool cg_is_legacy(void) {
        struct statfs fs;

        if (statfs("/sys/fs/cgroup/", &fs) < 0)
                return false;

        return F_TYPE_EQUAL(fs.f_type, TMPFS_MAGIC);
}

uint64_t physical_memory(void) {
        _cleanup_free_ char *root = NULL, *p = NULL, *value = NULL;
        uint64_t mem, lim;
        size_t ps;
        long sc;
        bool legacy;
        int r;

        /* We return this as uint64_t in case we are running as 32-bit process on a 64-bit kernel with huge amounts of
         * memory.
         *
         * In order to support containers nicely that have a configured memory limit we'll take the minimum of the
         * physically reported amount of memory and the limit configured for the root cgroup, if there is any. */

        sc = sysconf(_SC_PHYS_PAGES);
        assert(sc > 0);

        ps = page_size();
        /* Physical page count times page size cannot realistically overflow uint64_t, but make this obvious. */
        assert((uint64_t) sc <= UINT64_MAX / ps);
        mem = (uint64_t) sc * (uint64_t) ps;

        /* eudev: like systemd v231 to v257, read the limit of cgroup v1 too, memory.limit_in_bytes, which
         * systemd a446e8ff2c no longer does. systemd took the cgroup of PID 1 in its own hierarchy
         * (name=systemd), which exists only when systemd is PID 1, and read the file of that cgroup in the
         * hierarchy of the memory controller; here, the cgroup of PID 1 in that hierarchy is used. */
        legacy = cg_is_legacy();

        r = cg_get_root_path(legacy ? "memory" : NULL, &root);
        if (r < 0) {
                log_debug_errno(r, "Failed to determine root cgroup, ignoring cgroup memory limit: %m");
                return mem;
        }

        if (legacy) {
                p = strjoin("/sys/fs/cgroup/memory/", root, "/memory.limit_in_bytes", NULL);
                if (!p) {
                        log_oom_debug();
                        return mem;
                }

                r = read_one_line_file(p, &value);
                if (r < 0) {
                        log_debug_errno(r, "Failed to read memory.limit_in_bytes cgroup attribute, ignoring cgroup memory limit: %m");
                        return mem;
                }
        } else {
                p = strjoin("/sys/fs/cgroup/", root, "/memory.max", NULL);
                if (!p) {
                        log_oom_debug();
                        return mem;
                }

                r = read_one_line_file(p, &value);
                if (r == -ENOENT) /* Field does not exist on the system's top-level cgroup, hence don't
                                   * complain. (Note that it might exist on our own root though, if we live
                                   * in a cgroup namespace, hence check anyway instead of not even
                                   * trying.) */
                        return mem;
                if (r < 0) {
                        log_debug_errno(r, "Failed to read memory.max cgroup attribute, ignoring cgroup memory limit: %m");
                        return mem;
                }

                if (streq(value, "max"))
                        return mem;
        }

        r = safe_atou64(value, &lim);
        if (r < 0) {
                log_debug_errno(r, "Failed to parse cgroup memory limit '%s', ignoring: %m", value);
                return mem;
        }
        if (lim == UINT64_MAX)
                return mem;

        /* Make sure the limit is a multiple of our own page size */
        lim /= ps;
        lim *= ps;

        return MIN(mem, lim);
}

int cpus_in_affinity_mask(void) {
        size_t n = 16;
        int r;

        for (;;) {
                cpu_set_t *c;

                c = CPU_ALLOC(n);
                if (!c)
                        return -ENOMEM;

                if (sched_getaffinity(0, CPU_ALLOC_SIZE(n), c) >= 0) {
                        int k;

                        k = CPU_COUNT_S(CPU_ALLOC_SIZE(n), c);
                        CPU_FREE(c);

                        if (k <= 0)
                                return -EINVAL;

                        return k;
                }

                r = -errno;
                CPU_FREE(c);

                if (r != -EINVAL)
                        return r;
                if (n > SIZE_MAX/2)
                        return -ENOMEM;
                n *= 2;
        }
}

/* Like close_all_fds() of systemd without exceptions: closes all file descriptors above stderr, e.g. in a
 * child process, like FORK_CLOSE_ALL_FDS. Call log_close() before, as the descriptors of the log are closed
 * too. */
int close_all_fds(void) {
        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;
        int r = 0;

#ifdef __NR_close_range
        /* Linux 5.9 or newer */
        if (syscall(__NR_close_range, 3U, ~0U, 0) >= 0)
                return 0;
#endif

        d = opendir("/proc/self/fd");
        if (!d) {
                long m;
                int fd;

                /* Without /proc, close all possible ones. */
                m = sysconf(_SC_OPEN_MAX);
                if (m <= 0 || m > INT_MAX)
                        m = 65536;

                for (fd = 3; fd < m; fd++)
                        (void) close(fd);

                return 0;
        }

        while ((de = readdir(d))) {
                int fd, k;

                if (safe_atoi(de->d_name, &fd) < 0 || fd <= STDERR_FILENO || fd == dirfd(d))
                        continue;

                k = close_nointr(fd);
                if (k < 0 && k != -EBADF && r == 0)
                        r = k;
        }

        return r;
}

bool streq_ptr(const char *a, const char *b) {

        /* Like streq(), but tries to make sense of NULL pointers */

        if (a && b)
                return streq(a, b);

        if (!a && !b)
                return true;

        return false;
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

size_t cescape_char(char c, char *buf) {
        char * buf_old = buf;

        switch (c) {

                case '\a':
                        *(buf++) = '\\';
                        *(buf++) = 'a';
                        break;
                case '\b':
                        *(buf++) = '\\';
                        *(buf++) = 'b';
                        break;
                case '\f':
                        *(buf++) = '\\';
                        *(buf++) = 'f';
                        break;
                case '\n':
                        *(buf++) = '\\';
                        *(buf++) = 'n';
                        break;
                case '\r':
                        *(buf++) = '\\';
                        *(buf++) = 'r';
                        break;
                case '\t':
                        *(buf++) = '\\';
                        *(buf++) = 't';
                        break;
                case '\v':
                        *(buf++) = '\\';
                        *(buf++) = 'v';
                        break;
                case '\\':
                        *(buf++) = '\\';
                        *(buf++) = '\\';
                        break;
                case '"':
                        *(buf++) = '\\';
                        *(buf++) = '"';
                        break;
                case '\'':
                        *(buf++) = '\\';
                        *(buf++) = '\'';
                        break;

                default:
                        /* For special chars we prefer octal over
                         * hexadecimal encoding, simply because glib's
                         * g_strescape() does the same */
                        if ((c < ' ') || (c >= 127)) {
                                *(buf++) = '\\';
                                *(buf++) = octchar((unsigned char) c >> 6);
                                *(buf++) = octchar((unsigned char) c >> 3);
                                *(buf++) = octchar((unsigned char) c);
                        } else
                                *(buf++) = c;
                        break;
        }

        return buf - buf_old;
}

int close_nointr(int fd) {
        assert(fd >= 0);

        if (close(fd) >= 0)
                return 0;

        /*
         * Just ignore EINTR; a retry loop is the wrong thing to do on
         * Linux.
         *
         * http://lkml.indiana.edu/hypermail/linux/kernel/0509.1/0877.html
         * https://bugzilla.gnome.org/show_bug.cgi?id=682819
         * http://utcc.utoronto.ca/~cks/space/blog/unix/CloseEINTR
         * https://sites.google.com/site/michaelsafyan/software-engineering/checkforeintrwheninvokingclosethinkagain
         */
        if (errno == EINTR)
                return 0;

        return -errno;
}

int safe_close(int fd) {

        /*
         * Like close_nointr() but cannot fail. Guarantees errno is
         * unchanged. Is a NOP with negative fds passed, and returns
         * -1, so that it can be used in this syntax:
         *
         * fd = safe_close(fd);
         */

        if (fd >= 0) {
                PROTECT_ERRNO;

                /* The kernel might return pretty much any error code
                 * via close(), but the fd will be closed anyway. The
                 * only condition we want to check for here is whether
                 * the fd was invalid at all... */

                assert_se(close_nointr(fd) != -EBADF);
        }

        return -1;
}

void close_many(const int fds[], unsigned n_fd) {
        unsigned i;

        assert(fds || n_fd <= 0);

        for (i = 0; i < n_fd; i++)
                safe_close(fds[i]);
}

int unlink_noerrno(const char *path) {
        PROTECT_ERRNO;
        int r;

        r = unlink(path);
        if (r < 0)
                return -errno;

        return 0;
}

int parse_uid(const char *s, uid_t* ret_uid) {
        unsigned uid = 0;
        int r;

        assert(s);

        assert_cc(sizeof(uid_t) == sizeof(unsigned));

        /* We are very strict when parsing UIDs, and prohibit +/- as prefix, leading zero as prefix, and
         * whitespace. We do this, since this call is often used in a context where we parse things as UID
         * first, and if that doesn't work we fall back to NSS. Thus we really want to make sure that UIDs
         * are parsed as UIDs only if they really really look like UIDs. */
        r = safe_atou_full(s, 10
                           | SAFE_ATO_REFUSE_PLUS_MINUS
                           | SAFE_ATO_REFUSE_LEADING_ZERO
                           | SAFE_ATO_REFUSE_LEADING_WHITESPACE, &uid);
        if (r < 0)
                return r;

        /* Some libc APIs use UID_INVALID as special placeholder */
        if (uid == (uid_t) 0xFFFFFFFF)
                return -ENXIO;

        /* A long time ago UIDs where 16bit, hence explicitly avoid the 16bit -1 too */
        if (uid == (uid_t) 0xFFFF)
                return -ENXIO;

        if (ret_uid)
                *ret_uid = uid;

        return 0;
}

/* Like parse_mode() of systemd: an octal mode of at most 07777, without a sign; leading whitespace is
 * fine. */
int parse_mode(const char *s, mode_t *ret) {
        unsigned m;
        int r;

        assert(s);

        r = safe_atou_full(s, 8 |
                           SAFE_ATO_REFUSE_PLUS_MINUS, /* Leading '+' or even '-' char? that's just weird,
                                                        * refuse. User might have wanted to add mode flags or
                                                        * so, but this parser doesn't allow that, so let's
                                                        * better be safe. */
                           &m);
        if (r < 0)
                return r;
        if (m > 07777)
                return -ERANGE;

        if (ret)
                *ret = m;
        return 0;
}

/* Like first_word() of systemd: if s starts with the word, followed by the end of s or by whitespace, returns
 * the position after the whitespace, else NULL. */
static const char *first_word(const char *s, const char *word) {
        const char *p, *nw;

        p = startswith(s, word);
        if (!p)
                return NULL;
        if (*p == '\0')
                return p;

        nw = p + strspn(p, WHITESPACE);
        if (nw == p)
                return NULL;

        return nw;
}

/* The highest IDs of system users and groups, like the UGIDAllocationRange of systemd, without the lowest IDs
 * for allocating them, which eudev does not need. */
typedef struct UGIDAllocationRange {
        uid_t system_uid_max;
        gid_t system_gid_max;
} UGIDAllocationRange;

/* The ones of --with-system-uid-max and --with-system-gid-max of configure */
static const UGIDAllocationRange default_ugid_allocation_range = {
        .system_uid_max = SYSTEM_UID_MAX,
        .system_gid_max = SYSTEM_GID_MAX,
};

static int parse_alloc_uid(const char *path, const char *name, const char *t, uid_t *ret_uid) {
        uid_t uid;
        int r;

        assert(ret_uid);

        r = parse_uid(t, &uid);
        if (r < 0)
                return log_debug_errno(r, "%s: failed to parse %s %s, ignoring: %m", path, name, t);
        if (uid == 0)
                uid = 1;

        *ret_uid = uid;
        return 0;
}

/* Like read_login_defs() of systemd, built with compat-mutable-uid-boundaries: reads SYS_UID_MAX and
 * SYS_GID_MAX of /etc/login.defs, the last of each that parses as a user or group ID counts. Without
 * the file, or for the settings that it does not have, the values of configure are taken. */
static int read_login_defs(UGIDAllocationRange *ret_defs, const char *path) {
        _cleanup_fclose_ FILE *f = NULL;
        UGIDAllocationRange defs;
        int r;

        assert(ret_defs);

        if (!path)
                path = "/etc/login.defs";

        f = fopen(path, "re");
        if (!f) {
                if (errno == ENOENT) {
                        *ret_defs = default_ugid_allocation_range;
                        return 0;
                }
                return log_debug_errno(errno, "Failed to open %s: %m", path);
        }

        defs = default_ugid_allocation_range;

        for (;;) {
                _cleanup_free_ char *line = NULL;
                const char *t;

                r = read_line(f, LINE_MAX, &line);
                if (r < 0)
                        return log_debug_errno(r, "Failed to read %s: %m", path);
                if (r == 0)
                        break;

                if ((t = first_word(line, "SYS_UID_MAX")))
                        (void) parse_alloc_uid(path, "SYS_UID_MAX", t, &defs.system_uid_max);
                else if ((t = first_word(line, "SYS_GID_MAX")))
                        (void) parse_alloc_uid(path, "SYS_GID_MAX", t, &defs.system_gid_max);
        }

        *ret_defs = defs;
        return 1;
}

/* Like acquire_ugid_allocation_range() of systemd: the file is read once per thread, and when it cannot be
 * read, the values of configure are taken. */
static const UGIDAllocationRange *acquire_ugid_allocation_range(void) {
        static thread_local UGIDAllocationRange defs;
        static thread_local int initialized = 0; /* == 0 → not initialized yet
                                                  * < 0 → failure
                                                  * > 0 → success */

        if (initialized == 0)
                initialized = read_login_defs(&defs, NULL) < 0 ? -1 : 1;
        if (initialized < 0)
                return &default_ugid_allocation_range;

        return &defs;
}

bool uid_is_system(uid_t uid) {
        return uid <= acquire_ugid_allocation_range()->system_uid_max;
}

bool gid_is_system(gid_t gid) {
        return gid <= acquire_ugid_allocation_range()->system_gid_max;
}

/* strtoul() and the other strto*() functions skip all leading characters for which isspace() is true, in
 * the C locale \v and \f as well as WHITESPACE. The safe_ato*() functions skip, or refuse, exactly those
 * characters too, so that their checks of the sign and of the base prefix see the character that strto*()
 * parses first. systemd skips only WHITESPACE there, so that it parses "\v-1" as an unsigned -1. */
static bool is_strto_space(char c) {
        return isspace((unsigned char) c);
}

static const char *skip_strto_space(const char *s) {
        while (is_strto_space(*s))
                s++;

        return s;
}

static const char *mangle_base(const char *s, unsigned *base) {
        const char *k;

        assert(s);
        assert(base);

        /* Base already explicitly specified, then don't do anything. */
        if (SAFE_ATO_MASK_FLAGS(*base) != 0)
                return s;

        /* Support Python 3 style "0b" and 0x" prefixes, because they truly make sense, much more than C's "0" prefix for octal. */
        k = startswith(s, "0b") ?: startswith(s, "0B");
        if (k) {
                *base = 2 | (*base & SAFE_ATO_ALL_FLAGS);
                return k;
        }

        k = startswith(s, "0o") ?: startswith(s, "0O");
        if (k) {
                *base = 8 | (*base & SAFE_ATO_ALL_FLAGS);
                return k;
        }

        return s;
}

int safe_atou_full(const char *s, unsigned base, unsigned *ret_u) {
        char *x = NULL;
        unsigned long l;

        assert(s);
        assert(SAFE_ATO_MASK_FLAGS(base) <= 16);

        /* strtoul() is happy to parse negative values, and silently converts them to unsigned values without
         * generating an error. We want a clean error, hence let's look for the "-" prefix on our own, and
         * generate an error. But let's do so only after strtoul() validated that the string is clean
         * otherwise, so that we return EINVAL preferably over ERANGE. */

        if (FLAGS_SET(base, SAFE_ATO_REFUSE_LEADING_WHITESPACE) &&
            is_strto_space(s[0]))
                return -EINVAL;

        s = skip_strto_space(s);

        if (FLAGS_SET(base, SAFE_ATO_REFUSE_PLUS_MINUS) &&
            (s[0] == '+' || s[0] == '-'))
                return -EINVAL; /* Note that we check the "-" prefix again a second time below, but return a
                                 * different error. I.e. if the SAFE_ATO_REFUSE_PLUS_MINUS flag is set we
                                 * blanket refuse +/- prefixed integers, while if it is missing we'll just
                                 * return ERANGE, because the string actually parses correctly, but doesn't
                                 * fit in the return type. */

        if (FLAGS_SET(base, SAFE_ATO_REFUSE_LEADING_ZERO) &&
            s[0] == '0' && !streq(s, "0"))
                return -EINVAL; /* This is particularly useful to avoid ambiguities between C's octal
                                 * notation and assumed-to-be-decimal integers with a leading zero. */

        s = mangle_base(s, &base);

        errno = 0;
        l = strtoul(s, &x, SAFE_ATO_MASK_FLAGS(base) /* Let's mask off the flags bits so that only the actual
                                                      * base is left */);
        if (errno > 0)
                return -errno;
        if (!x || x == s || *x != 0)
                return -EINVAL;
        if (l != 0 && s[0] == '-')
                return -ERANGE;
        if ((unsigned long) (unsigned) l != l)
                return -ERANGE;

        if (ret_u)
                *ret_u = (unsigned) l;

        return 0;
}

int safe_atoi(const char *s, int *ret_i) {
        unsigned base = 0;
        char *x = NULL;
        long l;

        assert(s);

        s = skip_strto_space(s);
        s = mangle_base(s, &base);

        errno = 0;
        l = strtol(s, &x, base);
        if (errno > 0)
                return -errno;
        if (!x || x == s || *x != 0)
                return -EINVAL;
        if ((long) (int) l != l)
                return -ERANGE;

        if (ret_i)
                *ret_i = (int) l;

        return 0;
}

static bool is_valid_version_char(char a) {
        return (a >= '0' && a <= '9') || (a >= 'a' && a <= 'z') || (a >= 'A' && a <= 'Z') ||
                IN_SET(a, '~', '-', '^', '.');
}

int strverscmp_improved(const char *a, const char *b) {
        /* This function is similar to strverscmp(3), but it treats '-' and '.' as separators.
         *
         * The logic is based on rpm's rpmvercmp(), but unlike rpmvercmp(), it distinguishes e.g.
         * '123a' and '123.a', with '123a' being newer.
         *
         * It allows direct comparison of strings which contain both a version and a release; e.g.
         * '247.2-3.1.fc33.x86_64' or '5.11.0-0.rc5.20210128git76c057c84d28.137.fc34'.
         *
         * The input string is split into segments. Each segment is numeric or alphabetic, and may be
         * prefixed with the following:
         *  '~' : used for pre-releases, a segment prefixed with this is the oldest,
         *  '-' : used for the separator between version and release,
         *  '^' : used for patched releases, a segment with this is newer than one with '-'.
         *  '.' : used for point releases.
         * Note that no prefix segment is the newest. All non-supported characters are dropped, and
         * handled as a separator of segments, e.g., '123_a' is equivalent to '123a'.
         *
         * By using this, version strings can be sorted like following:
         *  (older) 122.1
         *     ^    123~rc1-1
         *     |    123
         *     |    123-a
         *     |    123-a.1
         *     |    123-1
         *     |    123-1.1
         *     |    123^post1
         *     |    123.a-1
         *     |    123.1-1
         *     v    123a-1
         *  (newer) 124-1
         *
         * Taken from systemd. */

        a = a ?: "";
        b = b ?: "";

        for (;;) {
                const char *aa, *bb;
                int r;

                /* Drop leading invalid characters. */
                while (*a != '\0' && !is_valid_version_char(*a))
                        a++;
                while (*b != '\0' && !is_valid_version_char(*b))
                        b++;

                /* Handle '~'. Used for pre-releases, e.g. 123~rc1, or 4.5~alpha1 */
                if (*a == '~' || *b == '~') {
                        /* The string prefixed with '~' is older. */
                        r = CMP(*a != '~', *b != '~');
                        if (r != 0)
                                return r;

                        /* Now both strings are prefixed with '~'. Compare remaining strings. */
                        a++;
                        b++;
                }

                /* If at least one string reaches the end, then longer is newer.
                 * Note that except for '~' prefixed segments, a string which has more segments is newer.
                 * So, this check must be after the '~' check. */
                if (*a == '\0' || *b == '\0')
                        return CMP(*a, *b);

                /* Handle '-', which separates version and release, e.g 123.4-3.1.fc33.x86_64 */
                if (*a == '-' || *b == '-') {
                        /* The string prefixed with '-' is older (e.g., 123-9 vs 123.1-1) */
                        r = CMP(*a != '-', *b != '-');
                        if (r != 0)
                                return r;

                        a++;
                        b++;
                }

                /* Handle '^'. Used for patched release. */
                if (*a == '^' || *b == '^') {
                        r = CMP(*a != '^', *b != '^');
                        if (r != 0)
                                return r;

                        a++;
                        b++;
                }

                /* Handle '.'. Used for point releases. */
                if (*a == '.' || *b == '.') {
                        r = CMP(*a != '.', *b != '.');
                        if (r != 0)
                                return r;

                        a++;
                        b++;
                }

                if (ascii_isdigit(*a) || ascii_isdigit(*b)) {
                        /* Find the leading numeric segments. One may be an empty string. So,
                         * numeric segments are always newer than alpha segments. */
                        for (aa = a; ascii_isdigit(*aa); aa++)
                                ;
                        for (bb = b; ascii_isdigit(*bb); bb++)
                                ;

                        /* Check if one of the strings was empty, but the other not. */
                        r = CMP(a != aa, b != bb);
                        if (r != 0)
                                return r;

                        /* Skip leading '0', to make 00123 equivalent to 123. */
                        while (*a == '0')
                                a++;
                        while (*b == '0')
                                b++;

                        /* To compare numeric segments without parsing their values, first compare the
                         * lengths of the segments. Eg. 12345 vs 123, longer is newer. */
                        r = CMP(aa - a, bb - b);
                        if (r != 0)
                                return r;

                        /* Then, compare them as strings. */
                        r = CMP(strncmp(a, b, aa - a), 0);
                        if (r != 0)
                                return r;
                } else {
                        /* Find the leading non-numeric segments. */
                        for (aa = a; ascii_isalpha(*aa); aa++)
                                ;
                        for (bb = b; ascii_isalpha(*bb); bb++)
                                ;

                        /* Note that the segments are usually not NUL-terminated. */
                        r = CMP(strncmp(a, b, MIN(aa - a, bb - b)), 0);
                        if (r != 0)
                                return r;

                        /* Longer is newer, e.g. abc vs abcde. */
                        r = CMP(aa - a, bb - b);
                        if (r != 0)
                                return r;
                }

                /* The current segments are equivalent. Let's move to the next one. */
                a = aa;
                b = bb;
        }
}

char ascii_tolower(char x) {

        if (x >= 'A' && x <= 'Z')
                return x - 'A' + 'a';

        return x;
}

char *ascii_strlower(char *s) {
        char *p;

        assert(s);

        for (p = s; *p; p++)
                *p = ascii_tolower(*p);

        return s;
}

int getenv_bool(const char *name) {
        const char *e;

        assert(name);

        e = getenv(name);
        if (!e)
                return -ENXIO;

        return parse_boolean(e);
}

int secure_getenv_bool(const char *name) {
        const char *e;

        assert(name);

        e = secure_getenv(name);
        if (!e)
                return -ENXIO;

        return parse_boolean(e);
}

int parse_boolean(const char *v) {
        assert(v);

        if (streq(v, "1") || strcaseeq(v, "yes") || strcaseeq(v, "y") ||
            strcaseeq(v, "true") || strcaseeq(v, "t") || strcaseeq(v, "on"))
                return 1;
        if (streq(v, "0") || strcaseeq(v, "no") || strcaseeq(v, "n") ||
            strcaseeq(v, "false") || strcaseeq(v, "f") || strcaseeq(v, "off"))
                return 0;

        return -EINVAL;
}

int safe_atollu_full(const char *s, unsigned base, unsigned long long *ret_llu) {
        char *x = NULL;
        unsigned long long l;

        assert(s);
        assert(SAFE_ATO_MASK_FLAGS(base) <= 16);

        if (FLAGS_SET(base, SAFE_ATO_REFUSE_LEADING_WHITESPACE) &&
            is_strto_space(s[0]))
                return -EINVAL;

        s = skip_strto_space(s);

        if (FLAGS_SET(base, SAFE_ATO_REFUSE_PLUS_MINUS) &&
            (s[0] == '+' || s[0] == '-'))
                return -EINVAL;

        if (FLAGS_SET(base, SAFE_ATO_REFUSE_LEADING_ZERO) &&
            s[0] == '0' && s[1] != 0)
                return -EINVAL;

        s = mangle_base(s, &base);

        errno = 0;
        l = strtoull(s, &x, SAFE_ATO_MASK_FLAGS(base));
        if (errno > 0)
                return -errno;
        if (!x || x == s || *x != 0)
                return -EINVAL;
        if (l != 0 && s[0] == '-')
                return -ERANGE;

        if (ret_llu)
                *ret_llu = l;

        return 0;
}

int safe_atolli(const char *s, long long int *ret_lli) {
        unsigned base = 0;
        char *x = NULL;
        long long l;

        assert(s);

        s = skip_strto_space(s);
        s = mangle_base(s, &base);

        errno = 0;
        l = strtoll(s, &x, base);
        if (errno > 0)
                return -errno;
        if (!x || x == s || *x != 0)
                return -EINVAL;

        if (ret_lli)
                *ret_lli = l;

        return 0;
}

static size_t strcspn_escaped(const char *s, const char *reject) {
        bool escaped = false;
        int n;

        for (n=0; s[n]; n++) {
                if (escaped)
                        escaped = false;
                else if (s[n] == '\\')
                        escaped = true;
                else if (strchr(reject, s[n]))
                        break;
        }

        /* if s ends in \, return index of previous char */
        return n - escaped;
}

/* Split a string into words. */
const char* split(const char **state, size_t *l, const char *separator, bool quoted) {
        const char *current;

        current = *state;

        if (!*current) {
                assert(**state == '\0');
                return NULL;
        }

        current += strspn(current, separator);
        if (!*current) {
                *state = current;
                return NULL;
        }

        if (quoted && strchr("\'\"", *current)) {
                char quotechars[2] = {*current, '\0'};

                *l = strcspn_escaped(current + 1, quotechars);
                if (current[*l + 1] == '\0' || current[*l + 1] != quotechars[0] ||
                    (current[*l + 2] && !strchr(separator, current[*l + 2]))) {
                        /* right quote missing or garbage at the end */
                        *state = current;
                        return NULL;
                }
                *state = current++ + *l + 2;
        } else if (quoted) {
                *l = strcspn_escaped(current, separator);
                if (current[*l] && !strchr(separator, current[*l])) {
                        /* unfinished escape */
                        *state = current;
                        return NULL;
                }
                *state = current + *l;
        } else {
                *l = strcspn(current, separator);
                *state = current + *l;
        }

        return current;
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

        return -EINVAL;
}

char octchar(int x) {
        return '0' + (x & 7);
}

int unoctchar(char c) {

        if (c >= '0' && c <= '7')
                return c - '0';

        return -EINVAL;
}

char *cescape(const char *s) {
        char *r, *t;
        const char *f;

        assert(s);

        /* Does C style string escaping. May be reversed with
         * cunescape(). */

        r = new(char, strlen(s)*4 + 1);
        if (!r)
                return NULL;

        for (f = s, t = r; *f; f++)
                t += cescape_char(*f, t);

        *t = 0;

        return r;
}


static int cunescape_one(const char *p, size_t length, uint32_t *ret, bool *eight_bit) {
        int r = 1;

        assert(p);
        assert(*p);
        assert(ret);

        /* Unescapes C style. Returns the unescaped character in ret.
         * Sets *eight_bit to true if the escaped sequence either fits in
         * one byte in UTF-8 or is a non-unicode literal byte and should
         * instead be copied directly.
         */

        if (length != (size_t) -1 && length < 1)
                return -EINVAL;

        switch (p[0]) {

        case 'a':
                *ret = '\a';
                break;
        case 'b':
                *ret = '\b';
                break;
        case 'f':
                *ret = '\f';
                break;
        case 'n':
                *ret = '\n';
                break;
        case 'r':
                *ret = '\r';
                break;
        case 't':
                *ret = '\t';
                break;
        case 'v':
                *ret = '\v';
                break;
        case '\\':
                *ret = '\\';
                break;
        case '"':
                *ret = '"';
                break;
        case '\'':
                *ret = '\'';
                break;

        case 's':
                /* This is an extension of the XDG syntax files */
                *ret = ' ';
                break;

        case 'x': {
                /* hexadecimal encoding */
                int a, b;

                if (length != (size_t) -1 && length < 3)
                        return -EINVAL;

                a = unhexchar(p[1]);
                if (a < 0)
                        return -EINVAL;

                b = unhexchar(p[2]);
                if (b < 0)
                        return -EINVAL;

                /* Don't allow NUL bytes */
                if (a == 0 && b == 0)
                        return -EINVAL;

                *ret = (a << 4U) | b;
                *eight_bit = true;
                r = 3;
                break;
        }

        case 'u': {
                /* C++11 style 16bit unicode */

                int a[4];
                unsigned i;
                uint32_t c;

                if (length != (size_t) -1 && length < 5)
                        return -EINVAL;

                for (i = 0; i < 4; i++) {
                        a[i] = unhexchar(p[1 + i]);
                        if (a[i] < 0)
                                return a[i];
                }

                c = ((uint32_t) a[0] << 12U) | ((uint32_t) a[1] << 8U) | ((uint32_t) a[2] << 4U) | (uint32_t) a[3];

                /* Don't allow 0 chars */
                if (c == 0)
                        return -EINVAL;

                *ret = c;
                r = 5;
                break;
        }

        case 'U': {
                /* C++11 style 32bit unicode */

                int a[8];
                unsigned i;
                uint32_t c;

                if (length != (size_t) -1 && length < 9)
                        return -EINVAL;

                for (i = 0; i < 8; i++) {
                        a[i] = unhexchar(p[1 + i]);
                        if (a[i] < 0)
                                return a[i];
                }

                c = ((uint32_t) a[0] << 28U) | ((uint32_t) a[1] << 24U) | ((uint32_t) a[2] << 20U) | ((uint32_t) a[3] << 16U) |
                    ((uint32_t) a[4] << 12U) | ((uint32_t) a[5] <<  8U) | ((uint32_t) a[6] <<  4U) |  (uint32_t) a[7];

                /* Don't allow 0 chars */
                if (c == 0)
                        return -EINVAL;

                /* Don't allow invalid code points */
                if (!unichar_is_valid(c))
                        return -EINVAL;

                *ret = c;
                r = 9;
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
                uint32_t m;

                if (length != (size_t) -1 && length < 3)
                        return -EINVAL;

                a = unoctchar(p[0]);
                if (a < 0)
                        return -EINVAL;

                b = unoctchar(p[1]);
                if (b < 0)
                        return -EINVAL;

                c = unoctchar(p[2]);
                if (c < 0)
                        return -EINVAL;

                /* don't allow NUL bytes */
                if (a == 0 && b == 0 && c == 0)
                        return -EINVAL;

                /* Don't allow bytes above 255 */
                m = ((uint32_t) a << 6U) | ((uint32_t) b << 3U) | (uint32_t) c;
                if (m > 255)
                        return -EINVAL;

                *ret = m;
                *eight_bit = true;
                r = 3;
                break;
        }

        default:
                return -EINVAL;
        }

        return r;
}

int cunescape_length(const char *s, size_t length, UnescapeFlags flags, char **ret) {
        char *r, *t;
        const char *f;

        assert(s);
        assert(ret);

        /* Undoes C style string escaping. */

        r = new(char, length+1);
        if (!r)
                return -ENOMEM;

        for (f = s, t = r; f < s + length; f++) {
                size_t remaining;
                uint32_t u;
                bool eight_bit = false;
                int k;

                remaining = s + length - f;
                assert(remaining > 0);

                if (*f != '\\') {
                        /* A literal literal, copy verbatim */
                        *(t++) = *f;
                        continue;
                }

                if (remaining == 1) {
                        if (flags & UNESCAPE_RELAX) {
                                /* A trailing backslash, copy verbatim */
                                *(t++) = *f;
                                continue;
                        }

                        free(r);
                        return -EINVAL;
                }

                k = cunescape_one(f + 1, remaining - 1, &u, &eight_bit);
                if (k < 0) {
                        if (flags & UNESCAPE_RELAX) {
                                /* Invalid escape code, let's take it literal then */
                                *(t++) = '\\';
                                continue;
                        }

                        free(r);
                        return k;
                }

                f += k;
                if (eight_bit)
                        /* One byte? Set directly as specified */
                        *(t++) = u;
                else
                        /* Otherwise encode as multi-byte UTF-8 */
                        t += utf8_encode_unichar(t, u);
        }

        *t = 0;

        *ret = r;
        return t - r;
}

char *xescape(const char *s, const char *bad) {
        char *r, *t;
        const char *f;

        /* Escapes all chars in bad, in addition to \ and all special
         * chars, in \xFF style escaping. May be reversed with
         * cunescape(). */

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

bool string_has_cc(const char *p, const char *ok) {
        const char *t;

        assert(p);

        /*
         * Check if a string contains control characters. If 'ok' is
         * non-NULL it may be a string containing additional CCs to be
         * considered OK.
         */

        for (t = p; *t; t++) {
                if (ok && strchr(ok, *t))
                        continue;

                if (char_is_cc(*t))
                        return true;
        }

        return false;
}

_pure_ static bool hidden_file_allow_backup(const char *filename) {
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
                endswith(filename, ".dpkg-tmp") ||
                endswith(filename, ".dpkg-dist") ||
                endswith(filename, ".dpkg-bak") ||
                endswith(filename, ".dpkg-backup") ||
                endswith(filename, ".dpkg-remove") ||
                endswith(filename, ".swp");
}

bool hidden_file(const char *filename) {
        assert(filename);

        if (endswith(filename, "~"))
                return true;

        return hidden_file_allow_backup(filename);
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
        uint8_t *p = buf;
        ssize_t n = 0;

        assert(fd >= 0);
        assert(buf);

        while (nbytes > 0) {
                ssize_t k;

                k = read(fd, p, nbytes);
                if (k < 0) {
                        if (errno == EINTR)
                                continue;

                        if (errno == EAGAIN && do_poll) {

                                /* We knowingly ignore any return value here,
                                 * and expect that any error/EOF is reported
                                 * via read() */

                                fd_wait_for_event(fd, POLLIN, USEC_INFINITY);
                                continue;
                        }

                        return n > 0 ? n : -errno;
                }

                if (k == 0)
                        return n;

                p += k;
                nbytes -= k;
                n += k;
        }

        return n;
}

int loop_read_exact(int fd, void *buf, size_t nbytes, bool do_poll) {
        ssize_t n;

        n = loop_read(fd, buf, nbytes, do_poll);
        if (n < 0)
                return n;
        if ((size_t) n != nbytes)
                return -EIO;
        return 0;
}

int loop_write(int fd, const void *buf, size_t nbytes, bool do_poll) {
        const uint8_t *p = buf;

        assert(fd >= 0);
        assert(buf);

        errno = 0;

        do {
                ssize_t k;

                k = write(fd, p, nbytes);
                if (k < 0) {
                        if (errno == EINTR)
                                continue;

                        if (errno == EAGAIN && do_poll) {
                                /* We knowingly ignore any return value here,
                                 * and expect that any error/EOF is reported
                                 * via write() */

                                fd_wait_for_event(fd, POLLOUT, USEC_INFINITY);
                                continue;
                        }

                        return -errno;
                }

                if (nbytes > 0 && k == 0) /* Can't really happen */
                        return -EIO;

                p += k;
                nbytes -= k;
        } while (nbytes > 0);

        return 0;
}

char* dirname_malloc(const char *path) {
        char *d, *dir, *dir2;

        d = strdup(path);
        if (!d)
                return NULL;
        dir = dirname(d);
        assert(dir);

        if (dir != d) {
                dir2 = strdup(dir);
                free(d);
                return dir2;
        }

        return dir;
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

        if (mode != MODE_INVALID)
                if (chmod(path, mode) < 0)
                        return -errno;

        if (uid != UID_INVALID || gid != GID_INVALID)
                if (chown(path, uid, gid) < 0)
                        return -errno;

        return 0;
}

static int proc_fd_enoent_errno(void) {
        /* When ENOENT is returned during the use of FORMAT_PROC_FD_PATH, it can mean two things: that the
         * fd does not exist or that /proc/ is not mounted. Let's make things debuggable and figure out the
         * most appropriate errno. */

        if (access("/proc/self/fd", F_OK) < 0)
                return errno == ENOENT ? -ENOSYS : -ENOENT;

        return -EBADF;
}

int fchmod_opath(int fd, mode_t m) {
        /* This function operates also on fd that might have been opened with O_PATH. fchmod() only
         * operates on open files, and fchmodat() has no AT_EMPTY_PATH, hence let's go via /proc/self/fd/. */

        assert(fd >= 0);

        if (chmod(FORMAT_PROC_FD_PATH(fd), m) < 0) {
                if (errno != ENOENT)
                        return -errno;

                return proc_fd_enoent_errno();
        }

        return 0;
}

int fchmod_and_chown(int fd, mode_t mode, uid_t uid, gid_t gid) {
        bool do_chown, do_chmod;
        struct stat st;
        int r;

        /* Change ownership and access mode of the specified fd. Tries to do so safely, ensuring that at no
         * point in time the access mode is above the old access mode under the old ownership or the new
         * access mode under the new ownership. Note: this call tries hard to leave the access mode
         * unaffected if the uid/gid is changed, i.e. it undoes implicit suid/sgid dropping the kernel does
         * on chown().
         *
         * This call is happy with O_PATH fds. */

        if (fstat(fd, &st) < 0)
                return -errno;

        do_chown =
                (uid != UID_INVALID && st.st_uid != uid) ||
                (gid != GID_INVALID && st.st_gid != gid);

        do_chmod =
                !S_ISLNK(st.st_mode) && /* chmod is not defined on symlinks */
                ((mode != MODE_INVALID && ((st.st_mode ^ mode) & 07777) != 0) ||
                 do_chown); /* If we change ownership, make sure we reset the mode afterwards, since chown()
                             * modifies the access mode too */

        if (mode == MODE_INVALID)
                mode = st.st_mode; /* If we only shall do a chown(), save original mode, since chown() might break it. */
        else if ((mode & S_IFMT) != 0 && ((mode ^ st.st_mode) & S_IFMT) != 0)
                return -EINVAL; /* insist on the right file type if it was specified */

        if (do_chown && do_chmod) {
                mode_t minimal = st.st_mode & mode; /* the subset of the old and the new mask */

                if (((minimal ^ st.st_mode) & 07777) != 0) {
                        r = fchmod_opath(fd, minimal & 07777);
                        if (r < 0)
                                return r;
                }
        }

        if (do_chown)
                if (fchownat(fd, "", uid, gid, AT_EMPTY_PATH) < 0)
                        return -errno;

        if (do_chmod) {
                r = fchmod_opath(fd, mode & 07777);
                if (r < 0)
                        return r;
        }

        return do_chown || do_chmod;
}

int futimens_opath(int fd, const struct timespec ts[2]) {
        /* Similar to fchmod_opath() but for futimens() */

        assert(fd >= 0);

        if (utimensat(fd, "", ts, AT_EMPTY_PATH) >= 0)
                return 0;
        if (errno != EINVAL)
                return -errno;

        /* Support for AT_EMPTY_PATH was added rather late (kernel 5.8), so fall back to going through
         * /proc/ if unavailable. */
        if (utimensat(AT_FDCWD, FORMAT_PROC_FD_PATH(fd), ts, 0) < 0) {
                if (errno != ENOENT)
                        return -errno;

                return proc_fd_enoent_errno();
        }

        return 0;
}

int touch_file(const char *path, bool parents, usec_t stamp, uid_t uid, gid_t gid, mode_t mode) {
        _cleanup_close_ int fd;
        int r;

        assert(path);

        if (parents)
                mkdir_parents(path, 0755);

        fd = open(path, O_WRONLY|O_CREAT|O_CLOEXEC|O_NOCTTY, mode > 0 ? mode : 0644);
        if (fd < 0)
                return -errno;

        if (mode > 0) {
                r = fchmod(fd, mode);
                if (r < 0)
                        return -errno;
        }

        if (uid != UID_INVALID || gid != GID_INVALID) {
                r = fchown(fd, uid, gid);
                if (r < 0)
                        return -errno;
        }

        if (stamp != USEC_INFINITY) {
                struct timespec ts[2];

                timespec_store(&ts[0], stamp);
                ts[1] = ts[0];
                r = futimens(fd, ts);
        } else
                r = futimens(fd, NULL);
        if (r < 0)
                return -errno;

        return 0;
}

int touch(const char *path) {
        return touch_file(path, false, USEC_INFINITY, UID_INVALID, GID_INVALID, 0);
}

int readlinkat_malloc(int fd, const char *p, char **ret) {
        size_t l = PATH_MAX;

        assert(fd >= 0 || fd == AT_FDCWD);

        if (fd < 0 && isempty(p))
                return -EISDIR; /* In this case, the fd points to the current working directory, and is
                                 * definitely not a symlink. Let's return earlier. */

        for (;;) {
                _cleanup_free_ char *c = NULL;
                ssize_t n;

                c = new(char, l+1);
                if (!c)
                        return -ENOMEM;

                n = readlinkat(fd, p ?: "", c, l);
                if (n < 0)
                        return -errno;

                if ((size_t) n < l) {
                        c[n] = 0;

                        if (ret)
                                *ret = TAKE_PTR(c);

                        return 0;
                }

                if (l > (SSIZE_MAX-1)/2) /* readlinkat() returns an ssize_t, and we want an extra byte for a
                                          * trailing NUL, hence do an overflow check relative to SSIZE_MAX-1
                                          * here */
                        return -EFBIG;

                l *= 2;
        }
}

int readlink_malloc(const char *p, char **ret) {
        return readlinkat_malloc(AT_FDCWD, p, ret);
}

DIR *xopendirat(int fd, const char *name, int flags) {
        int nfd;
        DIR *d;

        nfd = openat(fd, name, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC|flags);
        if (nfd < 0)
                return NULL;

        d = fdopendir(nfd);
        if (!d) {
                safe_close(nfd);
                return NULL;
        }

        return d;
}

int open_mkdir_at(int dirfd, const char *path, int flags, mode_t mode) {
        _cleanup_close_ int fd = -1, parent_fd = -1;
        _cleanup_free_ char *fname = NULL;
        const char *slash;
        bool made;
        int r;

        /* Creates a directory with mkdirat() and then opens it, in the "most atomic" fashion we can
         * do. Guarantees that the returned fd refers to a directory. If O_EXCL is specified will fail if the
         * dir already exists. Otherwise will open an existing dir, but only if it is one.  */

        if (flags & ~(O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_EXCL|O_NOATIME|O_NOFOLLOW|O_PATH))
                return -EINVAL;
        if ((flags & O_ACCMODE) != O_RDONLY)
                return -EINVAL;

        /* Note that O_DIRECTORY|O_NOFOLLOW is implied, but we allow specifying it anyway. The following
         * flags actually make sense to specify: O_CLOEXEC, O_EXCL, O_NOATIME, O_PATH */

        if (isempty(path))
                return -EINVAL;

        slash = strrchr(path, '/');
        if (slash) {
                _cleanup_free_ char *parent = NULL;

                /* If this is not a valid filename, it's a path. Let's open the parent directory then, so
                 * that we can pin it, and operate below it. */

                if (isempty(slash + 1))
                        return -EINVAL;

                parent = dirname_malloc(path);
                if (!parent)
                        return -ENOMEM;

                fname = strdup(slash + 1);
                if (!fname)
                        return -ENOMEM;

                parent_fd = openat(dirfd, parent, O_PATH|O_DIRECTORY|O_CLOEXEC);
                if (parent_fd < 0)
                        return -errno;

                dirfd = parent_fd;
                path = fname;
        }

        r = RET_NERRNO(mkdirat(dirfd, path, mode));
        if (r == -EEXIST) {
                if (flags & O_EXCL)
                        return -EEXIST;

                made = false;
        } else if (r < 0)
                return r;
        else
                made = true;

        fd = RET_NERRNO(openat(dirfd, path, (flags & ~O_EXCL)|O_DIRECTORY|O_NOFOLLOW));
        if (fd < 0) {
                if (fd == -ENOENT)  /* We got ENOENT? then someone else immediately removed it after we
                                     * created it. In that case let's return immediately without unlinking
                                     * anything, because there simply isn't anything to unlink anymore. */
                        return -ENOENT;
                if (fd == -ELOOP)   /* is a symlink? exists already → created by someone else, don't unlink */
                        return -EEXIST;
                if (fd == -ENOTDIR) /* not a directory? exists already → created by someone else, don't unlink */
                        return -EEXIST;

                if (made)
                        (void) unlinkat(dirfd, path, AT_REMOVEDIR);

                return fd;
        }

        return TAKE_FD(fd);
}

int make_lock_file(const char *p, int operation, LockFile *ret) {
        _cleanup_close_ int fd = -1;
        _cleanup_free_ char *t = NULL;

        assert(p);
        assert(IN_SET(operation & ~LOCK_NB, LOCK_EX, LOCK_SH));
        assert(ret);

        if (isempty(p))
                return -EINVAL;

        t = strdup(p);
        if (!t)
                return -ENOMEM;

        for (;;) {
                struct stat st;

                fd = open(p, O_CREAT|O_RDWR|O_NOFOLLOW|O_CLOEXEC|O_NOCTTY, 0600);
                if (fd < 0)
                        return -errno;

                if (flock(fd, operation) < 0)
                        return errno == EWOULDBLOCK ? -EBUSY : -errno;

                /* If we acquired the lock, let's check if the file still exists in the file system. If not,
                 * then the previous exclusive owner removed it and then closed it. In such a case our
                 * acquired lock is worthless, hence try again. */

                if (fstat(fd, &st) < 0)
                        return -errno;
                if (st.st_nlink > 0)
                        break;

                fd = safe_close(fd);
        }

        *ret = (LockFile) {
                .path = TAKE_PTR(t),
                .fd = TAKE_FD(fd),
                .operation = operation,
        };

        return 0;
}

void release_lock_file(LockFile *f) {
        if (!f)
                return;

        if (f->path) {

                /* If we are the exclusive owner we can safely delete
                 * the lock file itself. If we are not the exclusive
                 * owner, we can try becoming it. */

                if (f->fd >= 0 &&
                    (f->operation & ~LOCK_NB) == LOCK_SH &&
                    flock(f->fd, LOCK_EX|LOCK_NB) >= 0)
                        f->operation = LOCK_EX|LOCK_NB;

                if ((f->operation & ~LOCK_NB) == LOCK_EX)
                        (void) unlink(f->path);

                free(f->path);
                f->path = NULL;
        }

        f->fd = safe_close(f->fd);
        f->operation = 0;
}

int free_and_strdup(char **p, const char *s) {
        char *t;

        assert(p);

        /* Replaces a string pointer with a strdup()ed new string, possibly freeing the old one. */

        if (streq_ptr(*p, s))
                return 0;

        if (s) {
                t = strdup(s);
                if (!t)
                        return -ENOMEM;
        } else
                t = NULL;

        free(*p);
        *p = t;

        return 1;
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

int null_or_empty_fd(int fd) {
        struct stat st;

        assert(fd >= 0);

        if (fstat(fd, &st) < 0)
                return -errno;

        return null_or_empty(&st);
}

bool dirent_is_file_with_suffix(const struct dirent *de, const char *suffix) {
        assert(de);

        if (de->d_type != DT_REG &&
            de->d_type != DT_LNK &&
            de->d_type != DT_UNKNOWN)
                return false;

        if (hidden_file_allow_backup(de->d_name))
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


static inline int ppoll_fallback(struct pollfd *fds, nfds_t nfds, const struct timespec *timeout_ts, const sigset_t *sigmask) {
        int ready, timeout;
        sigset_t origmask;

        timeout = (timeout_ts == NULL) ? -1 : (timeout_ts->tv_sec * 1000 + timeout_ts->tv_nsec / 1000000);

        /* This is racey, but what can we do without ppoll? */
        sigprocmask(SIG_SETMASK, sigmask, &origmask);
        ready = poll(fds, nfds, timeout);
        sigprocmask(SIG_SETMASK, &origmask, NULL);

	return ready;
}

int fd_wait_for_event(int fd, int event, usec_t t) {

        struct pollfd pollfd = {
                .fd = fd,
                .events = event,
        };

        struct timespec ts;
        int r;

#if HAVE_DECL_PPOLL
        r = ppoll(&pollfd, 1, t == USEC_INFINITY ? NULL : timespec_store(&ts, t), NULL);
#else
        /* Fallback path when ppoll() is unavailable */
        r = ppoll_fallback(&pollfd, 1, t == USEC_INFINITY ? NULL : timespec_store(&ts, t), NULL);
#endif
        if (r < 0)
                return -errno;

        if (r == 0)
                return 0;

        return pollfd.revents;
}

int fopen_temporary(const char *path, FILE **_f, char **_temp_path) {
        FILE *f;
        char *t;
        int r, fd;

        assert(path);
        assert(_f);
        assert(_temp_path);

        r = tempfn_xxxxxx(path, &t);
        if (r < 0)
                return r;

#if HAVE_DECL_MKOSTEMP
        fd = mkostemp_safe(t, O_WRONLY|O_CLOEXEC);
#else
        fd = mkstemp_safe(t);
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
        static thread_local int cached = 0;

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

static const char* const rlimit_table[_RLIMIT_MAX] = {
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
        static thread_local char buf[sizeof("RTMIN+")-1 + DECIMAL_STR_MAX(int) + 1];
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
        const char *p;
        int signo, r;

        /* Check that the input is a signal number. */
        if (safe_atoi(s, &signo) >= 0) {
                if (SIGNAL_VALID(signo))
                        return signo;
                else
                        return -ERANGE;
        }

        /* Drop "SIG" prefix. */
        if (startswith(s, "SIG"))
                s += 3;

        /* Check that the input is a signal name. */
        signo = __signal_from_string(s);
        if (signo > 0)
                return signo;

        /* Check that the input is RTMIN or
         * RTMIN+n (0 <= n <= SIGRTMAX-SIGRTMIN). */
        p = startswith(s, "RTMIN");
        if (p) {
                if (*p == '\0')
                        return SIGRTMIN;
                if (*p != '+')
                        return -EINVAL;

                r = safe_atoi(p, &signo);
                if (r < 0)
                        return r;

                if (signo < 0 || signo > SIGRTMAX - SIGRTMIN)
                        return -ERANGE;

                return signo + SIGRTMIN;
        }

        /* Check that the input is RTMAX or
         * RTMAX-n (0 <= n <= SIGRTMAX-SIGRTMIN). */
        p = startswith(s, "RTMAX");
        if (p) {
                if (*p == '\0')
                        return SIGRTMAX;
                if (*p != '-')
                        return -EINVAL;

                r = safe_atoi(p, &signo);
                if (r < 0)
                        return r;

                if (signo > 0 || signo < SIGRTMIN - SIGRTMAX)
                        return -ERANGE;

                return signo + SIGRTMAX;
        }

        return -EINVAL;
}

int kill_and_sigcont(pid_t pid, int sig) {
        int r;

        r = kill(pid, sig) < 0 ? -errno : 0;

        /* If this worked, also send SIGCONT, unless we already just sent a SIGCONT, or SIGKILL was sent which isn't
         * affected by a process being suspended anyway. */
        if (r >= 0 && !IN_SET(sig, SIGCONT, SIGKILL))
                (void) kill(pid, SIGCONT);

        return r;
}

int fd_inc_sndbuf(int fd, size_t n) {
        int r, value;
        socklen_t l = sizeof(value);

        r = getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &value, &l);
        if (r >= 0 && l == sizeof(value) && (size_t) value >= n*2)
                return 0;

        /* If we have the privileges we will ignore the kernel limit. */

        value = (int) n;
        if (setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &value, sizeof(value)) < 0)
                if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &value, sizeof(value)) < 0)
                        return -errno;

        return 1;
}

/* Files that initrd generators that do not create /etc/initrd-release put into the initrd. */
static const char * const initrd_markers[] = {
        "/conf/initramfs.conf", /* initramfs-tools */
        "/lib/dracut-lib.sh",   /* dracut before version 019 */
        "/init_functions",      /* old versions of mkinitcpio (version 18 and later create it) */
        "/etc/initrd.defaults", /* genkernel before version 4.2, e.g. 4.1 with eudev in the initrd */
        "/.modloop",            /* Alpine's mkinitfs */
};

bool in_initrd(void) {
        static int saved = -1;
        struct statfs s;
        const char *e;
        size_t i;
        int r;

        if (saved >= 0)
                return saved;

        /* As systemd does, this can be overridden by setting $SYSTEMD_IN_INITRD=0|1. */
        e = secure_getenv("SYSTEMD_IN_INITRD");
        if (e) {
                r = parse_boolean(e);
                if (r >= 0) {
                        saved = r > 0;
                        return saved;
                }
                log_debug_errno(r, "Failed to parse $SYSTEMD_IN_INITRD, ignoring: %m");
        }

        /* As systemd (since v252) does, we are in an initrd if /etc/initrd-release exists. */
        if (access("/etc/initrd-release", F_OK) >= 0) {
                saved = true;
                return saved;
        }

        /* eudev: initrds that are not made for systemd, e.g. those of initramfs-tools, lack
         * /etc/initrd-release. Also consider an initramfs an initrd, i.e. when the root file system is a
         * memory file system (rootfs, which is ramfs or tmpfs, as older versions of systemd also required),
         * /init, which the kernel runs from an initramfs, exists, and so does a file that is specific to the
         * initrds of one of the generators that do not create /etc/initrd-release. */
        saved = false;
        if (statfs("/", &s) < 0 || !is_temporary_fs(&s) || access("/init", F_OK) < 0)
                return saved;

        for (i = 0; i < ELEMENTSOF(initrd_markers); i++)
                if (access(initrd_markers[i], F_OK) >= 0) {
                        log_debug("Found %s in a memory file system with /init, assuming to run in an initrd.",
                                  initrd_markers[i]);
                        saved = true;
                        break;
                }

        return saved;
}

bool filename_is_valid(const char *p) {

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

void* greedy_realloc(void **p, size_t *allocated, size_t need, size_t size) {
        size_t a, newalloc;
        void *q;

        assert(p);
        assert(allocated);

        if (*allocated >= need)
                return *p;

        newalloc = MAX(need * 2, 64u / size);
        a = newalloc * size;

        /* check for overflows */
        if (a < size * need)
                return NULL;

        q = realloc(*p, a);
        if (!q)
                return NULL;

        *p = q;
        *allocated = newalloc;
        return q;
}

int proc_cmdline(char **ret) {
        const char *e;

        assert(ret);

        /* For testing purposes it is sometimes useful to be able to override what we consider /proc/cmdline to be.
         * eudev: $UDEV_PROC_CMDLINE takes precedence over $SYSTEMD_PROC_CMDLINE. */
        e = secure_getenv("UDEV_PROC_CMDLINE");
        if (!e)
                e = secure_getenv("SYSTEMD_PROC_CMDLINE");
        if (e) {
                char *m;

                m = strdup(e);
                if (!m)
                        return -ENOMEM;

                *ret = m;
                return 0;
        }

        if (detect_container(NULL) > 0)
                return get_process_cmdline(1, 0, false, ret);
        else
                return read_full_file("/proc/cmdline", ret, NULL);
}

static bool relaxed_equal_char(char a, char b) {
        return a == b ||
                (a == '_' && b == '-') ||
                (a == '-' && b == '_');
}

bool proc_cmdline_key_streq(const char *x, const char *y) {
        /* Much like streq(), but considers "_" and "-" equivalent */

        for (;;) {
                if (!relaxed_equal_char(*x, *y))
                        return false;

                if (*x == 0)
                        return true;

                x++, y++;
        }
}

bool proc_cmdline_value_missing(const char *key, const char *value) {
        assert(key);

        if (!value) {
                log_warning("Missing argument for %s= kernel command line switch, ignoring.", key);
                return true;
        }

        return false;
}

static const char *proc_cmdline_key_startswith(const char *s, const char *prefix) {
        /* Much like startswith(), but considers "-" and "_" the same */

        for (; *prefix != 0; s++, prefix++)
                if (!relaxed_equal_char(*s, *prefix))
                        return NULL;

        return s;
}

/* Looks for a specific key on the kernel command line. A parameter beginning with the "key" string
 * followed by "=" is searched, and the value following this is returned in "value". If the key is
 * found as a separate word (i.e. not followed by "="), this is also accepted, and "value" is
 * returned as NULL. When comparing the key, "-" and "_" are considered equivalent. Returns > 0 if
 * the key is found, 0 if not. */
int proc_cmdline_get_key(const char *key, char **value) {
        _cleanup_free_ char *line = NULL, *ret = NULL;
        bool found = false;
        const char *p;
        int r;

        assert(value);

        if (isempty(key))
                return -EINVAL;

        r = proc_cmdline(&line);
        if (r < 0)
                return r;

        p = line;
        for (;;) {
                _cleanup_free_ char *word = NULL;
                const char *e;

                r = unquote_first_word(&p, &word, UNQUOTE_RELAX);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                /* Automatically filter out arguments that are intended only for the initrd, if we are not in the
                 * initrd. */
                if (!in_initrd() && startswith(word, "rd."))
                        continue;

                e = proc_cmdline_key_startswith(word, key);
                if (!e)
                        continue;

                if (*e == '=') {
                        free(ret);
                        ret = strdup(e+1);
                        if (!ret)
                                return -ENOMEM;

                        found = true;
                } else if (*e == 0)
                        found = true;
        }

        *value = ret;
        ret = NULL;

        return found;
}

/* Like proc_cmdline_get_key(), but parses the value as a boolean; the key without a value means
 * true. Returns > 0 if the key is found, 0 (and false) if not. */
int proc_cmdline_get_bool(const char *key, bool *ret) {
        _cleanup_free_ char *v = NULL;
        int r;

        assert(ret);

        r = proc_cmdline_get_key(key, &v);
        if (r < 0)
                return r;
        if (r == 0) {
                *ret = false;
                return 0;
        }

        if (v) {
                r = parse_boolean(v);
                if (r < 0)
                        return r;
                *ret = r;
        } else
                *ret = true;

        return 1;
}

int parse_proc_cmdline(int (*parse_item)(const char *key, const char *value)) {
        _cleanup_free_ char *line = NULL;
        const char *p;
        int r;

        assert(parse_item);

        r = proc_cmdline(&line);
        if (r < 0)
                return r;

        p = line;
        for (;;) {
                _cleanup_free_ char *word = NULL;
                char *value = NULL;

                r = unquote_first_word(&p, &word, UNQUOTE_RELAX);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                /* Filter out arguments that are intended only for the
                 * initrd */
                if (!in_initrd() && startswith(word, "rd."))
                        continue;

                value = strchr(word, '=');
                if (value)
                        *(value++) = 0;

                r = parse_item(word, value);
                if (r < 0)
                        return r;
        }

        return 0;
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
        if (u.uid == UID_INVALID)
                return -ENODATA;
        if (u.gid == GID_INVALID)
                return -ENODATA;

        *ucred = u;
        return 0;
}

#if HAVE_DECL_MKOSTEMP
/* This is much like like mkostemp() but is subject to umask(). */
int mkostemp_safe(char *pattern, int flags) {
        _cleanup_umask_ mode_t u = umask(077);
        int fd;

        assert(pattern);

        fd = mkostemp(pattern, flags);
        if (fd < 0)
                return -errno;

        return fd;
}
#else
/* This is much like like mkstemp() but is subject to umask(). */
int mkstemp_safe(char *pattern) {
        _cleanup_umask_ mode_t u = umask(077);
        int fd;

        assert(pattern);

        fd = mkstemp(pattern);
        if (fd < 0)
                return -errno;

        return fd;
}
#endif

int tempfn_xxxxxx(const char *p, char **ret) {
        const char *fn;
        char *t;

        assert(p);
        assert(ret);

        /*
         * Turns this:
         *         /foo/bar/waldo
         *
         * Into this:
         *         /foo/bar/.#waldoXXXXXX
         */

        fn = eudev_basename(p);
        if (!filename_is_valid(fn))
                return -EINVAL;

        t = new(char, strlen(p) + 2 + 6 + 1);
        if (!t)
                return -ENOMEM;

        strcpy(stpcpy(stpcpy(mempcpy(t, p, fn - p), ".#"), fn), "XXXXXX");

        *ret = path_kill_slashes(t);
        return 0;
}

int tempfn_random(const char *p, const char *extra, char **ret) {
        _cleanup_free_ char *d = NULL, *fn = NULL;
        char suffix[16 + 1];
        size_t len_add;
        char *t;

        assert(p);
        assert(ret);

        /*
         * Turns this:
         *         /foo/bar/waldo
         *
         * Into this:
         *         /foo/bar/.#<extra>waldobaa2a261115984a9
         */

        xsprintf(suffix, "%016" PRIx64, random_u64());

        fn = strdup(eudev_basename(p));
        if (!fn)
                return -ENOMEM;
        if (!filename_is_valid(fn))
                return -EINVAL;

        len_add = 2 + strlen_ptr(extra) + strlen(suffix);
        if (len_add >= NAME_MAX)
                return -EINVAL;

        if (strlen(fn) > NAME_MAX - len_add)
                /* We cannot simply prepend and append strings to the filename. Let's truncate the filename. */
                fn[NAME_MAX - len_add] = '\0';

        d = strndup(p, eudev_basename(p) - p);
        if (!d)
                return -ENOMEM;

        t = strjoin(d, ".#", extra ?: "", fn, suffix, NULL);
        if (!t)
                return -ENOMEM;

        *ret = path_kill_slashes(t);
        return 0;
}

int symlinkat_atomic_full(const char *from, int atfd, const char *to, bool make_relative) {
        _cleanup_free_ char *relpath = NULL, *t = NULL;
        int r;

        assert(from);
        assert(to);

        if (make_relative) {
                r = path_make_relative_parent(to, from, &relpath);
                if (r < 0)
                        return r;

                from = relpath;
        }

        r = tempfn_random(to, NULL, &t);
        if (r < 0)
                return r;

        if (symlinkat(from, atfd, t) < 0)
                return -errno;

        r = RET_NERRNO(renameat(atfd, t, atfd, to));
        if (r < 0) {
                (void) unlinkat(atfd, t, 0);
                return r;
        }

        return 0;
}

int is_dir(const char* path, bool follow) {
        struct stat st;
        int r;

        if (follow)
                r = stat(path, &st);
        else
                r = lstat(path, &st);
        if (r < 0)
                return -errno;

        return !!S_ISDIR(st.st_mode);
}

int unquote_first_word(const char **p, char **ret, UnquoteFlags flags) {
        _cleanup_free_ char *s = NULL;
        size_t allocated = 0, sz = 0;
        int r;

        enum {
                START,
                VALUE,
                VALUE_ESCAPE,
                SINGLE_QUOTE,
                SINGLE_QUOTE_ESCAPE,
                DOUBLE_QUOTE,
                DOUBLE_QUOTE_ESCAPE,
                SPACE,
        } state = START;

        assert(p);
        assert(*p);
        assert(ret);

        /* Parses the first word of a string, and returns it in
         * *ret. Removes all quotes in the process. When parsing fails
         * (because of an uneven number of quotes or similar), leaves
         * the pointer *p at the first invalid character. */

        for (;;) {
                char c = **p;

                switch (state) {

                case START:
                        if (c == 0)
                                goto finish;
                        else if (strchr(WHITESPACE, c))
                                break;

                        state = VALUE;
                        /* fallthrough */

                case VALUE:
                        if (c == 0)
                                goto finish;
                        else if (c == '\'')
                                state = SINGLE_QUOTE;
                        else if (c == '\\')
                                state = VALUE_ESCAPE;
                        else if (c == '\"')
                                state = DOUBLE_QUOTE;
                        else if (strchr(WHITESPACE, c))
                                state = SPACE;
                        else {
                                if (!GREEDY_REALLOC(s, allocated, sz+2))
                                        return -ENOMEM;

                                s[sz++] = c;
                        }

                        break;

                case VALUE_ESCAPE:
                        if (c == 0) {
                                if (flags & UNQUOTE_RELAX)
                                        goto finish;
                                return -EINVAL;
                        }

                        if (!GREEDY_REALLOC(s, allocated, sz+7))
                                return -ENOMEM;

                        if (flags & UNQUOTE_CUNESCAPE) {
                                uint32_t u;
                                bool eight_bit = false;

                                r = cunescape_one(*p, (size_t) -1, &u, &eight_bit);
                                if (r < 0)
                                        return -EINVAL;

                                (*p) += r - 1;

                                if (eight_bit)
                                        s[sz++] = u;
                                else
                                        sz += utf8_encode_unichar(s + sz, u);
                        } else
                                s[sz++] = c;

                        state = VALUE;
                        break;

                case SINGLE_QUOTE:
                        if (c == 0) {
                                if (flags & UNQUOTE_RELAX)
                                        goto finish;
                                return -EINVAL;
                        } else if (c == '\'')
                                state = VALUE;
                        else if (c == '\\')
                                state = SINGLE_QUOTE_ESCAPE;
                        else {
                                if (!GREEDY_REALLOC(s, allocated, sz+2))
                                        return -ENOMEM;

                                s[sz++] = c;
                        }

                        break;

                case SINGLE_QUOTE_ESCAPE:
                        if (c == 0) {
                                if (flags & UNQUOTE_RELAX)
                                        goto finish;
                                return -EINVAL;
                        }

                        if (!GREEDY_REALLOC(s, allocated, sz+7))
                                return -ENOMEM;

                        if (flags & UNQUOTE_CUNESCAPE) {
                                uint32_t u;
                                bool eight_bit = false;

                                r = cunescape_one(*p, (size_t) -1, &u, &eight_bit);
                                if (r < 0)
                                        return -EINVAL;

                                (*p) += r - 1;

                                if (eight_bit)
                                        s[sz++] = u;
                                else
                                        sz += utf8_encode_unichar(s + sz, u);
                        } else
                                s[sz++] = c;

                        state = SINGLE_QUOTE;
                        break;

                case DOUBLE_QUOTE:
                        if (c == 0)
                                return -EINVAL;
                        else if (c == '\"')
                                state = VALUE;
                        else if (c == '\\')
                                state = DOUBLE_QUOTE_ESCAPE;
                        else {
                                if (!GREEDY_REALLOC(s, allocated, sz+2))
                                        return -ENOMEM;

                                s[sz++] = c;
                        }

                        break;

                case DOUBLE_QUOTE_ESCAPE:
                        if (c == 0) {
                                if (flags & UNQUOTE_RELAX)
                                        goto finish;
                                return -EINVAL;
                        }

                        if (!GREEDY_REALLOC(s, allocated, sz+7))
                                return -ENOMEM;

                        if (flags & UNQUOTE_CUNESCAPE) {
                                uint32_t u;
                                bool eight_bit = false;

                                r = cunescape_one(*p, (size_t) -1, &u, &eight_bit);
                                if (r < 0)
                                        return -EINVAL;

                                (*p) += r - 1;

                                if (eight_bit)
                                        s[sz++] = u;
                                else
                                        sz += utf8_encode_unichar(s + sz, u);
                        } else
                                s[sz++] = c;

                        state = DOUBLE_QUOTE;
                        break;

                case SPACE:
                        if (c == 0)
                                goto finish;
                        if (!strchr(WHITESPACE, c))
                                goto finish;

                        break;
                }

                (*p) ++;
        }

finish:
        if (!s) {
                *ret = NULL;
                return 0;
        }

        s[sz] = 0;
        *ret = s;
        s = NULL;

        return 1;
}

void cmsg_close_all(struct msghdr *mh) {
        struct cmsghdr *cmsg;

        assert(mh);

        for (cmsg = CMSG_FIRSTHDR(mh); cmsg; cmsg = CMSG_NXTHDR(mh, cmsg))
                if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS)
                        close_many((int*) CMSG_DATA(cmsg), (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int));
}

const char *eudev_basename(const char *filename) {
        const char *p = strrchr(filename, '/');

        if (p)
                return p + 1;
        return filename;
}
