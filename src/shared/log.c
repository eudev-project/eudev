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

#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>

#include "log.h"
#include "strv.h"
#include "util.h"
#include "missing.h"
#include "macro.h"
#include "socket-util.h"
#include "time-util.h"
#include "process-util.h"
#include "terminal-util.h"

#define SNDBUF_SIZE (8*1024*1024)

static LogTarget log_target = LOG_TARGET_CONSOLE;
static int log_max_level = LOG_INFO;
static int log_facility = LOG_DAEMON;

/* Like log_target_max_level[] of systemd: the maximum log levels of the single targets, which can only
 * lower the global one, see log_set_max_level_from_string(). */
static int log_target_max_level[] = {
        [LOG_TARGET_CONSOLE] = INT_MAX,
        [LOG_TARGET_KMSG] = INT_MAX,
        [LOG_TARGET_SYSLOG] = INT_MAX,
};

static int console_fd = STDERR_FILENO;
static int syslog_fd = -1;
static int kmsg_fd = -1;

static bool syslog_is_stream = false;

/* like systemd: unset (-1) until $SYSTEMD_LOG_COLOR sets it, or log_open() turns it on for the console */
static int show_color = -1;
static bool show_location = false;

/* Akin to glibc's __abort_msg; which is private and we hence cannot
 * use here. */
static char *log_abort_msg = NULL;

void log_close_console(void) {

        if (console_fd < 0)
                return;

        if (getpid() == 1) {
                if (console_fd >= 3)
                        safe_close(console_fd);

                console_fd = -1;
        }
}

static int log_open_console(void) {

        if (console_fd >= 0)
                return 0;

        if (getpid() == 1) {
                console_fd = open_terminal("/dev/console", O_WRONLY|O_NOCTTY|O_CLOEXEC);
                if (console_fd < 0)
                        return console_fd;
        } else
                console_fd = STDERR_FILENO;

        return 0;
}

void log_close_kmsg(void) {
        kmsg_fd = safe_close(kmsg_fd);
}

static int log_open_kmsg(void) {

        if (kmsg_fd >= 0)
                return 0;

        kmsg_fd = open("/dev/kmsg", O_WRONLY|O_NOCTTY|O_CLOEXEC);
        if (kmsg_fd < 0)
                return -errno;

        return 0;
}

void log_close_syslog(void) {
        syslog_fd = safe_close(syslog_fd);
}

static int create_log_socket(int type) {
        struct timeval tv;
        int fd;

        fd = socket(AF_UNIX, type|SOCK_CLOEXEC, 0);
        if (fd < 0)
                return -errno;

        fd_inc_sndbuf(fd, SNDBUF_SIZE);

        /* We need a blocking fd here since we'd otherwise lose
        messages way too early. However, let's not hang forever in the
        unlikely case of a deadlock. */
        if (getpid() == 1)
                timeval_store(&tv, 10 * USEC_PER_MSEC);
        else
                timeval_store(&tv, 10 * USEC_PER_SEC);
        (void) setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        return fd;
}

static int log_open_syslog(void) {

        static const union sockaddr_union sa = {
                .un.sun_family = AF_UNIX,
                .un.sun_path = "/dev/log",
        };

        int r;

        if (syslog_fd >= 0)
                return 0;

        syslog_fd = create_log_socket(SOCK_DGRAM);
        if (syslog_fd < 0) {
                r = syslog_fd;
                goto fail;
        }

        if (connect(syslog_fd, &sa.sa, offsetof(struct sockaddr_un, sun_path) + strlen(sa.un.sun_path)) < 0) {
                safe_close(syslog_fd);

                /* Some legacy syslog systems still use stream
                 * sockets. They really shouldn't. But what can we
                 * do... */
                syslog_fd = create_log_socket(SOCK_STREAM);
                if (syslog_fd < 0) {
                        r = syslog_fd;
                        goto fail;
                }

                if (connect(syslog_fd, &sa.sa, offsetof(struct sockaddr_un, sun_path) + strlen(sa.un.sun_path)) < 0) {
                        r = -errno;
                        goto fail;
                }

                syslog_is_stream = true;
        } else
                syslog_is_stream = false;

        return 0;

fail:
        log_close_syslog();
        return r;
}

/* Like log_on_console() of systemd: whether the messages go to the console. */
static bool log_on_console(void) {
        if (IN_SET(log_target, LOG_TARGET_CONSOLE, LOG_TARGET_CONSOLE_PREFIXED))
                return true;

        return syslog_fd < 0 && kmsg_fd < 0;
}

static int log_open_internal(void) {
        int r;

        /* If we don't use the console we close it here, to not get
         * killed by SAK. If we don't use syslog we close it here so
         * that we are not confused by somebody deleting the socket in
         * the fs. If we don't use /dev/kmsg we still keep it open,
         * because there is no reason to close it. */

        if (log_target == LOG_TARGET_NULL) {
                log_close_syslog();
                log_close_console();
                return 0;
        }

        if ((log_target != LOG_TARGET_AUTO && log_target != LOG_TARGET_SAFE) ||
            getpid() == 1 ||
            isatty(STDERR_FILENO) <= 0) {

                if (log_target == LOG_TARGET_SYSLOG_OR_KMSG ||
                    log_target == LOG_TARGET_SYSLOG) {
                        r = log_open_syslog();
                        if (r >= 0) {
                                log_close_console();
                                return r;
                        }
                }

                if (log_target == LOG_TARGET_AUTO ||
                    log_target == LOG_TARGET_SAFE ||
                    log_target == LOG_TARGET_SYSLOG_OR_KMSG ||
                    log_target == LOG_TARGET_KMSG) {
                        r = log_open_kmsg();
                        if (r >= 0) {
                                log_close_syslog();
                                log_close_console();
                                return r;
                        }
                }
        }

        log_close_syslog();

        return log_open_console();
}

int log_open(void) {
        int r;

        r = log_open_internal();

        /* Like log_setup() of systemd, which eudev's programs do not have: the messages to the console are
         * colored by default, as far as colors_enabled() allows it, i.e. on a terminal. */
        if (show_color < 0 && log_on_console())
                show_color = true;

        return r;
}

void log_set_target(LogTarget target) {
        assert(target >= 0);
        assert(target < _LOG_TARGET_MAX);

        log_target = target;
}

void log_close(void) {
        log_close_syslog();
        log_close_kmsg();
        log_close_console();
}

void log_set_max_level(int level) {
        assert((level & LOG_PRIMASK) == level);

        log_max_level = level;
}

static int write_to_console(
                int level,
                int error __attribute__((unused)),
                const char *file,
                int line,
                const char *func __attribute__((unused)),
                const char *object_field __attribute__((unused)),
                const char *object __attribute__((unused)),
                const char *buffer) {

        char location[256], prefix[1 + DECIMAL_STR_MAX(int) + 2];
        struct iovec iovec[6] = {};
        const char *on = NULL, *off = NULL;
        unsigned n = 0;

        if (console_fd < 0)
                return 0;

        if (LOG_PRI(level) > log_target_max_level[LOG_TARGET_CONSOLE])
                return 0;

        if (log_target == LOG_TARGET_CONSOLE_PREFIXED) {
                sprintf(prefix, "<%i>", level);
                IOVEC_SET_STRING(iovec[n++], prefix);
        }

        /* like systemd, a color for each level, and the location in dark yellow */
        if (show_color > 0)
                get_log_colors(LOG_PRI(level), &on, &off, NULL);

        if (show_location) {
                const char *lon = "", *loff = "";

                if (show_color > 0) {
                        lon = ansi_highlight_yellow4();
                        loff = ansi_normal();
                }

                snprintf(location, sizeof(location), "%s%s:%i%s: ", lon, file, line, loff);
                char_array_0(location);
                IOVEC_SET_STRING(iovec[n++], location);
        }

        if (on)
                IOVEC_SET_STRING(iovec[n++], on);
        IOVEC_SET_STRING(iovec[n++], buffer);
        if (off)
                IOVEC_SET_STRING(iovec[n++], off);
        IOVEC_SET_STRING(iovec[n++], "\n");

        if (writev(console_fd, iovec, n) < 0) {

                if (errno == EIO && getpid() == 1) {

                        /* If somebody tried to kick us from our
                         * console tty (via vhangup() or suchlike),
                         * try to reconnect */

                        log_close_console();
                        log_open_console();

                        if (console_fd < 0)
                                return 0;

                        if (writev(console_fd, iovec, n) < 0)
                                return -errno;
                } else
                        return -errno;
        }

        return 1;
}

static int write_to_syslog(
                int level,
                int error __attribute__((unused)),
                const char *file __attribute__((unused)),
                int line __attribute__((unused)),
                const char *func __attribute__((unused)),
                const char *object_field __attribute__((unused)),
                const char *object __attribute__((unused)),
                const char *buffer) {

        char header_priority[1 + DECIMAL_STR_MAX(int) + 2], header_time[64], header_pid[1 + DECIMAL_STR_MAX(pid_t) + 4];
        struct iovec iovec[5] = {};
        struct msghdr msghdr = {
                .msg_iov = iovec,
                .msg_iovlen = ELEMENTSOF(iovec),
        };
        time_t t;
        struct tm *tm;

        if (syslog_fd < 0)
                return 0;

        if (LOG_PRI(level) > log_target_max_level[LOG_TARGET_SYSLOG])
                return 0;

        snprintf(header_priority, sizeof(header_priority), "<%i>", level);
        char_array_0(header_priority);

        t = (time_t) (now(CLOCK_REALTIME) / USEC_PER_SEC);
        tm = localtime(&t);
        if (!tm)
                return -EINVAL;

        if (strftime(header_time, sizeof(header_time), "%h %e %T ", tm) <= 0)
                return -EINVAL;

        snprintf(header_pid, sizeof(header_pid), "["PID_FMT"]: ", getpid());
        char_array_0(header_pid);

        IOVEC_SET_STRING(iovec[0], header_priority);
        IOVEC_SET_STRING(iovec[1], header_time);
        IOVEC_SET_STRING(iovec[2], program_invocation_short_name);
        IOVEC_SET_STRING(iovec[3], header_pid);
        IOVEC_SET_STRING(iovec[4], buffer);

        /* When using syslog via SOCK_STREAM separate the messages by NUL chars */
        if (syslog_is_stream)
                iovec[4].iov_len++;

        for (;;) {
                ssize_t n;

                n = sendmsg(syslog_fd, &msghdr, MSG_NOSIGNAL);
                if (n < 0)
                        return -errno;

                if (!syslog_is_stream ||
                    (size_t) n >= IOVEC_TOTAL_SIZE(iovec, ELEMENTSOF(iovec)))
                        break;

                IOVEC_INCREMENT(iovec, ELEMENTSOF(iovec), n);
        }

        return 1;
}

/* The longest record that /dev/kmsg accepts, including the "<N>" prefix and the newline; the kernel refuses
 * longer ones with EINVAL. Since Linux 6.3 that is PRINTKRB_RECORD_MAX, 1024 bytes; from Linux 3.6 to 6.2 it
 * was LOG_LINE_MAX, 1024 - PREFIX_MAX, i.e. 992 bytes, or 976 bytes with CONFIG_PRINTK_CALLER (Linux 5.1 and
 * later); Linux 3.5 refused records of more than 1024 bytes, and older kernels took any length. */
#define KMSG_RECORD_MAX 992U
/* the mark of a message that is cut to fit into a record of /dev/kmsg */
#define KMSG_TRUNCATED "..."

static int write_to_kmsg(
                int level,
                int error __attribute__((unused)),
                const char *file __attribute__((unused)),
                int line __attribute__((unused)),
                const char *func __attribute__((unused)),
                const char *object_field __attribute__((unused)),
                const char *object __attribute__((unused)),
                const char *buffer) {

        char header_priority[1 + DECIMAL_STR_MAX(int) + 2], header_pid[1 + DECIMAL_STR_MAX(pid_t) + 4];
        struct iovec iovec[6] = {};
        size_t total;

        if (kmsg_fd < 0)
                return 0;

        if (LOG_PRI(level) > log_target_max_level[LOG_TARGET_KMSG])
                return 0;

        snprintf(header_priority, sizeof(header_priority), "<%i>", level);
        char_array_0(header_priority);

        snprintf(header_pid, sizeof(header_pid), "["PID_FMT"]: ", getpid());
        char_array_0(header_pid);

        IOVEC_SET_STRING(iovec[0], header_priority);
        IOVEC_SET_STRING(iovec[1], program_invocation_short_name);
        IOVEC_SET_STRING(iovec[2], header_pid);
        IOVEC_SET_STRING(iovec[3], buffer);
        IOVEC_SET_STRING(iovec[4], "");
        IOVEC_SET_STRING(iovec[5], "\n");

        /* Unlike systemd, which then gives up on /dev/kmsg, and writes this and all later messages to the
         * console, cut a message that does not fit into a record, at the start of a UTF-8 character, and
         * mark it as cut. The other log targets get the whole message. */
        total = IOVEC_TOTAL_SIZE(iovec, ELEMENTSOF(iovec));
        if (total > KMSG_RECORD_MAX) {
                size_t excess = total - KMSG_RECORD_MAX + STRLEN(KMSG_TRUNCATED);

                if (excess < iovec[3].iov_len) {
                        size_t n = iovec[3].iov_len - excess;

                        while (n > 0 && ((unsigned char) buffer[n] & 0xc0) == 0x80)
                                n--;
                        iovec[3].iov_len = n;
                        IOVEC_SET_STRING(iovec[4], KMSG_TRUNCATED);
                }
        }

        if (writev(kmsg_fd, iovec, ELEMENTSOF(iovec)) < 0)
                return -errno;

        return 1;
}

static int log_dispatch(
                int level,
                int error,
                const char*file,
                int line,
                const char *func,
                const char *object_field,
                const char *object,
                char *buffer) {

        if (error < 0)
                error = -error;

        if (log_target == LOG_TARGET_NULL)
                return -error;

        /* Patch in LOG_DAEMON facility if necessary */
        if ((level & LOG_FACMASK) == 0)
                level = log_facility | LOG_PRI(level);

        do {
                char *e;
                int k = 0;

                buffer += strspn(buffer, NEWLINE);

                if (buffer[0] == 0)
                        break;

                if ((e = strpbrk(buffer, NEWLINE)))
                        *(e++) = 0;

                if (log_target == LOG_TARGET_AUTO)
                        log_open_kmsg();

                if (log_target == LOG_TARGET_SYSLOG_OR_KMSG ||
                    log_target == LOG_TARGET_SYSLOG) {

                        k = write_to_syslog(level, error, file, line, func, object_field, object, buffer);
                        if (k < 0) {
                                if (k != -EAGAIN)
                                        log_close_syslog();
                                log_open_kmsg();
                        }
                }

                if (k <= 0 &&
                    (log_target == LOG_TARGET_AUTO ||
                     log_target == LOG_TARGET_SAFE ||
                     log_target == LOG_TARGET_SYSLOG_OR_KMSG ||
                     log_target == LOG_TARGET_KMSG)) {

                        k = write_to_kmsg(level, error, file, line, func, object_field, object, buffer);
                        if (k < 0) {
                                log_close_kmsg();
                                log_open_console();
                        }
                }

                /* like systemd, a failure to write to the console is ignored, and the error that was
                 * passed is returned */
                if (k <= 0)
                        (void) write_to_console(level, error, file, line, func, object_field, object, buffer);

                buffer = e;
        } while (buffer);

        return -error;
}

/* The longest message that is logged whole. The messages about applying a udev rule start with the
 * device, the rules file and its line, and the key with its value, which can be as long as a rule, 16383
 * characters, and up to four times that when escaped, and the message itself may contain a value of up
 * to 16 KiB again, e.g. a command; 128 KiB is enough for all of them. Other messages are much shorter;
 * one that does not fit into LINE_MAX is formatted again into a buffer of its size. The kernel refuses
 * records of more than 1 KiB in /dev/kmsg, or less on older kernels, though; a longer message is cut there,
 * see write_to_kmsg(). */
#define LOG_MESSAGE_MAX (128U * 1024U)

int log_internalv(
        int level,
        int error,
        const char*file,
        int line,
        const char *func,
        const char *format,
        va_list ap) {

        PROTECT_ERRNO;
        _cleanup_free_ char *long_buffer = NULL;
        char buffer[LINE_MAX];
        int saved_errno, n;
        va_list aq;

        if (error < 0)
                error = -error;

        if (_likely_(LOG_PRI(level) > log_max_level))
                return -error;

        /* Make sure that %m maps to the specified error */
        if (error != 0)
                errno = error;
        saved_errno = errno;

        va_copy(aq, ap);
        n = vsnprintf(buffer, sizeof(buffer), format, ap);
        char_array_0(buffer);

        if (n >= (int) sizeof(buffer)) {
                size_t size = MIN((size_t) n + 1, (size_t) LOG_MESSAGE_MAX);

                long_buffer = malloc(size);
                if (long_buffer) {
                        errno = saved_errno;
                        vsnprintf(long_buffer, size, format, aq);
                        long_buffer[size - 1] = '\0';
                }
        }
        va_end(aq);

        return log_dispatch(level, error, file, line, func, NULL, NULL, long_buffer ?: buffer);
}

int log_internal_long(
        int level,
        int error,
        const char *file,
        int line,
        const char *func,
        const char *message) {

        PROTECT_ERRNO;
        _cleanup_free_ char *buffer = NULL;

        if (error < 0)
                error = -error;

        if (_likely_(LOG_PRI(level) > log_max_level))
                return -error;

        /* log_dispatch() modifies the buffer while splitting the lines */
        buffer = strdup(message);
        if (!buffer)
                return log_internal(level, error, file, line, func, "%.*s", LINE_MAX - 1, message);

        return log_dispatch(level, error, file, line, func, NULL, NULL, buffer);
}

int log_internal(
                int level,
                int error,
                const char*file,
                int line,
                const char *func,
                const char *format, ...) {

        int r;
        va_list ap;

        va_start(ap, format);
        r = log_internalv(level, error, file, line, func, format, ap);
        va_end(ap);

        return r;
}

static void log_assert(
                int level,
                const char *text,
                const char *file,
                int line,
                const char *func,
                const char *format) {
        static char buffer[LINE_MAX];

        if (_likely_(LOG_PRI(level) > log_max_level))
                return;

        DISABLE_WARNING_FORMAT_NONLITERAL;
        snprintf(buffer, sizeof(buffer), format, text, file, line, func);
        REENABLE_WARNING;

        char_array_0(buffer);
        log_abort_msg = buffer;

        log_dispatch(level, 0, file, line, func, NULL, NULL, buffer);
}

noreturn void log_assert_failed(const char *text, const char *file, int line, const char *func) {
        log_assert(LOG_CRIT, text, file, line, func, "Assertion '%s' failed at %s:%u, function %s(). Aborting.");
        abort();
}

noreturn void log_assert_failed_unreachable(const char *text, const char *file, int line, const char *func) {
        log_assert(LOG_CRIT, text, file, line, func, "Code should not be reached '%s' at %s:%u, function %s(). Aborting.");
        abort();
}

int log_oom_internal(const char *file, int line, const char *func) {
        log_internal(LOG_ERR, ENOMEM, file, line, func, "Out of memory.");
        return -ENOMEM;
}

int log_get_max_level(void) {
        return log_max_level;
}

static int log_set_target_from_string(const char *e) {
        LogTarget t;

        t = log_target_from_string(e);
        if (t < 0)
                return -EINVAL;

        log_set_target(t);
        return 0;
}

/* Like log_set_max_level_from_string() of systemd: a comma-separated list of log levels, by name or
 * number, the global one, or one of a single target, console, kmsg or syslog, with the name of the target
 * and a colon in front, e.g. "debug,console:info"; systemd's journal target does not exist in eudev. The
 * values are applied in order, until one is invalid. */
static int log_set_max_level_from_string(const char *e) {
        _cleanup_strv_free_ char **words = NULL;
        char **w;
        int r;

        r = strv_split_and_extend(&words, e, ",", false);
        if (r < 0)
                return r;

        STRV_FOREACH(w, words) {
                _cleanup_free_ char *prefix = NULL;
                const char *colon;
                LogTarget target;
                int level;

                colon = strchr(*w, ':');
                if (!colon) {
                        level = log_level_from_string(*w);
                        if (level < 0)
                                return -EINVAL;

                        log_set_max_level(level);
                        continue;
                }

                prefix = strndup(*w, colon - *w);
                if (!prefix)
                        return -ENOMEM;

                target = log_target_from_string(prefix);
                if (!IN_SET(target, LOG_TARGET_CONSOLE, LOG_TARGET_KMSG, LOG_TARGET_SYSLOG))
                        return -EINVAL;

                level = log_level_from_string(colon + 1);
                if (level < 0)
                        return -EINVAL;

                log_target_max_level[target] = level;
        }

        return 0;
}

static int log_show_color_from_string(const char *e) {
        int r;

        r = parse_boolean(e);
        if (r < 0)
                return r;

        show_color = r;
        return 0;
}

static int log_show_location_from_string(const char *e) {
        int r;

        r = parse_boolean(e);
        if (r < 0)
                return r;

        show_location = r;
        return 0;
}

/* $UDEV_LOG_<name>, or $SYSTEMD_LOG_<name> when that is not set */
static const char *log_getenv(const char *name) {
        const char *u, *s, *e;

        u = strjoina("UDEV_LOG_", name);
        s = strjoina("SYSTEMD_LOG_", name);

        e = getenv(u);
        if (!e)
                e = getenv(s);

        return e;
}

void log_parse_environment(void) {
        const char *e;
        int r;

        e = log_getenv("TARGET");
        if (e && log_set_target_from_string(e) < 0)
                log_warning("Failed to parse log target '%s', ignoring.", e);

        e = log_getenv("LEVEL");
        if (e) {
                r = log_set_max_level_from_string(e);
                if (r < 0)
                        log_warning_errno(r, "Failed to parse log level '%s', ignoring: %m", e);
        }

        e = log_getenv("COLOR");
        if (e && log_show_color_from_string(e) < 0)
                log_warning("Failed to parse log color '%s', ignoring.", e);

        e = log_getenv("LOCATION");
        if (e && log_show_location_from_string(e) < 0)
                log_warning("Failed to parse log location '%s', ignoring.", e);
}
static const char *const log_target_table[] = {
        [LOG_TARGET_CONSOLE] = "console",
        [LOG_TARGET_CONSOLE_PREFIXED] = "console-prefixed",
        [LOG_TARGET_KMSG] = "kmsg",
        [LOG_TARGET_SYSLOG] = "syslog",
        [LOG_TARGET_SYSLOG_OR_KMSG] = "syslog-or-kmsg",
        [LOG_TARGET_AUTO] = "auto",
        [LOG_TARGET_SAFE] = "safe",
        [LOG_TARGET_NULL] = "null"
};

DEFINE_STRING_TABLE_LOOKUP(log_target, LogTarget);
