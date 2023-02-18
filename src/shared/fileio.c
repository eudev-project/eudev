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

#include <unistd.h>
#include <sys/sendfile.h>
#include <stdio_ext.h>
#include "fileio.h"
#include "util.h"
#include "strv.h"
#include "utf8.h"
#include "ctype.h"
#include "socket-util.h"

int write_string_stream(FILE *f, const char *line) {
        assert(f);
        assert(line);

        errno = 0;

        fputs(line, f);
        if (!endswith(line, "\n"))
                fputc('\n', f);

        fflush(f);

        if (ferror(f))
                return errno ? -errno : -EIO;

        return 0;
}

int write_string_file(const char *fn, const char *line) {
        _cleanup_fclose_ FILE *f = NULL;

        assert(fn);
        assert(line);

        f = fopen(fn, "we");
        if (!f)
                return -errno;

        return write_string_stream(f, line);
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

int read_full_stream(FILE *f, char **contents, size_t *size) {
        size_t n, l;
        _cleanup_free_ char *buf = NULL;
        struct stat st;

        assert(f);
        assert(contents);

        if (fstat(fileno(f), &st) < 0)
                return -errno;

        n = LINE_MAX;

        if (S_ISREG(st.st_mode)) {

                /* Safety check */
                if (st.st_size > 4*1024*1024)
                        return -E2BIG;

                /* Start with the right file size, but be prepared for
                 * files from /proc which generally report a file size
                 * of 0 */
                if (st.st_size > 0)
                        n = st.st_size;
        }

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
        buf = NULL; /* do not free */

        if (size)
                *size = l;

        return 0;
}

int read_full_file(const char *fn, char **contents, size_t *size) {
        _cleanup_fclose_ FILE *f = NULL;

        assert(fn);
        assert(contents);

        f = fopen(fn, "re");
        if (!f)
                return -errno;

        return read_full_stream(f, contents, size);
}

int fopen_mode_to_flags(const char *mode) {
        const char *p;
        int flags;

        assert(mode);

        if ((p = startswith(mode, "r+")))
                flags = O_RDWR;
        else if ((p = startswith(mode, "r")))
                flags = O_RDONLY;
        else if ((p = startswith(mode, "w+")))
                flags = O_RDWR|O_CREAT|O_TRUNC;
        else if ((p = startswith(mode, "w")))
                flags = O_WRONLY|O_CREAT|O_TRUNC;
        else if ((p = startswith(mode, "a+")))
                flags = O_RDWR|O_CREAT|O_APPEND;
        else if ((p = startswith(mode, "a")))
                flags = O_WRONLY|O_CREAT|O_APPEND;
        else
                return -EINVAL;

        for (; *p != 0; p++) {

                switch (*p) {

                case 'e':
                        flags |= O_CLOEXEC;
                        break;

                case 'x':
                        flags |= O_EXCL;
                        break;

                case 'm':
                        /* ignore this here, fdopen() might care later though */
                        break;

                case 'c': /* not sure what to do about this one */
                default:
                        return -EINVAL;
                }
        }

        return flags;
}

int xfopenat(int dir_fd, const char *path, const char *mode, int flags, FILE **ret) {
        FILE *f;

        /* A combination of fopen() with openat() */

        if (dir_fd == AT_FDCWD && flags == 0) {
                f = fopen(path, mode);
                if (!f)
                        return -errno;
        } else {
                int fd, mode_flags;

                mode_flags = fopen_mode_to_flags(mode);
                if (mode_flags < 0)
                        return mode_flags;

                fd = openat(dir_fd, path, mode_flags | flags);
                if (fd < 0)
                        return -errno;

                f = fdopen(fd, mode);
                if (!f) {
                        safe_close(fd);
                        return -errno;
                }
        }

        *ret = f;
        return 0;
}

int read_full_file_full(
                int dir_fd,
                const char *filename,
                uint64_t offset,
                size_t size,
                ReadFullFileFlags flags,
                const char *bind_name,
                char **ret_contents,
                size_t *ret_size) {

        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(filename);
        assert(ret_contents);

        r = xfopenat(dir_fd, filename, "re", 0, &f);
        if (r < 0) {
                _cleanup_close_ int sk = -1;

                /* ENXIO is what Linux returns if we open a node that is an AF_UNIX socket */
                if (r != -ENXIO)
                        return r;

                /* If this is enabled, let's try to connect to it */
                if (!FLAGS_SET(flags, READ_FULL_FILE_CONNECT_SOCKET))
                        return -ENXIO;

                /* Seeking is not supported on AF_UNIX sockets */
                if (offset != UINT64_MAX)
                        return -ENXIO;

                sk = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
                if (sk < 0)
                        return -errno;

                if (bind_name) {
                        /* If the caller specified a socket name to bind to, do so before connecting. This is
                         * useful to communicate some minor, short meta-information token from the client to
                         * the server. */
                        union sockaddr_union bsa;

                        r = sockaddr_un_set_path(&bsa.un, bind_name);
                        if (r < 0)
                                return r;

                        if (bind(sk, &bsa.sa, r) < 0)
                                return -errno;
                }

                r = connect_unix_path(sk, dir_fd, filename);
                if (IN_SET(r, -ENOTSOCK, -EINVAL)) /* propagate original error if this is not a socket after all */
                        return -ENXIO;
                if (r < 0)
                        return r;

                if (shutdown(sk, SHUT_WR) < 0)
                        return -errno;

                f = fdopen(sk, "r");
                if (!f)
                        return -errno;

                TAKE_FD(sk);
        }

        (void) __fsetlocking(f, FSETLOCKING_BYCALLER);

        return read_full_stream_full(f, filename, offset, size, flags, ret_contents, ret_size);
}

int read_full_stream_full(
                FILE *f,
                const char *filename,
                uint64_t offset,
                size_t size,
                ReadFullFileFlags flags,
                char **ret_contents,
                size_t *ret_size) {

        _cleanup_free_ char *buf = NULL;
        size_t n, n_next = 0, l;
        int fd, r;

        assert(f);
        assert(ret_contents);
        assert(!FLAGS_SET(flags, READ_FULL_FILE_UNBASE64 | READ_FULL_FILE_UNHEX));
        assert(size != SIZE_MAX || !FLAGS_SET(flags, READ_FULL_FILE_FAIL_WHEN_LARGER));

        if (offset != UINT64_MAX && offset > LONG_MAX) /* fseek() can only deal with "long" offsets */
                return -ERANGE;

        fd = fileno(f);
        if (fd >= 0) { /* If the FILE* object is backed by an fd (as opposed to memory or such, see
                        * fmemopen()), let's optimize our buffering */
                struct stat st;

                if (fstat(fd, &st) < 0)
                        return -errno;

                if (S_ISREG(st.st_mode)) {

                        /* Try to start with the right file size if we shall read the file in full. Note
                         * that we increase the size to read here by one, so that the first read attempt
                         * already makes us notice the EOF. If the reported size of the file is zero, we
                         * avoid this logic however, since quite likely it might be a virtual file in procfs
                         * that all report a zero file size. */

                        if (st.st_size > 0 &&
                            (size == SIZE_MAX || FLAGS_SET(flags, READ_FULL_FILE_FAIL_WHEN_LARGER))) {

                                uint64_t rsize =
                                        LESS_BY((uint64_t) st.st_size, offset == UINT64_MAX ? 0 : offset);

                                if (rsize < SIZE_MAX) /* overflow check */
                                        n_next = rsize + 1;
                        }

                        if (flags & READ_FULL_FILE_WARN_WORLD_READABLE)
                                (void) warn_file_is_world_accessible(filename, &st, NULL, 0);
                }
        }

        /* If we don't know how much to read, figure it out now. If we shall read a part of the file, then
         * allocate the requested size. If we shall load the full file start with LINE_MAX. Note that if
         * READ_FULL_FILE_FAIL_WHEN_LARGER we consider the specified size a safety limit, and thus also start
         * with LINE_MAX, under assumption the file is most likely much shorter. */
        if (n_next == 0)
                n_next = size != SIZE_MAX && !FLAGS_SET(flags, READ_FULL_FILE_FAIL_WHEN_LARGER) ? size : LINE_MAX;

        /* Never read more than we need to determine that our own limit is hit */
        if (n_next > READ_FULL_BYTES_MAX)
                n_next = READ_FULL_BYTES_MAX + 1;

        if (offset != UINT64_MAX && fseek(f, offset, SEEK_SET) < 0)
                return -errno;

        n = l = 0;
        for (;;) {
                char *t;
                size_t k;

                /* If we shall fail when reading overly large data, then read exactly one byte more than the
                 * specified size at max, since that'll tell us if there's anymore data beyond the limit*/
                if (FLAGS_SET(flags, READ_FULL_FILE_FAIL_WHEN_LARGER) && n_next > size)
                        n_next = size + 1;

                if (flags & READ_FULL_FILE_SECURE) {
                        t = malloc(n_next + 1);
                        if (!t) {
                                r = -ENOMEM;
                                goto finalize;
                        }
                        memcpy_safe(t, buf, n);
                        explicit_bzero_safe(buf, n);
                        free(buf);
                } else {
                        t = realloc(buf, n_next + 1);
                        if (!t)
                                return -ENOMEM;
                }

                buf = t;
                /* Unless a size has been explicitly specified, try to read as much as fits into the memory
                 * we allocated (minus 1, to leave one byte for the safety NUL byte) */
                n = size == SIZE_MAX ? MALLOC_SIZEOF_SAFE(buf) - 1 : n_next;

                errno = 0;
                k = fread(buf + l, 1, n - l, f);

                assert(k <= n - l);
                l += k;

                if (ferror(f)) {
                        r = errno_or_else(EIO);
                        goto finalize;
                }
                if (feof(f))
                        break;

                if (size != SIZE_MAX && !FLAGS_SET(flags, READ_FULL_FILE_FAIL_WHEN_LARGER)) { /* If we got asked to read some specific size, we already sized the buffer right, hence leave */
                        assert(l == size);
                        break;
                }

                assert(k > 0); /* we can't have read zero bytes because that would have been EOF */

                if (FLAGS_SET(flags, READ_FULL_FILE_FAIL_WHEN_LARGER) && l > size) {
                        r = -E2BIG;
                        goto finalize;
                }

                if (n >= READ_FULL_BYTES_MAX) {
                        r = -E2BIG;
                        goto finalize;
                }

                n_next = MIN(n * 2, READ_FULL_BYTES_MAX);
        }

        if (flags & (READ_FULL_FILE_UNBASE64 | READ_FULL_FILE_UNHEX)) {
                _cleanup_free_ void *decoded = NULL;
                size_t decoded_size;

                buf[l++] = 0;
                if (flags & READ_FULL_FILE_UNBASE64)
                        r = unbase64mem_full(buf, l, flags & READ_FULL_FILE_SECURE, &decoded, &decoded_size);
                else
                        r = unhexmem_full(buf, l, flags & READ_FULL_FILE_SECURE, &decoded, &decoded_size);
                if (r < 0)
                        goto finalize;

                if (flags & READ_FULL_FILE_SECURE)
                        explicit_bzero_safe(buf, n);
                free_and_replace(buf, decoded);
                n = l = decoded_size;
        }

        if (!ret_size) {
                /* Safety check: if the caller doesn't want to know the size of what we just read it will rely on the
                 * trailing NUL byte. But if there's an embedded NUL byte, then we should refuse operation as otherwise
                 * there'd be ambiguity about what we just read. */

                if (memchr(buf, 0, l)) {
                        r = -EBADMSG;
                        goto finalize;
                }
        }

        buf[l] = 0;
        *ret_contents = TAKE_PTR(buf);

        if (ret_size)
                *ret_size = l;

        return 0;

finalize:
        if (flags & READ_FULL_FILE_SECURE)
                explicit_bzero_safe(buf, n);

        return r;
}

int warn_file_is_world_accessible(const char *filename, struct stat *st, const char *unit, unsigned line) {
        struct stat _st;

        if (!filename)
                return 0;

        if (!st) {
                if (stat(filename, &_st) < 0)
                        return -errno;
                st = &_st;
        }

        if ((st->st_mode & S_IRWXO) == 0)
                return 0;

        //if (unit)
        //        log_syntax(unit, LOG_WARNING, filename, line, 0,
        //                   "%s has %04o mode that is too permissive, please adjust the ownership and access mode.",
        //                   filename, st->st_mode & 07777);
        //else
                log_warning("%s has %04o mode that is too permissive, please adjust the ownership and access mode.",
                            filename, st->st_mode & 07777);
        return 0;
}
