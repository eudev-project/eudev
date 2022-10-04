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

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "macro.h"
#include "util.h"

typedef enum {
        READ_FULL_FILE_SECURE              = 1 << 0, /* erase any buffers we employ internally, after use */
        READ_FULL_FILE_UNBASE64            = 1 << 1, /* base64 decode what we read */
        READ_FULL_FILE_UNHEX               = 1 << 2, /* hex decode what we read */
        READ_FULL_FILE_WARN_WORLD_READABLE = 1 << 3, /* if regular file, log at LOG_WARNING level if access mode above 0700 */
        READ_FULL_FILE_CONNECT_SOCKET      = 1 << 4, /* if socket inode, connect to it and read off it */
        READ_FULL_FILE_FAIL_WHEN_LARGER    = 1 << 5, /* fail loading if file is larger than specified size */
} ReadFullFileFlags;

int write_string_stream(FILE *f, const char *line);
int write_string_file(const char *fn, const char *line);
int read_one_line_file(const char *fn, char **line);
int read_full_file(const char *fn, char **contents, size_t *size);
int read_full_stream(FILE *f, char **contents, size_t *size);
int read_full_stream_full(FILE *f, const char *filename, uint64_t offset, size_t size, ReadFullFileFlags flags, char **ret_contents, size_t *ret_size);

static inline int unhex_next(const char **p, size_t *l) {
        int r;

        assert(p);
        assert(l);

        /* Find the next non-whitespace character, and decode it. We
         * greedily skip all preceding and all following whitespace. */

        for (;;) {
                if (*l == 0)
                        return -EPIPE;

                if (!strchr(WHITESPACE, **p))
                        break;

                /* Skip leading whitespace */
                (*p)++, (*l)--;
        }

        r = unhexchar(**p);
        if (r < 0)
                return r;

        for (;;) {
                (*p)++, (*l)--;

                if (*l == 0 || !strchr(WHITESPACE, **p))
                        break;

                /* Skip following whitespace */
        }

        return r;
}

static inline int unhexmem_full(const char *p, size_t l, bool secure, void **ret, size_t *ret_len) {
        _cleanup_free_ uint8_t *buf = NULL;
        size_t buf_size;
        const char *x;
        uint8_t *z;
        int r;

        assert(p || l == 0);

        if (l == SIZE_MAX)
                l = strlen(p);

        /* Note that the calculation of memory size is an upper boundary, as we ignore whitespace while decoding */
        buf_size = (l + 1) / 2 + 1;
        buf = malloc(buf_size);
        if (!buf)
                return -ENOMEM;

        for (x = p, z = buf;;) {
                int a, b;

                a = unhex_next(&x, &l);
                if (a == -EPIPE) /* End of string */
                        break;
                if (a < 0) {
                        r = a;
                        goto on_failure;
                }

                b = unhex_next(&x, &l);
                if (b < 0) {
                        r = b;
                        goto on_failure;
                }

                *(z++) = (uint8_t) a << 4 | (uint8_t) b;
        }

        *z = 0;

        if (ret_len)
                *ret_len = (size_t) (z - buf);
        if (ret)
                *ret = TAKE_PTR(buf);

        return 0;

on_failure:
        if (secure)
                explicit_bzero_safe(buf, buf_size);

        return r;
}

static inline int unbase64char(char c) {
        unsigned offset;

        if (c >= 'A' && c <= 'Z')
                return c - 'A';

        offset = 'Z' - 'A' + 1;

        if (c >= 'a' && c <= 'z')
                return c - 'a' + offset;

        offset += 'z' - 'a' + 1;

        if (c >= '0' && c <= '9')
                return c - '0' + offset;

        offset += '9' - '0' + 1;

        if (c == '+')
                return offset;

        offset++;

        if (c == '/')
                return offset;

        return -EINVAL;
}

static inline int unbase64_next(const char **p, size_t *l) {
        int ret;

        assert(p);
        assert(l);

        /* Find the next non-whitespace character, and decode it. If we find padding, we return it as INT_MAX. We
         * greedily skip all preceding and all following whitespace. */

        for (;;) {
                if (*l == 0)
                        return -EPIPE;

                if (!strchr(WHITESPACE, **p))
                        break;

                /* Skip leading whitespace */
                (*p)++, (*l)--;
        }

        if (**p == '=')
                ret = INT_MAX; /* return padding as INT_MAX */
        else {
                ret = unbase64char(**p);
                if (ret < 0)
                        return ret;
        }

        for (;;) {
                (*p)++, (*l)--;

                if (*l == 0)
                        break;
                if (!strchr(WHITESPACE, **p))
                        break;

                /* Skip following whitespace */
        }

        return ret;
}

static inline int unbase64mem_full(const char *p, size_t l, bool secure, void **ret, size_t *ret_size) {
        _cleanup_free_ uint8_t *buf = NULL;
        const char *x;
        uint8_t *z;
        size_t len;
        int r;

        assert(p || l == 0);

        if (l == SIZE_MAX)
                l = strlen(p);

        /* A group of four input bytes needs three output bytes, in case of padding we need to add two or three extra
         * bytes. Note that this calculation is an upper boundary, as we ignore whitespace while decoding */
        len = (l / 4) * 3 + (l % 4 != 0 ? (l % 4) - 1 : 0);

        buf = malloc(len + 1);
        if (!buf)
                return -ENOMEM;

        for (x = p, z = buf;;) {
                int a, b, c, d; /* a == 00XXXXXX; b == 00YYYYYY; c == 00ZZZZZZ; d == 00WWWWWW */

                a = unbase64_next(&x, &l);
                if (a == -EPIPE) /* End of string */
                        break;
                if (a < 0) {
                        r = a;
                        goto on_failure;
                }
                if (a == INT_MAX) { /* Padding is not allowed at the beginning of a 4ch block */
                        r = -EINVAL;
                        goto on_failure;
                }

                b = unbase64_next(&x, &l);
                if (b < 0) {
                        r = b;
                        goto on_failure;
                }
                if (b == INT_MAX) { /* Padding is not allowed at the second character of a 4ch block either */
                        r = -EINVAL;
                        goto on_failure;
                }

                c = unbase64_next(&x, &l);
                if (c < 0) {
                        r = c;
                        goto on_failure;
                }

                d = unbase64_next(&x, &l);
                if (d < 0) {
                        r = d;
                        goto on_failure;
                }

                if (c == INT_MAX) { /* Padding at the third character */

                        if (d != INT_MAX) { /* If the third character is padding, the fourth must be too */
                                r = -EINVAL;
                                goto on_failure;
                        }

                        /* b == 00YY0000 */
                        if (b & 15) {
                                r = -EINVAL;
                                goto on_failure;
                        }

                        if (l > 0) { /* Trailing rubbish? */
                                r = -ENAMETOOLONG;
                                goto on_failure;
                        }

                        *(z++) = (uint8_t) a << 2 | (uint8_t) (b >> 4); /* XXXXXXYY */
                        break;
                }

                if (d == INT_MAX) {
                        /* c == 00ZZZZ00 */
                        if (c & 3) {
                                r = -EINVAL;
                                goto on_failure;
                        }

                        if (l > 0) { /* Trailing rubbish? */
                                r = -ENAMETOOLONG;
                                goto on_failure;
                        }

                        *(z++) = (uint8_t) a << 2 | (uint8_t) b >> 4; /* XXXXXXYY */
                        *(z++) = (uint8_t) b << 4 | (uint8_t) c >> 2; /* YYYYZZZZ */
                        break;
                }

                *(z++) = (uint8_t) a << 2 | (uint8_t) b >> 4; /* XXXXXXYY */
                *(z++) = (uint8_t) b << 4 | (uint8_t) c >> 2; /* YYYYZZZZ */
                *(z++) = (uint8_t) c << 6 | (uint8_t) d;      /* ZZWWWWWW */
        }

        *z = 0;

        if (ret_size)
                *ret_size = (size_t) (z - buf);
        if (ret)
                *ret = TAKE_PTR(buf);

        return 0;

on_failure:
        if (secure)
                explicit_bzero_safe(buf, len);

        return r;
}

int warn_file_is_world_accessible(const char *filename, struct stat *st, const char *unit, unsigned line);

int read_full_file_full(
                int dir_fd,
                const char *filename,
                uint64_t offset,
                size_t size,
                ReadFullFileFlags flags,
                const char *bind_name,
                char **ret_contents,
                size_t *ret_size);
