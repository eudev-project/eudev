/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "fileio.h"
#include "id128-util.h"
#include "util.h"

int id128_from_string(const char *s, id128_t *ret) {
        id128_t t;
        size_t n, i = 0, j = 0;
        bool is_uuid;

        assert(s);

        /* Like sd_id128_from_string() of systemd: 32 hexadecimal digits, optionally in the UUID form
         * with dashes after the 8th, 12th, 16th and 20th digit. */

        n = strlen(s);
        if (n == 32)
                is_uuid = false;
        else if (n == 36)
                is_uuid = true;
        else
                return -EINVAL;

        while (i < 16) {
                int a, b;

                if (is_uuid && IN_SET(j, 8, 13, 18, 23)) {
                        if (s[j] != '-')
                                return -EINVAL;
                        j++;
                        continue;
                }

                a = unhexchar(s[j++]);
                if (a < 0)
                        return -EINVAL;

                b = unhexchar(s[j++]);
                if (b < 0)
                        return -EINVAL;

                t.bytes[i++] = (a << 4) | b;
        }

        if (s[j] != 0)
                return -EINVAL;

        if (ret)
                *ret = t;
        return 0;
}

char *id128_to_uuid_string(id128_t id, char s[static ID128_UUID_STRING_MAX]) {
        size_t k = 0;
        unsigned i;

        for (i = 0; i < 16; i++) {
                if (IN_SET(i, 4, 6, 8, 10))
                        s[k++] = '-';

                s[k++] = hexchar(id.bytes[i] >> 4);
                s[k++] = hexchar(id.bytes[i] & 0xF);
        }

        s[k] = 0;
        return s;
}

bool id128_in_set_internal(id128_t id, const id128_t *set, unsigned n) {
        unsigned i;

        for (i = 0; i < n; i++)
                if (id128_equal(id, set[i]))
                        return true;

        return false;
}

int id128_get_boot(id128_t *ret) {
        _cleanup_free_ char *s = NULL;
        int r;

        r = read_one_line_file("/proc/sys/kernel/random/boot_id", &s);
        if (r < 0)
                return r;

        return id128_from_string(s, ret);
}
