/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* ifname_valid_full() and its helpers, as in src/basic/socket-util.c and src/basic/parse-util.c of
 * systemd a446e8ff2c. */

#include <errno.h>
#include <string.h>

#include "socket-util.h"
#include "util.h"

int parse_ifindex(const char *s) {
        int ifi, r;

        assert(s);

        r = safe_atoi(s, &ifi);
        if (r < 0)
                return r;
        if (ifi <= 0)
                return -EINVAL;

        return ifi;
}

bool ifname_valid_char(char a) {
        if ((unsigned char) a >= 127U)
                return false;

        if ((unsigned char) a <= 32U)
                return false;

        if (IN_SET(a,
                   ':',  /* colons are used by the legacy "alias" interface logic */
                   '/',  /* slashes cannot work, since we need to use network interfaces in sysfs paths, and in paths slashes are separators */
                   '%')) /* %d is used in the kernel's weird foo%d format string naming feature which we really really don't want to ever run into by accident */
                return false;

        return true;
}

bool ifname_valid_full(const char *p, IfnameValidFlags flags) {
        bool numeric = true;
        const char *t;

        /* Checks whether a network interface name is valid. This is inspired by dev_valid_name() in the kernel sources
         * but slightly stricter, as we only allow non-control, non-space ASCII characters in the interface name. We
         * also don't permit names that only container numbers, to avoid confusion with numeric interface indexes. */

        assert(!(flags & ~_IFNAME_VALID_ALL));

        if (isempty(p))
                return false;

        /* A valid ifindex? If so, it's valid iff IFNAME_VALID_NUMERIC is set */
        if (parse_ifindex(p) >= 0)
                return flags & IFNAME_VALID_NUMERIC;

        if (flags & IFNAME_VALID_ALTERNATIVE) {
                if (strlen(p) >= ALTIFNAMSIZ)
                        return false;
        } else {
                if (strlen(p) >= IFNAMSIZ)
                        return false;
        }

        if (streq(p, ".") || streq(p, ".."))
                return false;

        /* Let's refuse "all" and "default" as interface name, to avoid collisions with the special sysctl
         * directories /proc/sys/net/{ipv4,ipv6}/conf/{all,default} */
        if (!(flags & IFNAME_VALID_SPECIAL) && (streq(p, "all") || streq(p, "default")))
                return false;

        for (t = p; *t; t++) {
                if (!ifname_valid_char(*t))
                        return false;

                numeric = numeric && (*t >= '0' && *t <= '9');
        }

        /* It's fully numeric but didn't parse as valid ifindex above? if so, it must be too large or zero or
         * so, let's refuse that. */
        if (numeric)
                return false;

        return true;
}
