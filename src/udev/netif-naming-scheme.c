/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "netif-naming-scheme.h"
#include "utf8.h"
#include "util.h"

/* eudev: the default can be changed at build time, e.g. with CPPFLAGS=-DDEFAULT_NET_NAMING_SCHEME='"eudev"'. */
#ifndef DEFAULT_NET_NAMING_SCHEME
#define DEFAULT_NET_NAMING_SCHEME "latest"
#endif

static const NamingScheme naming_schemes[] = {
        { "eudev", NAMING_EUDEV },
        { "v238",  NAMING_V238 },
        { "v239",  NAMING_V239 },
        { "v240",  NAMING_V240 },
        { "v241",  NAMING_V241 },
        { "v243",  NAMING_V243 },
        { "v245",  NAMING_V245 },
        { "v247",  NAMING_V247 },
        { "v249",  NAMING_V249 },
        { "v250",  NAMING_V250 },
        { "v251",  NAMING_V251 },
        { "v252",  NAMING_V252 },
        { "v253",  NAMING_V253 },
        { "v254",  NAMING_V254 },
        { "v255",  NAMING_V255 },
        { "v257",  NAMING_V257 },
        { "v258",  NAMING_V258 },
        { "v259",  NAMING_V259 },
        { "v260",  NAMING_V260 },
        { "v261",  NAMING_V261 },
        /* … add more schemes here, as the logic to name devices is updated … */
};

const NamingScheme* naming_scheme_from_name(const char *name) {
        size_t i;

        /* "latest" maps to the last defined entry, whatever that is. */

        for (i = 0; i < ELEMENTSOF(naming_schemes); i++)
                if (streq(naming_schemes[i].name, name))
                        return naming_schemes + i;

        if (streq(name, "latest"))
                return naming_schemes + ELEMENTSOF(naming_schemes) - 1;

        return NULL;
}

static bool relaxed_equal_char(char a, char b) {
        return a == b ||
                (a == '_' && b == '-') ||
                (a == '-' && b == '_');
}

static bool proc_cmdline_key_streq(const char *x, const char *y) {
        /* Much like streq(), but considers "_" and "-" equivalent */

        for (;;) {
                if (!relaxed_equal_char(*x, *y))
                        return false;

                if (*x == 0)
                        return true;

                x++, y++;
        }
}

static char *cmdline_naming_scheme = NULL;

static int parse_proc_cmdline_item(const char *key, const char *value) {
        char *s;

        if (!value || !proc_cmdline_key_streq(key, "net.naming_scheme"))
                return 0;

        /* The last occurrence wins. */
        s = strdup(value);
        if (!s)
                return log_oom();

        free_and_replace(cmdline_naming_scheme, s);
        return 0;
}

const NamingScheme* naming_scheme(void) {
        static const NamingScheme *cache = NULL;
        const char *e, *k;
        int r;

        if (cache)
                return cache;

        /* Acquire setting from the kernel command line */
        r = parse_proc_cmdline(parse_proc_cmdline_item);
        if (r < 0)
                log_debug_errno(r, "Failed to parse kernel command line, ignoring: %m");

        /* Also acquire it from an env var */
        e = getenv("NET_NAMING_SCHEME");
        if (e) {
                if (*e == ':') {
                        /* If prefixed with ':' the kernel cmdline takes precedence */
                        k = cmdline_naming_scheme ?: e + 1;
                } else
                        k = e; /* Otherwise the env var takes precedence */
        } else
                k = cmdline_naming_scheme;

        if (k) {
                cache = naming_scheme_from_name(k);
                if (cache) {
                        log_info("Using interface naming scheme '%s'.", cache->name);
                        goto finish;
                }

                log_warning("Unknown interface naming scheme '%s' requested, ignoring.", k);
        }

        cache = naming_scheme_from_name(DEFAULT_NET_NAMING_SCHEME);
        assert_se(cache);
        log_info("Using default interface naming scheme '%s'.", cache->name);

finish:
        free(cmdline_naming_scheme);
        cmdline_naming_scheme = NULL;
        return cache;
}

static int parse_boolean(const char *v) {
        if (streq(v, "1") || strcaseeq(v, "yes") || strcaseeq(v, "y") ||
            strcaseeq(v, "true") || strcaseeq(v, "t") || strcaseeq(v, "on"))
                return 1;
        if (streq(v, "0") || strcaseeq(v, "no") || strcaseeq(v, "n") ||
            strcaseeq(v, "false") || strcaseeq(v, "f") || strcaseeq(v, "off"))
                return 0;
        return -EINVAL;
}

static int device_get_sysattr_value(struct udev_device *dev, const char *sysattr, const char **ret) {
        const char *value;

        value = udev_device_get_sysattr_value(dev, sysattr);
        if (!value)
                return -ENOENT;

        *ret = value;
        return 0;
}

static bool sysattr_string_is_safe(const char *p) {
        /* Like systemd's string_is_safe() with STRING_ALLOW_EMPTY, STRING_ALLOW_NEWLINES,
         * STRING_ALLOW_BACKSLASHES, STRING_ALLOW_QUOTES and STRING_ALLOW_GLOBS: the string must be
         * valid UTF-8 and must not contain control characters other than newline. */

        while (*p) {
                int len;

                if ((*p > 0 && *p < ' ' && *p != '\n') || *p == 0x7f)
                        return false;

                len = utf8_encoded_valid_unichar(p);
                if (len < 0)
                        return false;

                p += len;
        }

        return true;
}

int device_get_sysattr_int(struct udev_device *device, const char *sysattr, int *ret_value) {
        const char *value;
        int r, v;

        r = device_get_sysattr_value(device, sysattr, &value);
        if (r < 0)
                return r;

        r = safe_atoi(value, &v);
        if (r < 0)
                return log_debug_errno(r, "%s: Failed to parse '%s' attribute: %m",
                                       udev_device_get_sysname(device), sysattr);

        if (ret_value)
                *ret_value = v;
        /* We return "true" if the value is positive. */
        return v > 0;
}

int device_get_sysattr_unsigned(struct udev_device *device, const char *sysattr, unsigned *ret_value) {
        const char *value;
        unsigned v;
        int r;

        r = device_get_sysattr_value(device, sysattr, &value);
        if (r < 0)
                return r;

        r = safe_atou_full(value, 0, &v);
        if (r < 0)
                return log_debug_errno(r, "%s: Failed to parse '%s' attribute: %m",
                                       udev_device_get_sysname(device), sysattr);

        if (ret_value)
                *ret_value = v;
        /* We return "true" if the value is positive. */
        return v > 0;
}

int device_get_sysattr_bool(struct udev_device *device, const char *sysattr) {
        const char *value;
        int r;

        r = device_get_sysattr_value(device, sysattr, &value);
        if (r < 0)
                return r;

        return parse_boolean(value);
}

int device_get_sysattr_safe_string(struct udev_device *device, const char *sysattr, const char **ret_value) {
        const char *value;
        int r;

        r = device_get_sysattr_value(device, sysattr, &value);
        if (r < 0)
                return r;

        if (!sysattr_string_is_safe(value)) {
                log_debug("%s: '%s' sysattr contains invalid characters, refusing.",
                          udev_device_get_sysname(device), sysattr);
                return -ENXIO;
        }

        if (ret_value)
                *ret_value = value;
        return 0;
}
