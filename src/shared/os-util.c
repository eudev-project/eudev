/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "def.h"
#include "fileio.h"
#include "os-util.h"
#include "util.h"

#define SHELL_NEED_ESCAPE "\"\\`$"

static bool env_name_is_valid_n(const char *e, size_t n) {
        size_t i;

        if (n == 0)
                return false;

        if (e[0] >= '0' && e[0] <= '9')
                return false;

        for (i = 0; i < n; i++)
                if (!strchr(LETTERS DIGITS "_", e[i]))
                        return false;

        return true;
}

/* Parses the value of an assignment, from the character after the "=" up to the end of the line (or
 * of a quoted string that continues on the following lines). Returns a pointer to the character
 * after the value. */
static const char *parse_value(const char *p, char **ret) {
        _cleanup_free_ char *v = NULL;
        size_t n = 0, last_nonspace = 0;

        v = malloc(strlen(p) + 1);
        if (!v)
                return NULL;

        /* Leading whitespace is dropped */
        while (IN_SET(*p, ' ', '\t'))
                p++;

        while (*p && *p != '\n') {
                if (*p == '\'') {
                        /* Single quotes: everything up to the next single quote is taken literally */
                        for (p++; *p && *p != '\''; p++)
                                v[n++] = *p;
                        if (*p)
                                p++;
                        last_nonspace = n;
                } else if (*p == '"') {
                        /* Double quotes: backslash escapes only the shell special characters */
                        for (p++; *p && *p != '"'; p++) {
                                if (*p == '\\' && p[1]) {
                                        p++;
                                        if (*p == '\n')
                                                continue;
                                        if (!strchr(SHELL_NEED_ESCAPE, *p))
                                                v[n++] = '\\';
                                }
                                v[n++] = *p;
                        }
                        if (*p)
                                p++;
                        last_nonspace = n;
                } else if (*p == '\\') {
                        /* Unquoted backslash escapes any character; backslash-newline continues the line */
                        p++;
                        if (*p == 0)
                                break;
                        if (*p != '\n') {
                                v[n++] = *p;
                                last_nonspace = n;
                        }
                        p++;
                } else {
                        v[n++] = *p;
                        if (!IN_SET(*p, ' ', '\t'))
                                last_nonspace = n;
                        p++;
                }
        }

        /* Trailing unquoted whitespace is dropped */
        v[last_nonspace] = 0;

        *ret = v;
        v = NULL;
        return p;
}

int parse_env_text(const char *text, const char *const keys[], char *ret_values[], size_t n) {
        _cleanup_free_ char **values = NULL;
        const char *p = text;
        size_t i;
        int r = 0;

        assert(text);
        assert(keys || n == 0);
        assert(ret_values || n == 0);

        values = new0(char*, n);
        if (!values)
                return -ENOMEM;

        while (*p) {
                const char *key, *eq;
                size_t l;
                char *v;

                /* Skip whitespace, empty lines and comments */
                p += strspn(p, WHITESPACE);
                if (*p == 0)
                        break;
                if (IN_SET(*p, '#', ';')) {
                        p += strcspn(p, "\n");
                        continue;
                }

                key = p;
                eq = p + strcspn(p, "=\n");
                if (*eq != '=') {
                        /* Not an assignment, ignore */
                        p = eq;
                        continue;
                }

                l = eq - key;
                while (l > 0 && IN_SET(key[l-1], ' ', '\t'))
                        l--;

                p = parse_value(eq + 1, &v);
                if (!p) {
                        r = -ENOMEM;
                        goto finish;
                }

                if (!env_name_is_valid_n(key, l)) {
                        free(v);
                        continue;
                }

                for (i = 0; i < n; i++)
                        if (strlen(keys[i]) == l && strneq(key, keys[i], l))
                                break;
                if (i >= n) {
                        free(v);
                        continue;
                }

                /* The last assignment wins */
                free(values[i]);
                values[i] = v;
        }

        for (i = 0; i < n; i++) {
                ret_values[i] = values[i];
                values[i] = NULL;
        }

finish:
        for (i = 0; i < n; i++)
                free(values[i]);

        return r;
}

int parse_os_release(const char *const keys[], char *ret_values[], size_t n) {
        _cleanup_free_ char *text = NULL;
        const char *e;
        int r;

        e = secure_getenv("SYSTEMD_OS_RELEASE");
        if (e)
                r = read_full_file(e, &text, NULL);
        else {
                r = read_full_file("/etc/os-release", &text, NULL);
                if (r == -ENOENT)
                        r = read_full_file("/usr/lib/os-release", &text, NULL);
        }
        if (r < 0)
                return r;

        return parse_env_text(text, keys, ret_values, n);
}
