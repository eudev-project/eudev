/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "json-util.h"
#include "utf8.h"
#include "util.h"

/* Nesting depth limit for the values that are skipped */
#define JSON_DEPTH_MAX 64

static void skip_space(const char **p) {
        while (IN_SET(**p, ' ', '\t', '\n', '\r'))
                (*p)++;
}

static int unhex4(const char *c, uint16_t *ret) {
        uint16_t x = 0;
        unsigned i;

        for (i = 0; i < 4; i++) {
                int v = unhexchar(c[i]);

                if (v < 0)
                        return -EBADMSG;

                x = (x << 4) | v;
        }

        *ret = x;
        return 0;
}

/* Parses a string starting at *p (which must point to the opening quote). If ret is NULL the string
 * is only validated. */
static int parse_string(const char **p, char **ret) {
        _cleanup_free_ char *s = NULL;
        size_t n = 0;
        const char *c = *p;

        if (*c != '"')
                return -EBADMSG;
        c++;

        if (ret) {
                /* The decoded string is never longer than the encoded one. */
                s = malloc(strlen(c) + 1);
                if (!s)
                        return -ENOMEM;
        }

        for (;;) {
                int len;

                if (*c == 0)
                        return -EBADMSG;

                /* Control characters must be escaped */
                if ((*c > 0 && *c < ' ') || *c == 0x7f)
                        return -EBADMSG;

                if (*c == '"') {
                        *p = c + 1;
                        if (ret) {
                                s[n] = 0;
                                *ret = s;
                                s = NULL;
                        }
                        return 0;
                }

                if (*c == '\\') {
                        char ch;

                        c++;
                        switch (*c) {
                        case '"':
                        case '\\':
                        case '/':
                                ch = *c;
                                break;
                        case 'b':
                                ch = '\b';
                                break;
                        case 'f':
                                ch = '\f';
                                break;
                        case 'n':
                                ch = '\n';
                                break;
                        case 'r':
                                ch = '\r';
                                break;
                        case 't':
                                ch = '\t';
                                break;
                        case 'u': {
                                uint16_t x, y;
                                uint32_t u;
                                int r;

                                r = unhex4(c + 1, &x);
                                if (r < 0)
                                        return r;
                                c += 5;

                                if (!utf16_is_surrogate(x))
                                        u = x;
                                else if (utf16_is_trailing_surrogate(x))
                                        return -EBADMSG;
                                else {
                                        if (c[0] != '\\' || c[1] != 'u')
                                                return -EBADMSG;

                                        r = unhex4(c + 2, &y);
                                        if (r < 0)
                                                return r;
                                        c += 6;

                                        if (!utf16_is_trailing_surrogate(y))
                                                return -EBADMSG;

                                        u = utf16_surrogate_pair_to_unichar(x, y);
                                }

                                /* Embedded NUL bytes cannot be represented in a C string, refuse them. */
                                if (u == 0)
                                        return -EBADMSG;

                                /* "\uXXXX" takes 6 bytes, and is encoded in at most 3; a surrogate pair
                                 * takes 12, and is encoded in 4. */
                                if (s)
                                        n += utf8_encode_unichar(s + n, u);
                                continue;
                        }
                        default:
                                return -EBADMSG;
                        }

                        if (s)
                                s[n++] = ch;
                        c++;
                        continue;
                }

                len = utf8_encoded_valid_unichar(c);
                if (len < 0)
                        return -EBADMSG;

                if (s)
                        memcpy(s + n, c, len);
                n += len;
                c += len;
        }
}

static int skip_number(const char **p) {
        const char *c = *p;

        if (*c == '-')
                c++;

        if (*c == '0')
                c++;
        else if (*c >= '1' && *c <= '9')
                while (*c >= '0' && *c <= '9')
                        c++;
        else
                return -EBADMSG;

        if (*c == '.') {
                c++;
                if (!(*c >= '0' && *c <= '9'))
                        return -EBADMSG;
                while (*c >= '0' && *c <= '9')
                        c++;
        }

        if (IN_SET(*c, 'e', 'E')) {
                c++;
                if (IN_SET(*c, '+', '-'))
                        c++;
                if (!(*c >= '0' && *c <= '9'))
                        return -EBADMSG;
                while (*c >= '0' && *c <= '9')
                        c++;
        }

        *p = c;
        return 0;
}

static int skip_value(const char **p, unsigned depth) {
        int r;

        if (depth > JSON_DEPTH_MAX)
                return -EBADMSG;

        skip_space(p);

        switch (**p) {
        case '"':
                return parse_string(p, NULL);

        case '{':
        case '[': {
                char close = **p == '{' ? '}' : ']';
                bool object = **p == '{';

                (*p)++;
                skip_space(p);
                if (**p == close) {
                        (*p)++;
                        return 0;
                }

                for (;;) {
                        if (object) {
                                skip_space(p);
                                r = parse_string(p, NULL);
                                if (r < 0)
                                        return r;
                                skip_space(p);
                                if (**p != ':')
                                        return -EBADMSG;
                                (*p)++;
                        }

                        r = skip_value(p, depth + 1);
                        if (r < 0)
                                return r;

                        skip_space(p);
                        if (**p == close) {
                                (*p)++;
                                return 0;
                        }
                        if (**p != ',')
                                return -EBADMSG;
                        (*p)++;
                }
        }

        case 't':
                if (!startswith(*p, "true"))
                        return -EBADMSG;
                *p += 4;
                return 0;

        case 'f':
                if (!startswith(*p, "false"))
                        return -EBADMSG;
                *p += 5;
                return 0;

        case 'n':
                if (!startswith(*p, "null"))
                        return -EBADMSG;
                *p += 4;
                return 0;

        default:
                return skip_number(p);
        }
}

int json_object_get_strings(const char *text, const char *const keys[], char *ret_values[], size_t n) {
        _cleanup_free_ char **values = NULL;
        const char *p = text;
        int r = 0, error = 0;
        size_t i;

        assert(text);
        assert(keys || n == 0);
        assert(ret_values || n == 0);

        values = new0(char*, n);
        if (!values)
                return -ENOMEM;

        skip_space(&p);
        if (*p != '{') {
                r = -EBADMSG;
                goto finish;
        }
        p++;

        skip_space(&p);
        if (*p == '}')
                p++;
        else
                for (;;) {
                        _cleanup_free_ char *key = NULL;
                        bool found = false;

                        skip_space(&p);
                        r = parse_string(&p, &key);
                        if (r < 0)
                                goto finish;

                        skip_space(&p);
                        if (*p != ':') {
                                r = -EBADMSG;
                                goto finish;
                        }
                        p++;
                        skip_space(&p);

                        for (i = 0; i < n; i++) {
                                if (!streq(key, keys[i]))
                                        continue;

                                found = true;

                                /* Wrong types and duplicates are only reported once the whole text
                                 * turned out to be valid JSON, so that syntax errors take precedence. */
                                if (*p != '"') {
                                        if (error == 0)
                                                error = -EINVAL;
                                        r = skip_value(&p, 1);
                                } else if (values[i]) {
                                        if (error == 0)
                                                error = -ENOTUNIQ;
                                        r = parse_string(&p, NULL);
                                } else
                                        r = parse_string(&p, &values[i]);
                                if (r < 0)
                                        goto finish;
                                break;
                        }

                        if (!found) {
                                r = skip_value(&p, 1);
                                if (r < 0)
                                        goto finish;
                        }

                        skip_space(&p);
                        if (*p == '}') {
                                p++;
                                break;
                        }
                        if (*p != ',') {
                                r = -EBADMSG;
                                goto finish;
                        }
                        p++;
                }

        skip_space(&p);
        if (*p != 0) {
                r = -EBADMSG;
                goto finish;
        }

        if (error < 0) {
                r = error;
                goto finish;
        }

        for (i = 0; i < n; i++) {
                ret_values[i] = values[i];
                values[i] = NULL;
        }
        r = 0;

finish:
        for (i = 0; i < n; i++)
                free(values[i]);

        return r;
}
