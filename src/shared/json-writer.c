/***
  This file is part of eudev.

  eudev is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  eudev is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with eudev; If not, see <http://www.gnu.org/licenses/>.
***/

#include <errno.h>
#include <inttypes.h>
#include <string.h>

#include "json-writer.h"
#include "terminal-util.h"
#include "util.h"

int json_parse_format(const char *s, JsonFormatFlags *ret) {
        assert(s);
        assert(ret);

        if (streq(s, "pretty"))
                *ret = JSON_FORMAT_PRETTY|JSON_FORMAT_COLOR_AUTO;
        else if (streq(s, "short"))
                *ret = JSON_FORMAT_NEWLINE;
        else if (streq(s, "off"))
                *ret = JSON_FORMAT_OFF;
        else if (streq(s, "help")) {
                puts("pretty\n"
                     "short\n"
                     "off");
                return 0;
        } else
                return -EINVAL;

        return 1;
}

void json_writer_init(JsonWriter *w, FILE *f, JsonFormatFlags flags) {
        assert(w);

        memzero(w, sizeof(*w));
        w->f = f ?: stdout;
        w->flags = flags;

        if ((flags & (JSON_FORMAT_COLOR_AUTO|JSON_FORMAT_COLOR)) == JSON_FORMAT_COLOR_AUTO && colors_enabled())
                w->flags |= JSON_FORMAT_COLOR;
}

/* The sequences of systemd's ansi-color.h that sd-json colors with. */
#define JSON_ANSI_GREEN          "\x1B[0;32m"
#define JSON_ANSI_HIGHLIGHT_BLUE "\x1B[0;1;34m"
#define JSON_ANSI_HIGHLIGHT      "\x1B[0;1;39m"
#define JSON_ANSI_NORMAL         "\x1B[0m"

static void json_writer_color(JsonWriter *w, const char *seq) {
        if (w->flags & JSON_FORMAT_COLOR)
                fputs(seq, w->f);
}

static void json_writer_fail(JsonWriter *w, int error) {
        if (w->error == 0)
                w->error = error;
}

static void json_writer_indent(JsonWriter *w) {
        unsigned i;

        for (i = 0; i < w->depth; i++)
                fputc('\t', w->f);
}

/* Checks that a key (or a value) may come now, and writes the separator and indentation before it.
 * Returns false and records the error otherwise. Nothing is written after an error. */
static bool json_writer_begin_item(JsonWriter *w, bool key) {
        if (w->error != 0)
                return false;

        if (w->depth == 0) {
                /* only a single top level value, and no key */
                if (key || w->done) {
                        json_writer_fail(w, -EINVAL);
                        return false;
                }
                if (!w->started) {
                        if (w->flags & JSON_FORMAT_SEQ)
                                fputc('\x1e', w->f);    /* ASCII record separator */
                        w->started = true;
                }
                return true;
        }

        if (w->stack[w->depth-1].object) {
                if (key == w->after_key) {
                        /* a key after a key, or a value without a key */
                        json_writer_fail(w, -EINVAL);
                        return false;
                }
                if (!key) {
                        /* the separator was written after the key */
                        w->after_key = false;
                        return true;
                }
        } else if (key) {
                json_writer_fail(w, -EINVAL);
                return false;
        }

        if (!w->stack[w->depth-1].empty)
                fputc(',', w->f);
        if (w->flags & JSON_FORMAT_PRETTY) {
                fputc('\n', w->f);
                json_writer_indent(w);
        }
        w->stack[w->depth-1].empty = false;
        return true;
}

static void json_writer_end_item(JsonWriter *w) {
        if (w->depth == 0)
                w->done = true;
}

static void json_writer_container_begin(JsonWriter *w, bool object) {
        if (!json_writer_begin_item(w, false))
                return;

        if (w->depth >= JSON_WRITER_DEPTH_MAX) {
                json_writer_fail(w, -EINVAL);
                return;
        }

        fputc(object ? '{' : '[', w->f);
        w->stack[w->depth].object = object;
        w->stack[w->depth].empty = true;
        w->depth++;
}

static void json_writer_container_end(JsonWriter *w, bool object) {
        bool empty;

        if (w->error != 0)
                return;

        if (w->depth == 0 || w->stack[w->depth-1].object != object || w->after_key) {
                json_writer_fail(w, -EINVAL);
                return;
        }

        empty = w->stack[w->depth-1].empty;
        w->depth--;
        if (!empty && (w->flags & JSON_FORMAT_PRETTY)) {
                fputc('\n', w->f);
                json_writer_indent(w);
        }
        fputc(object ? '}' : ']', w->f);
        json_writer_end_item(w);
}

void json_writer_object_begin(JsonWriter *w) {
        json_writer_container_begin(w, true);
}

void json_writer_object_end(JsonWriter *w) {
        json_writer_container_end(w, true);
}

void json_writer_array_begin(JsonWriter *w) {
        json_writer_container_begin(w, false);
}

void json_writer_array_end(JsonWriter *w) {
        json_writer_container_end(w, false);
}

/* Returns the length of the UTF-8 sequence at str if it is the shortest form of a Unicode scalar
 * value, i.e. of any code point up to U+10FFFF except the UTF-16 surrogates, and -1 otherwise.
 * Unlike utf8_encoded_valid_unichar(), noncharacters like U+FFFE or U+FDD0 are accepted: they are
 * valid in JSON strings. */
static int utf8_scalar_len(const char *str) {
        const unsigned char *s = (const unsigned char *) str;
        uint32_t c;
        int len, i;

        if (s[0] < 0x80)
                return 1;
        if ((s[0] & 0xe0) == 0xc0) {
                len = 2;
                c = s[0] & 0x1f;
        } else if ((s[0] & 0xf0) == 0xe0) {
                len = 3;
                c = s[0] & 0x0f;
        } else if ((s[0] & 0xf8) == 0xf0) {
                len = 4;
                c = s[0] & 0x07;
        } else
                return -1;

        /* a NUL fails this check too */
        for (i = 1; i < len; i++) {
                if ((s[i] & 0xc0) != 0x80)
                        return -1;
                c = (c << 6) | (s[i] & 0x3f);
        }

        /* overlong forms */
        if ((len == 2 && c < 0x80) || (len == 3 && c < 0x800) || (len == 4 && c < 0x10000))
                return -1;

        if ((c >= 0xd800 && c <= 0xdfff) || c > 0x10ffff)
                return -1;

        return len;
}

static void json_write_string(JsonWriter *w, const char *s) {
        FILE *f = w->f;

        fputc('"', f);
        json_writer_color(w, JSON_ANSI_GREEN);

        while (*s != '\0') {
                unsigned char c = *s;

                if (c >= 0x80) {
                        int len;

                        len = utf8_scalar_len(s);
                        if (len < 0) {
                                /* not valid UTF-8, JSON cannot carry it */
                                fputs("\\ufffd", f);
                                s++;
                        } else {
                                fwrite(s, 1, len, f);
                                s += len;
                        }
                        continue;
                }

                switch (c) {
                case '"':
                        fputs("\\\"", f);
                        break;
                case '\\':
                        fputs("\\\\", f);
                        break;
                case '\b':
                        fputs("\\b", f);
                        break;
                case '\f':
                        fputs("\\f", f);
                        break;
                case '\n':
                        fputs("\\n", f);
                        break;
                case '\r':
                        fputs("\\r", f);
                        break;
                case '\t':
                        fputs("\\t", f);
                        break;
                default:
                        if (c < ' ')
                                fprintf(f, "\\u%04x", (unsigned) c);
                        else
                                fputc(c, f);
                }
                s++;
        }

        json_writer_color(w, JSON_ANSI_NORMAL);
        fputc('"', f);
}

void json_writer_key(JsonWriter *w, const char *key) {
        if (!key) {
                json_writer_fail(w, -EINVAL);
                return;
        }

        if (!json_writer_begin_item(w, true))
                return;

        json_write_string(w, key);
        fputs(w->flags & JSON_FORMAT_PRETTY ? " : " : ":", w->f);
        w->after_key = true;
}

void json_writer_string(JsonWriter *w, const char *s) {
        if (!s) {
                json_writer_null(w);
                return;
        }

        if (!json_writer_begin_item(w, false))
                return;

        json_write_string(w, s);
        json_writer_end_item(w);
}

void json_writer_integer(JsonWriter *w, int64_t i) {
        if (!json_writer_begin_item(w, false))
                return;

        json_writer_color(w, JSON_ANSI_HIGHLIGHT_BLUE);
        fprintf(w->f, "%" PRId64, i);
        json_writer_color(w, JSON_ANSI_NORMAL);
        json_writer_end_item(w);
}

void json_writer_unsigned(JsonWriter *w, uint64_t u) {
        if (!json_writer_begin_item(w, false))
                return;

        json_writer_color(w, JSON_ANSI_HIGHLIGHT_BLUE);
        fprintf(w->f, "%" PRIu64, u);
        json_writer_color(w, JSON_ANSI_NORMAL);
        json_writer_end_item(w);
}

void json_writer_boolean(JsonWriter *w, bool b) {
        if (!json_writer_begin_item(w, false))
                return;

        json_writer_color(w, JSON_ANSI_HIGHLIGHT);
        fputs(b ? "true" : "false", w->f);
        json_writer_color(w, JSON_ANSI_NORMAL);
        json_writer_end_item(w);
}

void json_writer_null(JsonWriter *w) {
        if (!json_writer_begin_item(w, false))
                return;

        json_writer_color(w, JSON_ANSI_HIGHLIGHT);
        fputs("null", w->f);
        json_writer_color(w, JSON_ANSI_NORMAL);
        json_writer_end_item(w);
}

void json_writer_field_string(JsonWriter *w, const char *key, const char *s) {
        json_writer_key(w, key);
        json_writer_string(w, s);
}

void json_writer_field_integer(JsonWriter *w, const char *key, int64_t i) {
        json_writer_key(w, key);
        json_writer_integer(w, i);
}

void json_writer_field_unsigned(JsonWriter *w, const char *key, uint64_t u) {
        json_writer_key(w, key);
        json_writer_unsigned(w, u);
}

void json_writer_field_boolean(JsonWriter *w, const char *key, bool b) {
        json_writer_key(w, key);
        json_writer_boolean(w, b);
}

int json_writer_finish(JsonWriter *w) {
        if (w->error != 0)
                return w->error;

        if (!w->started)
                return 0;

        if (!w->done)
                return -EINVAL;

        if (w->flags & (JSON_FORMAT_PRETTY|JSON_FORMAT_NEWLINE|JSON_FORMAT_SEQ))
                fputc('\n', w->f);

        if (ferror(w->f))
                return -EIO;

        return 0;
}
