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

#pragma once

/* A small streaming JSON writer. Values are written to a FILE as they are added, in the formats
 * of systemd's sd_json_variant_dump(), so that 'udevadm ... --json=' prints the same as systemd.
 *
 *     JsonWriter w;
 *
 *     json_writer_init(&w, stdout, JSON_FORMAT_PRETTY);
 *     json_writer_object_begin(&w);
 *     json_writer_field_string(&w, "name", "sda");
 *     json_writer_key(&w, "tags");
 *     json_writer_array_begin(&w);
 *     json_writer_string(&w, "systemd");
 *     json_writer_array_end(&w);
 *     json_writer_object_end(&w);
 *     r = json_writer_finish(&w);
 *
 * With JSON_FORMAT_COLOR, the strings, numbers, booleans and null are colored like sd-json does it:
 * strings in green, numbers in bright blue, booleans and null in bold. JSON_FORMAT_COLOR_AUTO turns
 * the colors on when colors_enabled() says so.
 *
 * Strings are escaped as JSON requires. Any Unicode scalar value is written as is, including
 * noncharacters like U+FFFE, as sd-json's formatter does. Bytes that are not valid UTF-8 are
 * written as U+FFFD, the replacement character, so the output is always valid JSON. A misuse, like
 * a value without a key inside an object, or unbalanced ends, is not written, and
 * json_writer_finish() returns -EINVAL. */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef enum JsonFormatFlags {
        JSON_FORMAT_OFF     = 1 << 0,   /* JSON output is disabled */
        JSON_FORMAT_NEWLINE = 1 << 1,   /* terminate the output with a newline */
        JSON_FORMAT_PRETTY  = 1 << 2,   /* one member or element per line, indented with tabs, terminated
                                         * with a newline */
        JSON_FORMAT_SEQ     = 1 << 3,   /* RFC 7464 application/json-seq: prefix with the record separator,
                                         * terminate with a newline */
        JSON_FORMAT_COLOR      = 1 << 4, /* insert ANSI color sequences */
        JSON_FORMAT_COLOR_AUTO = 1 << 5, /* insert ANSI color sequences if colors_enabled() says so */
} JsonFormatFlags;

static inline bool json_format_enabled(JsonFormatFlags flags) {
        return !(flags & JSON_FORMAT_OFF);
}

/* Parses the argument of a --json= option like systemd's parse_json_argument(): "pretty", which
 * is colored on a terminal, "short" or "off". For "help", lists them on stdout and returns 0.
 * Returns 1 when parsed, and -EINVAL for anything else. */
int json_parse_format(const char *s, JsonFormatFlags *ret);

#define JSON_WRITER_DEPTH_MAX 32

typedef struct JsonWriter {
        FILE *f;
        JsonFormatFlags flags;
        int error;                      /* the first error, reported by json_writer_finish() */
        bool started;                   /* the top level value has been started */
        bool done;                      /* the top level value is complete */
        bool after_key;                 /* a key has been written, its value comes next */
        unsigned depth;                 /* number of open objects and arrays */
        struct {
                bool object;            /* object or array */
                bool empty;             /* no member or element yet */
        } stack[JSON_WRITER_DEPTH_MAX];
} JsonWriter;

void json_writer_init(JsonWriter *w, FILE *f, JsonFormatFlags flags);

/* Terminates the output as the flags say. Returns 0, or the first error: -EINVAL on misuse or when
 * the value is incomplete, -EIO when writing failed. Writing nothing at all is fine. */
int json_writer_finish(JsonWriter *w);

void json_writer_object_begin(JsonWriter *w);
void json_writer_object_end(JsonWriter *w);
void json_writer_array_begin(JsonWriter *w);
void json_writer_array_end(JsonWriter *w);

/* The key of the next member of the current object. */
void json_writer_key(JsonWriter *w, const char *key);

/* A NULL string is written as null. */
void json_writer_string(JsonWriter *w, const char *s);
void json_writer_integer(JsonWriter *w, int64_t i);
void json_writer_unsigned(JsonWriter *w, uint64_t u);
void json_writer_boolean(JsonWriter *w, bool b);
void json_writer_null(JsonWriter *w);

/* A member of the current object. */
void json_writer_field_string(JsonWriter *w, const char *key, const char *s);
void json_writer_field_integer(JsonWriter *w, const char *key, int64_t i);
void json_writer_field_unsigned(JsonWriter *w, const char *key, uint64_t u);
void json_writer_field_boolean(JsonWriter *w, const char *key, bool b);
