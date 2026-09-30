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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json-writer.h"

static int failures;

/* the colors of sd-json: strings, numbers, booleans and null, and the end of a color */
#define G "\x1B[0;32m"
#define B "\x1B[0;1;34m"
#define H "\x1B[0;1;39m"
#define N "\x1B[0m"

typedef void (*writer_func)(JsonWriter *w);

static void check(const char *name, writer_func func, JsonFormatFlags flags, int exp_r, const char *exp) {
        JsonWriter w;
        char *buf = NULL;
        size_t size = 0;
        FILE *f;
        int r;

        f = open_memstream(&buf, &size);
        if (!f) {
                perror("open_memstream");
                exit(EXIT_FAILURE);
        }

        json_writer_init(&w, f, flags);
        func(&w);
        r = json_writer_finish(&w);
        fclose(f);

        if (r != exp_r || (exp && strcmp(buf, exp) != 0)) {
                printf("FAIL %s: r=%i (expected %i)\n--- got:\n%s\n--- expected:\n%s\n", name, r, exp_r, buf, exp ?: "(any)");
                failures++;
        } else
                printf("ok   %s\n", name);

        free(buf);
}

static void doc_nested(JsonWriter *w) {
        json_writer_object_begin(w);
        json_writer_field_string(w, "path", "/devices/virtual/net/lo");
        json_writer_field_unsigned(w, "number", 18446744073709551615ULL);
        json_writer_field_integer(w, "prio", -5);
        json_writer_field_boolean(w, "watch", false);
        json_writer_key(w, "none");
        json_writer_null(w);
        json_writer_key(w, "empty");
        json_writer_array_begin(w);
        json_writer_array_end(w);
        json_writer_key(w, "emptyobj");
        json_writer_object_begin(w);
        json_writer_object_end(w);
        json_writer_key(w, "tags");
        json_writer_array_begin(w);
        json_writer_string(w, "a");
        json_writer_object_begin(w);
        json_writer_field_string(w, "k", "v");
        json_writer_object_end(w);
        json_writer_array_end(w);
        json_writer_object_end(w);
}

static void doc_boolean(JsonWriter *w) {
        json_writer_object_begin(w);
        json_writer_field_boolean(w, "on", true);
        json_writer_object_end(w);
}

static void doc_escape(JsonWriter *w) {
        json_writer_array_begin(w);
        json_writer_string(w, "q\" b\\ \b\f\n\r\t \x01\x1f\x7f /");
        json_writer_string(w, "utf8 \xc3\xa4\xe2\x82\xac\xf0\x9f\x98\x80");
        /* noncharacters U+FFFE, U+FFFF, U+FDD0 and U+10FFFF are valid in JSON */
        json_writer_string(w, "nonchar \xef\xbf\xbe \xef\xbf\xbf \xef\xb7\x90 \xf4\x8f\xbf\xbf");
        /* U+110000 is beyond Unicode */
        json_writer_string(w, "beyond \xf4\x90\x80\x80 end");
        json_writer_string(w, "bad \xff \xc3 \xe2\x82 \xc0\x80 \xed\xa0\x80 end");
        json_writer_string(w, NULL);
        json_writer_array_end(w);
}

static void doc_scalar(JsonWriter *w) {
        json_writer_string(w, "x");
}

static void doc_nothing(JsonWriter *w) {
}

static void bad_value_without_key(JsonWriter *w) {
        json_writer_object_begin(w);
        json_writer_string(w, "x");
        json_writer_object_end(w);
}

static void bad_key_in_array(JsonWriter *w) {
        json_writer_array_begin(w);
        json_writer_key(w, "x");
        json_writer_array_end(w);
}

static void bad_two_keys(JsonWriter *w) {
        json_writer_object_begin(w);
        json_writer_key(w, "x");
        json_writer_key(w, "y");
}

static void bad_mismatch(JsonWriter *w) {
        json_writer_object_begin(w);
        json_writer_array_end(w);
}

static void bad_unterminated(JsonWriter *w) {
        json_writer_array_begin(w);
        json_writer_string(w, "x");
}

static void bad_key_without_value(JsonWriter *w) {
        json_writer_object_begin(w);
        json_writer_key(w, "x");
        json_writer_object_end(w);
}

static void bad_two_values(JsonWriter *w) {
        json_writer_string(w, "x");
        json_writer_string(w, "y");
}

static void bad_too_deep(JsonWriter *w) {
        unsigned i;

        for (i = 0; i <= JSON_WRITER_DEPTH_MAX; i++)
                json_writer_array_begin(w);
}

int main(void) {
        JsonFormatFlags flags;

        /* for JSON_FORMAT_COLOR_AUTO, also when the test runs on a terminal */
        if (setenv("SYSTEMD_COLORS", "0", 1) < 0) {
                perror("setenv");
                return EXIT_FAILURE;
        }

        check("nested short", doc_nested, JSON_FORMAT_NEWLINE, 0,
              "{\"path\":\"/devices/virtual/net/lo\",\"number\":18446744073709551615,\"prio\":-5,\"watch\":false,"
              "\"none\":null,\"empty\":[],\"emptyobj\":{},\"tags\":[\"a\",{\"k\":\"v\"}]}\n");
        check("nested off", doc_nested, 0, 0,
              "{\"path\":\"/devices/virtual/net/lo\",\"number\":18446744073709551615,\"prio\":-5,\"watch\":false,"
              "\"none\":null,\"empty\":[],\"emptyobj\":{},\"tags\":[\"a\",{\"k\":\"v\"}]}");
        check("nested pretty", doc_nested, JSON_FORMAT_PRETTY, 0,
              "{\n"
              "\t\"path\" : \"/devices/virtual/net/lo\",\n"
              "\t\"number\" : 18446744073709551615,\n"
              "\t\"prio\" : -5,\n"
              "\t\"watch\" : false,\n"
              "\t\"none\" : null,\n"
              "\t\"empty\" : [],\n"
              "\t\"emptyobj\" : {},\n"
              "\t\"tags\" : [\n"
              "\t\t\"a\",\n"
              "\t\t{\n"
              "\t\t\t\"k\" : \"v\"\n"
              "\t\t}\n"
              "\t]\n"
              "}\n");
        check("nested seq", doc_nested, JSON_FORMAT_SEQ, 0,
              "\x1e{\"path\":\"/devices/virtual/net/lo\",\"number\":18446744073709551615,\"prio\":-5,\"watch\":false,"
              "\"none\":null,\"empty\":[],\"emptyobj\":{},\"tags\":[\"a\",{\"k\":\"v\"}]}\n");
        check("escape", doc_escape, JSON_FORMAT_NEWLINE, 0,
              "[\"q\\\" b\\\\ \\b\\f\\n\\r\\t \\u0001\\u001f\x7f /\","
              "\"utf8 \xc3\xa4\xe2\x82\xac\xf0\x9f\x98\x80\","
              "\"nonchar \xef\xbf\xbe \xef\xbf\xbf \xef\xb7\x90 \xf4\x8f\xbf\xbf\","
              "\"beyond \\ufffd\\ufffd\\ufffd\\ufffd end\","
              "\"bad \\ufffd \\ufffd \\ufffd\\ufffd \\ufffd\\ufffd \\ufffd\\ufffd\\ufffd end\","
              "null]\n");
        /* the colors of sd-json */
        check("nested short color", doc_nested, JSON_FORMAT_NEWLINE|JSON_FORMAT_COLOR, 0,
              "{\"" G "path" N "\":\"" G "/devices/virtual/net/lo" N "\","
              "\"" G "number" N "\":" B "18446744073709551615" N ","
              "\"" G "prio" N "\":" B "-5" N ","
              "\"" G "watch" N "\":" H "false" N ","
              "\"" G "none" N "\":" H "null" N ","
              "\"" G "empty" N "\":[],"
              "\"" G "emptyobj" N "\":{},"
              "\"" G "tags" N "\":[\"" G "a" N "\",{\"" G "k" N "\":\"" G "v" N "\"}]}\n");
        check("boolean pretty color", doc_boolean, JSON_FORMAT_PRETTY|JSON_FORMAT_COLOR, 0,
              "{\n"
              "\t\"" G "on" N "\" : " H "true" N "\n"
              "}\n");
        /* $SYSTEMD_COLORS=0 is set, and turns off the colors */
        check("nested short color auto", doc_nested, JSON_FORMAT_NEWLINE|JSON_FORMAT_COLOR_AUTO, 0,
              "{\"path\":\"/devices/virtual/net/lo\",\"number\":18446744073709551615,\"prio\":-5,\"watch\":false,"
              "\"none\":null,\"empty\":[],\"emptyobj\":{},\"tags\":[\"a\",{\"k\":\"v\"}]}\n");
        check("scalar", doc_scalar, JSON_FORMAT_PRETTY, 0, "\"x\"\n");
        check("nothing", doc_nothing, JSON_FORMAT_PRETTY, 0, "");

        check("value without key", bad_value_without_key, 0, -EINVAL, NULL);
        check("key in array", bad_key_in_array, 0, -EINVAL, NULL);
        check("two keys", bad_two_keys, 0, -EINVAL, NULL);
        check("mismatched end", bad_mismatch, 0, -EINVAL, NULL);
        check("unterminated", bad_unterminated, 0, -EINVAL, NULL);
        check("key without value", bad_key_without_value, 0, -EINVAL, NULL);
        check("two values", bad_two_values, 0, -EINVAL, NULL);
        check("too deep", bad_too_deep, 0, -EINVAL, NULL);

        if (json_parse_format("pretty", &flags) != 1 || flags != (JSON_FORMAT_PRETTY|JSON_FORMAT_COLOR_AUTO) ||
            json_parse_format("short", &flags) != 1 || flags != JSON_FORMAT_NEWLINE ||
            json_parse_format("off", &flags) != 1 || json_format_enabled(flags) ||
            json_parse_format("foo", &flags) != -EINVAL) {
                printf("FAIL json_parse_format\n");
                failures++;
        } else
                printf("ok   json_parse_format\n");

        return failures > 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
