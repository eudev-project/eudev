/***
  This file is part of eudev, forked from systemd

  Copyright 2012 Lennart Poettering

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

#include <stdbool.h>

#include "macro.h"

bool unichar_is_valid(uint32_t c);

char *utf8_is_valid(const char *s) _pure_;
char *ascii_is_valid(const char *s) _pure_;

bool utf8_is_printable_newline(const char* str, size_t length, bool newline) _pure_;
_pure_ static inline bool utf8_is_printable(const char* str, size_t length) {
        return utf8_is_printable_newline(str, length, true);
}

/* Like utf8_escape_non_printable() of systemd: escapes a string for a log message, where it is shown in one
 * line, as it is: the control characters, also tab and newline, DEL and the C1 control characters, are written
 * as \xNN, and everything else, valid UTF-8, also a backslash, is kept, so that e.g. an "a" with umlaut stays
 * readable and a value of the rules is shown as written. Unlike in systemd, where they become U+FFFD, also the
 * bytes of invalid UTF-8 are written as \xNN, so that they can be told apart. With escape_quote, a '"' is
 * written as \", as in the values of the rules. Returns a new string, or NULL when out of memory. */
char *utf8_escape_non_printable_full(const char *str, bool escape_quote);
static inline char *utf8_escape_non_printable(const char *str) {
        return utf8_escape_non_printable_full(str, false);
}

/* Whether utf8_escape_non_printable() changes str, i.e. it has control characters or invalid UTF-8. */
bool utf8_needs_escape(const char *str) _pure_;

/* For the messages: str escaped like utf8_escape_non_printable(). Returns str itself when there is nothing to
 * escape, which needs no memory, the usual case; otherwise the escaped copy, which is also stored in *buf, for
 * the caller to free (*buf must be NULL or freeable, it is freed first). Returns str too without memory, and
 * NULL for NULL. */
const char *utf8_escape_for_log(const char *str, char **buf);

size_t utf8_encode_unichar(char *out_utf8, uint32_t g);
char *utf16_to_utf8(const void *s, size_t length);

int utf8_encoded_valid_unichar(const char *str);
int utf8_encoded_to_unichar(const char *str);

static inline bool utf16_is_surrogate(uint16_t c) {
        return (0xd800 <= c && c <= 0xdfff);
}

static inline bool utf16_is_trailing_surrogate(uint16_t c) {
        return (0xdc00 <= c && c <= 0xdfff);
}

static inline uint32_t utf16_surrogate_pair_to_unichar(uint16_t lead, uint16_t trail) {
                return ((lead - 0xd800) << 10) + (trail - 0xdc00) + 0x10000;
}
