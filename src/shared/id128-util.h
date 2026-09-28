/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdint.h>

/* 128-bit IDs (UUIDs), after sd_id128_t of systemd. */
typedef union id128 {
        uint8_t bytes[16];
        uint64_t qwords[2];
} id128_t;

#define ID128_NULL ((const id128_t) {})

/* "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" plus the terminating NUL */
#define ID128_UUID_STRING_MAX 37

/* Accepts both the plain form (32 hexadecimal digits) and the UUID form. */
int id128_from_string(const char *s, id128_t *ret);
char *id128_to_uuid_string(id128_t id, char s[static ID128_UUID_STRING_MAX]);

static inline bool id128_equal(id128_t a, id128_t b) {
        return a.qwords[0] == b.qwords[0] && a.qwords[1] == b.qwords[1];
}

static inline bool id128_is_null(id128_t a) {
        return a.qwords[0] == 0 && a.qwords[1] == 0;
}

bool id128_in_set_internal(id128_t id, const id128_t *set, unsigned n);
#define id128_in_set(id, ...)                                                   \
        ({                                                                      \
                const id128_t _set_[] = { __VA_ARGS__ };                        \
                id128_in_set_internal((id), _set_, sizeof(_set_) / sizeof(_set_[0])); \
        })

/* The boot ID of the running kernel, from /proc/sys/kernel/random/boot_id */
int id128_get_boot(id128_t *ret);
