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

#define ID128_MAKE(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15) \
        ((const id128_t) { .bytes = {                                   \
                        0x##v0, 0x##v1, 0x##v2, 0x##v3, 0x##v4, 0x##v5, 0x##v6, 0x##v7, \
                        0x##v8, 0x##v9, 0x##v10, 0x##v11, 0x##v12, 0x##v13, 0x##v14, 0x##v15 }})

/* "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" plus the terminating NUL */
#define ID128_UUID_STRING_MAX 37

/* Accepts both the plain form (32 hexadecimal digits) and the UUID form. */
int id128_from_string(const char *s, id128_t *ret);
char *id128_to_uuid_string(id128_t id, char s[static ID128_UUID_STRING_MAX]);
void id128_randomize(id128_t *ret);

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
