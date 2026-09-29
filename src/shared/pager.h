/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

typedef enum PagerFlags {
        PAGER_DISABLE     = 1 << 0,
        PAGER_JUMP_TO_END = 1 << 1,
} PagerFlags;

/* Like systemd's pager_open(): pipes standard output and standard error into a pager, if both are
 * a terminal, $TERM is set and not "dumb", and the pager is not disabled with PAGER_DISABLE,
 * $SYSTEMD_PAGER or $PAGER. The pager is closed with pager_close(), which is also called at exit. */
void pager_open(PagerFlags flags);
void pager_close(void);
bool pager_have(void);
