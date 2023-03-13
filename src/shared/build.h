/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdio.h>

#include "config.h"

/* Like systemd's version(), but eudev prints just its package version, as scsi_id --version and
 * dmi_memory_id --version always did. */
static inline int version(void) {
        printf("%s\n", VERSION);
        return 0;
}
