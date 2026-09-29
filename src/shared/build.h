/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdio.h>

#include "config.h"

/* Like systemd's version(), but eudev prints just the version of udev it corresponds to, like
 * 'udevadm --version' does it, e.g. "262". UDEV_VERSION is defined by the Makefile.am of each
 * helper. */
static inline int version(void) {
        printf("%s\n", UDEV_VERSION);
        return 0;
}
