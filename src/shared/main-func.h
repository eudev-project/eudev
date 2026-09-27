/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdlib.h>

/* A minimal version of systemd's DEFINE_MAIN_FUNCTION(): call impl() and turn a negative return value
 * into EXIT_FAILURE and everything else into EXIT_SUCCESS. */
#define DEFINE_MAIN_FUNCTION(impl)                                      \
        int main(int argc, char *argv[]) {                              \
                return impl(argc, argv) < 0 ? EXIT_FAILURE : EXIT_SUCCESS; \
        }
