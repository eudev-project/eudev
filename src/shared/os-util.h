/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>

/* Reads the values of the given fields from os-release: $SYSTEMD_OS_RELEASE if set, otherwise
 * /etc/os-release, or /usr/lib/os-release if the former does not exist. Fields that are not set are
 * returned as NULL; the caller frees the values. Returns -ENOENT if there is no os-release file. */
int parse_os_release(const char *const keys[], char *ret_values[], size_t n);

/* Parses the text of an environment-like file (as os-release), with shell-like quoting. */
int parse_env_text(const char *text, const char *const keys[], char *ret_values[], size_t n);
