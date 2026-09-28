/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>

/* A minimal JSON reader, for the few places where udev has to look at small JSON documents written by
 * other tools. It is not a general purpose parser: it only extracts string members from an object.
 *
 * The text must consist of exactly one JSON object. The values of the members named in keys[] are
 * returned in the matching element of ret_values[] (NULL if the member does not exist; the caller
 * frees them); all other members are validated and skipped.
 *
 * Returns 0 on success, -EBADMSG if the text is not valid JSON or not an object, -EINVAL if one of
 * the requested members is not a string (including null), -ENOTUNIQ if one of them appears more
 * than once, and -ENOMEM. On failure ret_values[] is left untouched. */
int json_object_get_strings(const char *text, const char *const keys[], char *ret_values[], size_t n);
