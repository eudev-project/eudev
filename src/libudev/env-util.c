/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

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

#include <assert.h>
#include <string.h>
#include <util.h>
#include <unistd.h>

#include "strv.h"

char *strv_env_get_n(char **l, const char *name, size_t k) {
        char **i;

        assert(name);

        if (k <= 0)
                return NULL;

        STRV_FOREACH(i, l)
                if (strneq(*i, name, k) &&
                    (*i)[k] == '=')
                        return *i + k + 1;

        return NULL;
}

char *strv_env_get(char **l, const char *name) {
        assert(name);

        return strv_env_get_n(l, name, strlen(name));
}
