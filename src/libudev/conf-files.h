/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef fooconffileshfoo
#define fooconffileshfoo

/***
  This file is part of systemd.

  Copyright 2010-2012 Lennart Poettering
  Copyright 2010-2012 Kay Sievers

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

#include "macro.h"

int conf_files_list(char ***strv,
                    const char *prefix,
                    const char *suffix,
                    const char *dir, ...);
int conf_files_list_strv(char ***strv,
                         const char *prefix,
                         const char *suffix,
                         const char **dirs);

#endif
