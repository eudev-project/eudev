/***
  This file is part of eudev, forked from systemd.

  Copyright 2010-2012 Lennart Poettering

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

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "util.h"
#include "path-util.h"

bool paths_check_timestamp(char **paths, usec_t *paths_ts_usec, bool update)
{
        unsigned int i;
        bool changed = false;

        if (paths == NULL)
                goto out;

        for (i = 0; paths[i]; i++) {
                struct stat stats;

                if (stat(paths[i], &stats) < 0)
                        continue;

                if (paths_ts_usec[i] == timespec_load(&stats.st_mtim))
                        continue;

                /* first check */
                if (paths_ts_usec[i] != 0) {
                        log_debug("reload - timestamp of '%s' changed\n", paths[i]);
                        changed = true;
                }

                /* update timestamp */
                if (update)
                        paths_ts_usec[i] = timespec_load(&stats.st_mtim);
        }
out:
        return changed;
}
