/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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
#include <sys/wait.h>

#include "exit-status.h"
#include "set.h"
#include "macro.h"

bool is_clean_exit(int code, int status, ExitStatusSet *success_status) {

        if (code == CLD_EXITED)
                return status == 0 ||
                       (success_status &&
                       set_contains(success_status->code, INT_TO_PTR(status)));

        /* If a daemon does not implement handlers for some of the
         * signals that's not considered an unclean shutdown */
        if (code == CLD_KILLED)
                return
                        status == SIGHUP ||
                        status == SIGINT ||
                        status == SIGTERM ||
                        status == SIGPIPE ||
                        (success_status &&
                        set_contains(success_status->signal, INT_TO_PTR(status)));

        return false;
}
