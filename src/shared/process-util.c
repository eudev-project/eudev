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

#include <stdbool.h>
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <ctype.h>

#include "process-util.h"
#include "fileio.h"
#include "util.h"
#include "log.h"

int get_process_comm(pid_t pid, char **name) {
        const char *p;
        int r;

        assert(name);
        assert(pid >= 0);

        p = procfs_file_alloca(pid, "comm");

        r = read_one_line_file(p, name);
        if (r == -ENOENT)
                return -ESRCH;

        return r;
}

int get_process_cmdline(pid_t pid, size_t max_length, bool comm_fallback, char **line) {
        _cleanup_fclose_ FILE *f = NULL;
        char *r = NULL, *k;
        const char *p;
        int c;

        assert(line);
        assert(pid >= 0);

        p = procfs_file_alloca(pid, "cmdline");

        f = fopen(p, "re");
        if (!f)
                return -errno;

        if (max_length == 0) {
                size_t len = 0, allocated = 0;

                while ((c = getc(f)) != EOF) {

                        if (!GREEDY_REALLOC(r, allocated, len+2)) {
                                free(r);
                                return -ENOMEM;
                        }

                        r[len++] = isprint(c) ? c : ' ';
                }

                if (len > 0)
                        r[len-1] = 0;

        } else {
                bool space = false;
                size_t left;

                r = new(char, max_length);
                if (!r)
                        return -ENOMEM;

                k = r;
                left = max_length;
                while ((c = getc(f)) != EOF) {

                        if (isprint(c)) {
                                if (space) {
                                        if (left <= 4)
                                                break;

                                        *(k++) = ' ';
                                        left--;
                                        space = false;
                                }

                                if (left <= 4)
                                        break;

                                *(k++) = (char) c;
                                left--;
                        }  else
                                space = true;
                }

                if (left <= 4) {
                        size_t n = MIN(left-1, 3U);
                        memcpy(k, "...", n);
                        k[n] = 0;
                } else
                        *k = 0;
        }

        /* Kernel threads have no argv[] */
        if (isempty(r)) {
                _cleanup_free_ char *t = NULL;
                int h;

                free(r);

                if (!comm_fallback)
                        return -ENOENT;

                h = get_process_comm(pid, &t);
                if (h < 0)
                        return h;

                r = strjoin("[", t, "]", NULL);
                if (!r)
                        return -ENOMEM;
        }

        *line = r;
        return 0;
}

int reset_all_signal_handlers(void) {
        static const struct sigaction sa = {
                .sa_handler = SIG_DFL,
                .sa_flags = SA_RESTART,
        };
        int ret = 0, sig;

        for (sig = 1; sig < _NSIG; sig++) {

                /* These two cannot be caught... */
                if (IN_SET(sig, SIGKILL, SIGSTOP))
                        continue;

                /* On Linux the first two RT signals are reserved by glibc, and sigaction() will return
                 * EINVAL for them. */
                if (sigaction(sig, &sa, NULL) < 0 && errno != EINVAL && ret >= 0)
                        ret = -errno;
        }

        return ret;
}

int reset_signal_mask(void) {
        sigset_t ss;

        if (sigemptyset(&ss) < 0)
                return -errno;

        if (sigprocmask(SIG_SETMASK, &ss, NULL) < 0)
                return -errno;

        return 0;
}
