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

#include <stdint.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <linux/random.h>

#include "random-util.h"
#include "time-util.h"
#include "missing.h"
#include "util.h"

int dev_urandom(void *p, size_t n) {
        static bool have_getrandom = true, have_grndinsecure = true;
        _cleanup_close_ int fd = -EBADF;

        if (n == 0)
                return 0;

        for (;;) {
                ssize_t l;

                if (!have_getrandom)
                        break;

                l = getrandom(p, n, have_grndinsecure ? GRND_INSECURE : GRND_NONBLOCK);
                if (l > 0) {
                        if ((size_t) l == n)
                                return 0; /* Done reading, success. */
                        p = (uint8_t *) p + l;
                        n -= l;
                        continue; /* Interrupted by a signal; keep going. */
                } else if (l == 0)
                        break; /* Weird, so fallback to /dev/urandom. */
                else if (errno == ENOSYS) {
                        have_getrandom = false;
                        break; /* No syscall, so fallback to /dev/urandom. */
                } else if (errno == EINVAL && have_grndinsecure) {
                        have_grndinsecure = false;
                        continue; /* No GRND_INSECURE; fallback to GRND_NONBLOCK. */
                } else if (errno == EAGAIN && !have_grndinsecure)
                        break; /* Will block, but no GRND_INSECURE, so fallback to /dev/urandom. */

                break; /* Unexpected, so just give up and fallback to /dev/urandom. */
        }

        fd = open("/dev/urandom", O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0)
                return errno == ENOENT ? -ENOSYS : -errno;

        return loop_read_exact(fd, p, n, true);
}

void initialize_srand(void) {
        static bool srand_called = false;
        unsigned x;
#ifdef HAVE_SYS_AUXV_H
        void *auxv;
#endif

        if (srand_called)
                return;

        x = 0;

#ifdef HAVE_SYS_AUXV_H
        /* The kernel provides us with a bit of entropy in auxv, so
         * let's try to make use of that to seed the pseudo-random
         * generator. It's better than nothing... */

        auxv = (void*) getauxval(AT_RANDOM);
        if (auxv)
                x ^= *(unsigned*) auxv;
#endif

        x ^= (unsigned) now(CLOCK_REALTIME);
        x ^= (unsigned) gettid();

        srand(x);
        srand_called = true;
}

void random_bytes(void *p, size_t n) {
        uint8_t *q;
        int r;

        r = dev_urandom(p, n);
        if (r >= 0)
                return;

        /* If some idiot made /dev/urandom unavailable to us, he'll
         * get a PRNG instead. */

        initialize_srand();

        for (q = p; q < (uint8_t*) p + n; q ++)
                *q = rand();
}
