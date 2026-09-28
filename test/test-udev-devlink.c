/***
  This file is part of eudev.

  eudev is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  eudev is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with eudev; If not, see <http://www.gnu.org/licenses/>.
***/

/* Processes one event like a udevd worker does, for udev-devlink-test.sh.
 *
 * Unlike test-udev, it neither sets up fake file systems nor creates or removes device nodes: the
 * caller provides /sys, /dev and /run/udev, e.g. in a user and mount namespace. Like a device
 * received from the kernel by udevd, the device does not read its old database entry.
 *
 * Usage: test-udev-devlink ACTION DEVPATH
 *
 * If $DL_BARRIER is set, the rules are loaded first, then the event waits until that file exists, so
 * that several processes can be released at the same moment. $DL_DEBUG enables debug logging. */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/signalfd.h>
#include <sys/stat.h>

#include "udev.h"
#include "udev-util.h"

int main(int argc, char *argv[]) {
        _cleanup_udev_unref_ struct udev *udev = NULL;
        _cleanup_udev_rules_unref_ struct udev_rules *rules = NULL;
        _cleanup_udev_device_unref_ struct udev_device *dev = NULL;
        _cleanup_udev_event_unref_ struct udev_event *event = NULL;
        char syspath[UTIL_PATH_SIZE];
        const char *barrier;
        sigset_t mask, sigmask_orig;

        if (argc != 3) {
                fprintf(stderr, "usage: %s ACTION DEVPATH\n", program_invocation_short_name);
                return EXIT_FAILURE;
        }

        udev = udev_new();
        if (!udev)
                return EXIT_FAILURE;

        if (getenv("DL_DEBUG")) {
                log_set_target(LOG_TARGET_CONSOLE);
                log_set_max_level(LOG_DEBUG);
                log_open();
        }

        rules = udev_rules_new(udev, 1);
        if (!rules)
                return EXIT_FAILURE;

        strscpyl(syspath, sizeof(syspath), "/sys", argv[2], NULL);
        dev = udev_device_new_from_synthetic_event(udev, syspath, argv[1]);
        if (!dev) {
                fprintf(stderr, "unknown device '%s'\n", argv[2]);
                return EXIT_FAILURE;
        }

        /* like a device received from the kernel by udevd: do not read the old database entry into it */
        udev_device_set_info_loaded(dev);

        event = udev_event_new(dev, EVENT_TEST_RULE_RUNNER);
        if (!event)
                return EXIT_FAILURE;

        sigprocmask(SIG_SETMASK, NULL, &sigmask_orig);
        sigfillset(&mask);
        sigprocmask(SIG_SETMASK, &mask, &sigmask_orig);
        event->fd_signal = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC);
        if (event->fd_signal < 0) {
                fprintf(stderr, "error creating signalfd: %m\n");
                return EXIT_FAILURE;
        }

        barrier = getenv("DL_BARRIER");
        if (barrier) {
                struct stat st;

                while (stat(barrier, &st) < 0)
                        nanosleep(&(struct timespec) { .tv_nsec = 50 * 1000 }, NULL);
        }

        udev_event_execute_rules(event, 3 * USEC_PER_SEC, USEC_PER_SEC, NULL, rules, &sigmask_orig);
        udev_event_execute_run(event, 3 * USEC_PER_SEC, USEC_PER_SEC, NULL);

        safe_close(event->fd_signal);
        return EXIT_SUCCESS;
}
