/***
  This file is part of systemd.

  Copyright 2003-2004 Greg Kroah-Hartman <greg@kroah.com>
  Copyright 2004-2012 Kay Sievers <kay@vrfy.org>

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

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <grp.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/signalfd.h>

#include "missing.h"
#include "netif-naming-scheme.h"
#include "path-util.h"
#include "udev.h"
#include "udev-rules-check.h"
#include "udev-util.h"

#ifndef HAVE_UNSHARE
#include <sys/syscall.h>
/* Provide our own replacement with local reach*/
static inline int unshare (int x) { return syscall(SYS_unshare, x); }
#endif

#ifndef _USE_GNU
/* Make sure CLONE_NEWNS macro is available */
#include <linux/sched.h>
#endif

/* The device nodes and symlinks the programs of PROGRAM, IMPORT{program} and RUN may need, e.g.
 * spawned programs get /dev/null as stdin. The device nodes of the host are bind mounted onto empty
 * files in the fake /dev, which also works in a user namespace, where mknod() is not permitted. */
static int fake_dev(const char *dir) {
        static const char *const nodes[] = { "null", "zero", "full", "random", "urandom" };
        static const char *const links[][2] = {
                { "fd",     "/proc/self/fd" },
                { "stdin",  "/proc/self/fd/0" },
                { "stdout", "/proc/self/fd/1" },
                { "stderr", "/proc/self/fd/2" },
        };
        char path[UTIL_PATH_SIZE], node[UTIL_PATH_SIZE];
        unsigned int i;

        for (i = 0; i < ELEMENTSOF(nodes); i++) {
                int fd;

                strscpyl(path, sizeof(path), dir, "/", nodes[i], NULL);
                strscpyl(node, sizeof(node), "/dev/", nodes[i], NULL);

                fd = open(path, O_WRONLY|O_CREAT|O_CLOEXEC|O_NOFOLLOW|O_NOCTTY, 0666);
                if (fd < 0) {
                        fprintf(stderr, "failed to create %s: %m\n", path);
                        return -errno;
                }
                close(fd);

                if (mount(node, path, "none", MS_BIND, NULL) < 0) {
                        fprintf(stderr, "failed to bind mount %s to %s: %m\n", node, path);
                        return -errno;
                }
        }

        for (i = 0; i < ELEMENTSOF(links); i++) {
                strscpyl(path, sizeof(path), dir, "/", links[i][0], NULL);
                if (symlink(links[i][1], path) < 0 && errno != EEXIST) {
                        fprintf(stderr, "failed to create symlink %s: %m\n", path);
                        return -errno;
                }
        }

        return 0;
}

/* Mount an empty, read-only tmpfs over each directory that the rules are read from, so that no rules of
 * the host get into the tests. The one below UDEV_ROOT_RUN is in the test's /run already, and holds the
 * rules of the test. A directory that does not exist has no rules to hide. */
static int mask_rules_dirs(void) {
        const char *const *dir;

        for (dir = udev_rules_get_dirs(); *dir; dir++) {
                if (path_startswith(*dir, UDEV_ROOT_RUN))
                        continue;

                if (mount("tmpfs", *dir, "tmpfs", MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC, "mode=0755") < 0) {
                        if (IN_SET(errno, ENOENT, ENOTDIR))
                                continue;
                        fprintf(stderr, "failed to mount an empty directory over %s: %m\n", *dir);
                        return -errno;
                }
        }

        return 0;
}

static int fake_filesystems(void) {
        static const struct fakefs {
                const char *src;
                const char *target;
                const char *error;
        } fakefss[] = {
                { "test/sys", "/sys",                   "failed to mount test /sys" },
                { "test/dev", "/dev",                   "failed to mount test /dev" },
                { "test/run", UDEV_ROOT_RUN,            "failed to mount test " UDEV_ROOT_RUN },
        };
        unsigned int i;
        int err;

        err = unshare(CLONE_NEWNS);
        if (err < 0) {
                err = -errno;
                fprintf(stderr, "failed to call unshare(): %m\n");
                goto out;
        }

        /* The fake network interfaces have the ifindexes of real ones, so NAME= and the alternative names
         * would rename the network interfaces of the host, or add names to them. In a network namespace of
         * its own, they reach only the loopback interface of the namespace. */
        if (unshare(CLONE_NEWNET) < 0) {
                err = -errno;
                fprintf(stderr, "failed to create a network namespace: %m\n");
                goto out;
        }

        /* The source and the type are ignored when changing the propagation and for bind mounts,
         * but pass strings instead of NULL, which valgrind reports as invalid. */
        if (mount("none", "/", "none", MS_PRIVATE|MS_REC, NULL) < 0) {
                err = -errno;
                fprintf(stderr, "failed to mount / as private: %m\n");
                goto out;
        }

        err = fake_dev("test/dev");
        if (err < 0)
                return err;

        /* recursively, to take the device nodes of the fake /dev along */
        for (i = 0; i < ELEMENTSOF(fakefss); i++) {
                err = mount(fakefss[i].src, fakefss[i].target, "none", MS_BIND|MS_REC, NULL);
                if (err < 0) {
                        err = -errno;
                        fprintf(stderr, "%s: %m\n", fakefss[i].error);
                        return err;
                }
        }

        err = mask_rules_dirs();
out:
        return err;
}

int main(int argc __attribute__((unused)), char *argv[]) {
        _cleanup_udev_unref_ struct udev *udev = NULL;
        _cleanup_udev_event_unref_ struct udev_event *event = NULL;
        _cleanup_udev_device_unref_ struct udev_device *dev = NULL;
        _cleanup_udev_rules_unref_ struct udev_rules *rules = NULL;
        char syspath[UTIL_PATH_SIZE];
        const char *devpath;
        const char *action;
        sigset_t mask, sigmask_orig;
        int err;

        err = fake_filesystems();
        if (err < 0)
                return EXIT_FAILURE;

        /* test/sys is a directory, which libudev refuses as sysfs by default */
        if (setenv("UDEV_DEVICE_VERIFY_SYSFS", "0", 1) < 0)
                return EXIT_FAILURE;

        udev = udev_new();
        if (udev == NULL)
                return EXIT_FAILURE;

        log_debug("version %s", VERSION);
        mac_selinux_init("/dev");

        sigprocmask(SIG_SETMASK, NULL, &sigmask_orig);

        action = argv[1];
        if (action == NULL) {
                log_error("action missing");
                goto out;
        }

        devpath = argv[2];
        if (devpath == NULL) {
                log_error("devpath missing");
                goto out;
        }

        rules = udev_rules_new(udev, 1);

        strscpyl(syspath, sizeof(syspath), "/sys", devpath, NULL);
        dev = udev_device_new_from_synthetic_event(udev, syspath, action);
        if (dev == NULL) {
                log_debug("unknown device '%s'", devpath);
                goto out;
        }

        /* Like the devices a udevd worker receives, do not read info from the db */
        udev_device_set_info_loaded(dev);

        /* NAME= of a network interface makes the rules select the naming scheme, which logs the scheme it
         * uses at info level, as udevd does once when it starts. Select it here without that line, so that
         * it does not end up in the output of the tests; warnings about unknown schemes are still shown. */
        if (udev_device_get_ifindex(dev) > 0) {
                int level = log_get_max_level();

                log_set_max_level(MIN(level, LOG_NOTICE));
                (void) naming_scheme_init(udev);
                log_set_max_level(level);
        }

        event = udev_event_new(dev, EVENT_TEST_RULE_RUNNER);

        sigfillset(&mask);
        sigprocmask(SIG_SETMASK, &mask, &sigmask_orig);
        event->fd_signal = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC);
        if (event->fd_signal < 0) {
                fprintf(stderr, "error creating signalfd\n");
                goto out;
        }

        /* do what devtmpfs usually provides us */
        if (udev_device_get_devnode(dev) != NULL) {
                mode_t mode = 0600;

                if (streq(udev_device_get_subsystem(dev), "block"))
                        mode |= S_IFBLK;
                else
                        mode |= S_IFCHR;

                if (!streq(action, "remove")) {
                        mkdir_parents_label(udev_device_get_devnode(dev), 0755);
                        mknod(udev_device_get_devnode(dev), mode, udev_device_get_devnum(dev));
                } else {
                        unlink(udev_device_get_devnode(dev));
                        rmdir_parents(udev_device_get_devnode(dev), "/");
                }
        }

        /* like udevd, which does not run RUN when the rules fail */
        if (udev_event_execute_rules(event,
                                     3 * USEC_PER_SEC, USEC_PER_SEC,
                                     NULL,
                                     rules,
                                     &sigmask_orig) >= 0) {
                udev_event_execute_run(event,
                                       3 * USEC_PER_SEC, USEC_PER_SEC,
                                       NULL);

                /* Finalize the database like the udevd worker does after RUN, so that ID_PROCESSING=1 is not
                 * left in it. The database was removed already on remove. */
                if (!streq(action, "remove")) {
                        err = udev_device_add_property(dev, "ID_PROCESSING", NULL);
                        if (err < 0)
                                log_error_errno(err, "Failed to remove 'ID_PROCESSING' property: %m");
                        else {
                                err = udev_device_update_db(dev);
                                if (err < 0)
                                        log_error_errno(err, "Failed to update database under " UDEV_ROOT_RUN "/udev/data/: %m");
                        }
                }
        }
out:
        if (event != NULL && event->fd_signal >= 0)
                close(event->fd_signal);
        mac_selinux_finish();

        return err ? EXIT_FAILURE : EXIT_SUCCESS;
}
