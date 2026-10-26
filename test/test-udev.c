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
#include <sys/statvfs.h>
#include <sys/syscall.h>

#include "missing.h"
#include "mount-private.h"
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
 * files in the fake /dev, which also works in a user namespace, where mknod() is not permitted. The
 * bind mounts are read-only, so that nothing that runs here can change the host's nodes, not even their
 * timestamps, also when the tests run as root. */
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
                struct statvfs st;
                unsigned long flags;
                int fd, r;

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

                /* A remount sets nosuid, nodev and noexec as given, and in a user namespace, the ones of
                 * the mount of the host's node may not be cleared: keep them. The kernel keeps the atime
                 * flags when none is given. */
                if (statvfs(path, &st) < 0) {
                        r = -errno;
                        fprintf(stderr, "failed to get the mount flags of %s: %m\n", path);
                        return r;
                }
                flags = MS_REMOUNT|MS_BIND|MS_RDONLY;
                if (st.f_flag & ST_NOSUID)
                        flags |= MS_NOSUID;
                if (st.f_flag & ST_NODEV)
                        flags |= MS_NODEV;
                if (st.f_flag & ST_NOEXEC)
                        flags |= MS_NOEXEC;
                if (mount("none", path, "none", flags, NULL) < 0) {
                        r = -errno;
                        fprintf(stderr, "failed to make the bind mount of %s on %s read-only: %m\n", node, path);
                        return r;
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
        _cleanup_strv_free_ char **dirs = NULL;
        char **dir;

        dirs = udev_rules_get_dirs_runtime();
        if (!dirs) {
                fprintf(stderr, "failed to get the rules directories: %m\n");
                return -ENOMEM;
        }

        STRV_FOREACH(dir, dirs) {
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

/* see fake_filesystems() */
static bool keep_netifs = false;

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
         * its own, they reach only the loopback interface of the namespace. Where that is not permitted or
         * not available, e.g. in a container or without CONFIG_NET_NS, do not rename network interfaces
         * and do not assign alternative names, like 'udevadm test', instead of failing. */
        if (unshare(CLONE_NEWNET) < 0) {
                fprintf(stderr, "failed to create a network namespace, not renaming network interfaces: %m\n");
                keep_netifs = true;
        }

        err = make_mounts_private();
        if (err < 0)
                goto out;

        err = fake_dev("test/dev");
        if (err < 0)
                return err;

        /* recursively, to take the device nodes of the fake /dev along; the type is ignored for bind mounts,
         * but pass a string instead of NULL, which valgrind reports as invalid */
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

int main(int argc, char *argv[]) {
        _cleanup_udev_unref_ struct udev *udev = NULL;
        _cleanup_udev_event_unref_ struct udev_event *event = NULL;
        _cleanup_udev_device_unref_ struct udev_device *dev = NULL;
        _cleanup_udev_rules_unref_ struct udev_rules *rules = NULL;
        char syspath[UTIL_PATH_SIZE];
        const char *devpath;
        const char *action;
        sigset_t mask;
        int err;

        /* like udevd and udevadm, see stdio_open_missing(); test-udev runs programs too */
        stdio_open_missing();
        save_argc_argv(argc, argv);

        /* "test-udev --check-namespace" or "test-udev ACTION DEVPATH"; like systemd, the number of arguments
         * is checked before the mount namespace is set up */
        if (!IN_SET(argc, 2, 3)) {
                log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                "This program needs one or two arguments, %d given", argc - 1);
                return EXIT_FAILURE;
        }

        err = fake_filesystems();
        if (err < 0)
                return EXIT_FAILURE;

        /* "test-udev --check-namespace" only tells whether the mount namespace with the fake file systems can
         * be set up, see udev-test.pl; the reason why not is printed above. Like systemd, which calls it
         * "check", any other single argument is refused only after that. */
        if (argc == 2) {
                if (!streq(argv[1], "--check-namespace")) {
                        log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown argument: %s", argv[1]);
                        return EXIT_FAILURE;
                }

                return EXIT_SUCCESS;
        }

        /* test/sys is a directory, which libudev refuses as sysfs by default */
        if (setenv("UDEV_DEVICE_VERIFY_SYSFS", "0", 1) < 0)
                return EXIT_FAILURE;

        udev = udev_new();
        if (udev == NULL)
                return EXIT_FAILURE;

        /* NAME= of a network interface and net_id select the naming scheme, which udevd logs at info
         * level once when it starts; not in the output of the tests. Warnings about unknown schemes are
         * still shown. */
        naming_scheme_set_log_level(LOG_DEBUG);

        log_debug("version %s", VERSION);
        mac_selinux_init("/dev");

        action = argv[1];
        devpath = argv[2];

        rules = udev_rules_new(udev, 1);
        if (rules == NULL) {
                err = log_error_errno(errno_or_else(ENOMEM), "Failed to read udev rules: %m");
                goto out;
        }

        strscpyl(syspath, sizeof(syspath), "/sys", devpath, NULL);
        dev = udev_device_new_from_synthetic_event(udev, syspath, action);
        if (dev == NULL) {
                err = log_debug_errno(errno_or_else(ENODEV), "Failed to open device '%s': %m", devpath);
                goto out;
        }

        /* Like the devices a udevd worker receives, do not read info from the db */
        udev_device_set_info_loaded(dev);

        event = udev_event_new(dev, EVENT_TEST_RULE_RUNNER);
        if (event == NULL) {
                err = log_oom();
                goto out;
        }
        event->keep_netifs = keep_netifs;

        sigfillset(&mask);
        sigprocmask(SIG_SETMASK, &mask, NULL);
        event->fd_signal = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC);
        if (event->fd_signal < 0) {
                err = log_error_errno(errno, "Failed to create signalfd: %m");
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
                                     3 * USEC_PER_SEC,
                                     NULL,
                                     rules) >= 0) {
                udev_event_execute_run(event,
                                       3 * USEC_PER_SEC);

                /* Finalize the database like the udevd worker does after RUN, so that ID_PROCESSING=1 is not
                 * left in it, and restore the previous database entry and the tag index like it, when that
                 * fails. The database was removed already on remove. */
                if (!streq(action, "remove")) {
                        err = udev_device_add_property(dev, "ID_PROCESSING", NULL);
                        if (err < 0)
                                log_error_errno(err, "Failed to remove 'ID_PROCESSING' property: %m");
                        else {
                                err = udev_device_update_db(dev);
                                if (err < 0)
                                        log_error_errno(err, "Failed to update database under " UDEV_ROOT_RUN "/udev/data/: %m");
                        }
                        if (err < 0)
                                udev_event_restore_db(event);
                }
        }
out:
        if (event != NULL && event->fd_signal >= 0)
                close(event->fd_signal);
        mac_selinux_finish();

        return err ? EXIT_FAILURE : EXIT_SUCCESS;
}
