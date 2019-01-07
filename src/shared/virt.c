/***
  This file is part of eudev, forked from systemd.

  Copyright 2011 Lennart Poettering

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

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <linux/magic.h>

#include "util.h"
#include "process-util.h"
#include "virt.h"
#include "fileio.h"
#include "log.h"

int detect_container(const char **id) {

        static thread_local int cached_found = -1;
        static thread_local const char *cached_id = NULL;

        _cleanup_free_ char *m = NULL;
        const char *_id = NULL, *e = NULL;
        int r;

        if (_likely_(cached_found >= 0)) {

                if (id)
                        *id = cached_id;

                return cached_found;
        }

        /* /proc/vz exists in container and outside of the container,
         * /proc/bc only outside of the container. */
        if (access("/proc/vz", F_OK) >= 0 &&
            access("/proc/bc", F_OK) < 0) {
                _id = "openvz";
                r = 1;
                goto finish;
        }

        if (getpid() == 1) {
                /* If we are PID 1 we can just check our own
                 * environment variable */

                e = getenv("container");
                if (isempty(e)) {
                        r = 0;
                        goto finish;
                }
        } else {

                /* Otherwise, PID 1 dropped this information into a
                 * file in UDEV_ROOT_RUN. This is better than accessing
                 * /proc/1/environ, since we don't need CAP_SYS_PTRACE
                 * for that. */

                r = read_one_line_file(UDEV_ROOT_RUN "/systemd/container", &m);
                if (r == -ENOENT) {
                        r = 0;
                        goto finish;
                }
                if (r < 0)
                        return r;

                e = m;
        }

        /* We only recognize a selected few here, since we want to
         * enforce a redacted namespace */
        if (streq(e, "lxc"))
                _id ="lxc";
        else if (streq(e, "lxc-libvirt"))
                _id = "lxc-libvirt";
        else if (streq(e, "systemd-nspawn"))
                _id = "systemd-nspawn";
        else if (streq(e, "docker"))
                _id = "docker";
        else
                _id = "other";

        r = 1;

finish:
        cached_found = r;

        cached_id = _id;
        if (id)
                *id = _id;

        return r;
}

/* Like systemd's proc_mounted(): whether procfs is mounted on /proc. */
static int proc_mounted(void) {
        struct statfs s;

        if (statfs("/proc/", &s) < 0)
                return errno == ENOENT ? false : -errno;

        return F_TYPE_EQUAL(s.f_type, PROC_SUPER_MAGIC);
}

/* Like the stat() fallback of systemd's inode_same(): whether a and b are the same inode. */
static int inode_same(const char *a, const char *b) {
        struct stat sta, stb;

        if (stat(a, &sta) < 0)
                return -errno;
        if (stat(b, &stb) < 0)
                return -errno;

        return ((sta.st_mode ^ stb.st_mode) & S_IFMT) == 0 &&
                sta.st_dev == stb.st_dev &&
                sta.st_ino == stb.st_ino;
}

int running_in_chroot(void) {
        int r;

        /* If we're PID1, /proc may not be mounted (and most likely we're not in a chroot). But PID1 will
         * mount /proc, so all other programs can assume that if /proc is *not* available, we're in some
         * chroot. */

        /* eudev: $UDEV_IN_CHROOT takes precedence over $SYSTEMD_IN_CHROOT. */
        r = getenv_bool("UDEV_IN_CHROOT");
        if (r >= 0)
                return r > 0;
        if (r != -ENXIO)
                log_debug_errno(r, "Failed to parse $UDEV_IN_CHROOT, ignoring: %m");

        r = getenv_bool("SYSTEMD_IN_CHROOT");
        if (r >= 0)
                return r > 0;
        if (r != -ENXIO)
                log_debug_errno(r, "Failed to parse $SYSTEMD_IN_CHROOT, ignoring: %m");

        /* Deprecated but kept for backwards compatibility. */
        if (getenv_bool("SYSTEMD_IGNORE_CHROOT") > 0)
                return 0;

        r = inode_same("/proc/1/root", "/");
        if (r == -ENOENT) {
                r = proc_mounted();
                if (r == 0) {
                        if (getpid() == 1)
                                return false; /* We will mount /proc, assuming we're not in a chroot. */

                        log_debug("/proc/ is not mounted, assuming we're in a chroot.");
                        return true;
                }
                if (r > 0) /* If we have fake /proc/, we can't do the check properly. */
                        return -ENOSYS;
        }
        if (r < 0)
                return log_debug_errno(r, "Failed to check if /proc/1/root and / are the same inode: %m");

        return r == 0;
}
