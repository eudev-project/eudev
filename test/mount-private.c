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

/* The private mount namespace of test-udev, and of udev-devlink-test.sh run as root. */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/syscall.h>

#include "missing.h"
#include "util.h"
#include "mount-private.h"

/* Whether the mount that / is in is shared, i.e. has a peer group, so that a mount on / would propagate to
 * the other mounts of the group, e.g. in the namespace of the host: 1 if it is, 0 if not, or a negative error,
 * -EOPNOTSUPP without statx() with STATX_MNT_ID_UNIQUE and statmount() of Linux 6.8, which tell it although
 * the mount is not visible in a chroot, not even in /proc/self/mountinfo. The structures of the kernel are
 * buffers here, as the headers may lack them: struct statx has stx_mask at offset 0 and stx_mnt_id at 144,
 * struct statmount mask at 8 and mnt_propagation at 72. */
static int root_mount_is_shared(void) {
#if defined(__NR_statx) && defined(__NR_statmount)
        uint64_t stx[256 / sizeof(uint64_t)] = {}, sm[4096 / sizeof(uint64_t)] = {};
        struct {
                uint32_t size, mnt_ns_fd;
                uint64_t mnt_id, param;
        } req = {
                .size = 24,             /* MNT_ID_REQ_SIZE_VER0 */
                .param = 0x2,           /* STATMOUNT_MNT_BASIC */
        };

        if (syscall(__NR_statx, AT_FDCWD, "/", 0, 0x4000 /* STATX_MNT_ID_UNIQUE */, stx) < 0)
                return errno == ENOSYS ? -EOPNOTSUPP : -errno;
        if (!((uint32_t) stx[0] & 0x4000))
                return -EOPNOTSUPP;
        req.mnt_id = stx[144 / sizeof(uint64_t)];

        if (syscall(__NR_statmount, &req, sm, sizeof(sm), 0) < 0)
                return errno == ENOSYS ? -EOPNOTSUPP : -errno;
        if (!(sm[8 / sizeof(uint64_t)] & 0x2))
                return -EOPNOTSUPP;

        return !!(sm[72 / sizeof(uint64_t)] & MS_SHARED);
#else
        return -EOPNOTSUPP;
#endif
}

/* In a plain chroot, / is not a mount point, and its propagation cannot be changed. Make it one, as a
 * container does it: bind mount / onto itself in the namespace, and change the root to the new mount, which
 * "/.." leads into, and the working directory to the same directory in it. Not if the mount that / is in is
 * shared, as the new mount would then propagate to the other mounts of its peer group, e.g. in the namespace
 * of the host, and unmounting it again would propagate as well, also to the mounts of the chroot there. */
static int mount_root_onto_itself(void) {
        _cleanup_free_ char *cwd = NULL;
        int r;

        r = root_mount_is_shared();
        if (r == -EOPNOTSUPP) {
                fprintf(stderr, "/ is not a mount point, and whether its mount is shared cannot be found out (this "
                        "needs statmount() of Linux 6.8 or later); bind mount the root directory onto itself before "
                        "changing the root to it\n");
                return r;
        }
        if (r < 0) {
                fprintf(stderr, "/ is not a mount point, and whether its mount is shared cannot be found out: %s\n",
                        strerror(-r));
                return r;
        }
        if (r > 0) {
                fprintf(stderr, "/ is not a mount point, and its mount is shared, so that a mount on / would show "
                        "outside of the chroot; bind mount the root directory onto itself before changing the root "
                        "to it, or make the mount it is in private\n");
                return -EPERM;
        }

        cwd = get_current_dir_name();
        if (!cwd) {
                r = -errno;
                fprintf(stderr, "failed to get the working directory: %m\n");
                return r;
        }

        if (mount("/", "/", "none", MS_BIND|MS_REC, NULL) < 0) {
                r = -errno;
                fprintf(stderr, "/ is not a mount point, and it cannot be bind mounted onto itself: %m\n");
                return r;
        }

        if (chroot("/..") < 0 || chdir(cwd) < 0) {
                r = -errno;
                fprintf(stderr, "failed to change the root to / bind mounted onto itself: %m\n");
                return r;
        }

        return 0;
}

int make_mounts_private(void) {
        int r;

        /* The source and the type are ignored when changing the propagation, but pass strings instead of
         * NULL, which valgrind reports as invalid. In a plain chroot, / is not a mount point, which fails
         * with EINVAL: make it one. */
        if (mount("none", "/", "none", MS_PRIVATE|MS_REC, NULL) >= 0)
                return 0;
        if (errno != EINVAL) {
                r = -errno;
                fprintf(stderr, "failed to mount / as private: %m\n");
                return r;
        }

        r = mount_root_onto_itself();
        if (r < 0)
                return r;

        if (mount("none", "/", "none", MS_PRIVATE|MS_REC, NULL) < 0) {
                r = -errno;
                fprintf(stderr, "failed to mount / as private: %m\n");
                return r;
        }

        return 0;
}
