/***
  This file is part of eudev, forked from systemd.

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

#pragma once

#include <asm/types.h>
#include <inttypes.h>
#include <linux/if_ether.h>
#include <linux/if_infiniband.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include "util.h"

union sockaddr_union {
        /* The minimal, abstract version */
        struct sockaddr sa;

        /* The libc provided version that allocates "enough room" for every protocol */
        struct sockaddr_storage storage;

        /* Protoctol-specific implementations */
        struct sockaddr_in in;
        struct sockaddr_in6 in6;
        struct sockaddr_un un;
        struct sockaddr_nl nl;
        struct sockaddr_ll ll;
        //struct sockaddr_vm vm;

        /* Ensure there is enough space to store Infiniband addresses */
        uint8_t ll_buffer[offsetof(struct sockaddr_ll, sll_addr) + CONST_MAX(ETH_ALEN, INFINIBAND_ALEN)];

        /* Ensure there is enough space after the AF_UNIX sun_path for one more NUL byte, just to be sure that the path
         * component is always followed by at least one NUL byte. */
        uint8_t un_buffer[sizeof(struct sockaddr_un) + 1];
};

static inline int sockaddr_un_set_path(struct sockaddr_un *ret, const char *path) {
        size_t l;

        assert(ret);
        assert(path);

        /* Initialize ret->sun_path from the specified argument. This will interpret paths starting with '@' as
         * abstract namespace sockets, and those starting with '/' as regular filesystem sockets. It won't accept
         * anything else (i.e. no relative paths), to avoid ambiguities. Note that this function cannot be used to
         * reference paths in the abstract namespace that include NUL bytes in the name. */

        l = strlen(path);
        if (l < 2)
                return -EINVAL;
        if (!IN_SET(path[0], '/', '@'))
                return -EINVAL;

        /* Don't allow paths larger than the space in sockaddr_un. Note that we are a tiny bit more restrictive than
         * the kernel is: we insist on NUL termination (both for abstract namespace and regular file system socket
         * addresses!), which the kernel doesn't. We do this to reduce chance of incompatibility with other apps that
         * do not expect non-NUL terminated file system path. */
        if (l+1 > sizeof(ret->sun_path))
                return path[0] == '@' ? -EINVAL : -ENAMETOOLONG; /* return a recognizable error if this is
                                                                  * too long to fit into a sockaddr_un, but
                                                                  * is a file system path, and thus might be
                                                                  * connectible via O_PATH indirection. */

        *ret = (struct sockaddr_un) {
                .sun_family = AF_UNIX,
        };

        if (path[0] == '@') {
                /* Abstract namespace socket */
                memcpy(ret->sun_path + 1, path + 1, l); /* copy *with* trailing NUL byte */
                return (int) (offsetof(struct sockaddr_un, sun_path) + l); /* 🔥 *don't* 🔥 include trailing NUL in size */

        } else {
                assert(path[0] == '/');

                /* File system socket */
                memcpy(ret->sun_path, path, l + 1); /* copy *with* trailing NUL byte */
                return (int) (offsetof(struct sockaddr_un, sun_path) + l + 1); /* include trailing NUL in size */
        }
}

static inline int connect_unix_path(int fd, int dir_fd, const char *path) {
        _cleanup_close_ int inode_fd = -1;
        union sockaddr_union sa = {
                .un.sun_family = AF_UNIX,
        };
        size_t path_len;
        socklen_t salen;

        assert(fd >= 0);
        assert(dir_fd == AT_FDCWD || dir_fd >= 0);
        assert(path);

        /* Connects to the specified AF_UNIX socket in the file system. Works around the 108 byte size limit
         * in sockaddr_un, by going via O_PATH if needed. This hence works for any kind of path. */

        path_len = strlen(path);

        /* Refuse zero length path early, to make sure AF_UNIX stack won't mistake this for an abstract
         * namespace path, since first char is NUL */
        if (path_len <= 0)
                return -EINVAL;

        if (dir_fd == AT_FDCWD && path_len < sizeof(sa.un.sun_path)) {
                memcpy(sa.un.sun_path, path, path_len + 1);
                salen = offsetof(struct sockaddr_un, sun_path) + path_len + 1;
        } else {
                const char *proc;
                size_t proc_len;

                /* If dir_fd is specified, then we need to go the indirect O_PATH route, because connectat()
                 * does not exist. If the path is too long, we also need to take the indirect route, since we
                 * can't fit this into a sockaddr_un directly. */

                inode_fd = openat(dir_fd, path, O_PATH|O_CLOEXEC);
                if (inode_fd < 0)
                        return -errno;

                proc = FORMAT_PROC_FD_PATH(inode_fd);
                proc_len = strlen(proc);

                assert(proc_len < sizeof(sa.un.sun_path));
                memcpy(sa.un.sun_path, proc, proc_len + 1);
                salen = offsetof(struct sockaddr_un, sun_path) + proc_len + 1;
        }

        return RET_NERRNO(connect(fd, &sa.sa, salen));
}
