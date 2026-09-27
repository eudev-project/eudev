/*
 * Copyright (C) 2004-2012 Kay Sievers <kay@vrfy.org>
 * Copyright (C) 2009 Canonical Ltd.
 * Copyright (C) 2009 Scott James Remnant <scott@netsplit.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <dirent.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/inotify.h>

#include "udev.h"
#include "mkdir.h"

#define WATCH_DIR UDEV_ROOT_RUN "/udev/watch"

static int inotify_fd = -1;

/* inotify descriptor, will be shared with rules directory;
 * set to cloexec since we need our children to be able to add
 * watches for us
 */
int udev_watch_init(struct udev *udev __attribute__((unused))) {
        inotify_fd = inotify_init1(IN_CLOEXEC);
        if (inotify_fd < 0)
                log_error_errno(errno, "inotify_init failed: %m");
        return inotify_fd;
}

/* move any old watches directory out of the way, and then restore
 * the watches
 */
void udev_watch_restore(struct udev *udev) {
        if (inotify_fd < 0)
                return;

        if (rename(WATCH_DIR, WATCH_DIR ".old") == 0) {
                DIR *dir;
                struct dirent *ent;

                dir = opendir(WATCH_DIR ".old");
                if (dir == NULL) {
                        log_error_errno(errno, "unable to open old watches dir " WATCH_DIR ".old; old watches will not be restored: %m");
                        return;
                }

                for (ent = readdir(dir); ent != NULL; ent = readdir(dir)) {
                        char device[UTIL_PATH_SIZE];
                        ssize_t len;
                        struct udev_device *dev;
                        int wd;

                        if (ent->d_name[0] == '.')
                                continue;

                        /* For backward compatibility, read symlink from watch handle to device id, and ignore
                         * the opposite direction symlink. */
                        if (safe_atoi(ent->d_name, &wd) < 0)
                                goto unlink;

                        len = readlinkat(dirfd(dir), ent->d_name, device, sizeof(device));
                        if (len <= 0 || len == (ssize_t)sizeof(device))
                                goto unlink;
                        device[len] = '\0';

                        dev = udev_device_new_from_device_id(udev, device);
                        if (dev == NULL)
                                goto unlink;

                        log_debug("restoring old watch on '%s'", udev_device_get_devnode(dev));
                        udev_watch_begin(udev, dev);
                        udev_device_unref(dev);
unlink:
                        unlinkat(dirfd(dir), ent->d_name, 0);
                }

                closedir(dir);
                rmdir(WATCH_DIR ".old");

        } else if (errno != ENOENT) {
                log_error_errno(errno, "unable to move watches dir " WATCH_DIR "; old watches will not be restored: %m");
        }
}

static int udev_watch_clear(struct udev_device *dev, int dirfd, int *ret_wd) {
        char wd_str[DECIMAL_STR_MAX(int)];
        char buf[UTIL_PATH_SIZE];
        const char *id;
        ssize_t len;
        int wd = -1, r;

        id = udev_device_get_id_filename(dev);
        if (id == NULL)
                return -ENODEV;

        /* 1. read symlink ID -> wd */
        len = readlinkat(dirfd, id, wd_str, sizeof(wd_str));
        if (len < 0 && errno == ENOENT) {
                if (ret_wd)
                        *ret_wd = -1;
                return 0;
        }
        if (len < 0) {
                r = -errno;
                log_debug_errno(r, "Failed to read symlink '" WATCH_DIR "/%s': %m", id);
                goto finalize;
        }
        if ((size_t) len >= sizeof(wd_str)) {
                r = -EINVAL;
                log_debug_errno(r, "Invalid symlink '" WATCH_DIR "/%s'.", id);
                goto finalize;
        }
        wd_str[len] = '\0';

        r = safe_atoi(wd_str, &wd);
        if (r < 0) {
                log_debug_errno(r, "Failed to parse watch handle from symlink '" WATCH_DIR "/%s': %m", id);
                goto finalize;
        }

        if (wd < 0) {
                r = -EBADF;
                log_debug_errno(r, "Invalid watch handle %i.", wd);
                goto finalize;
        }

        /* 2. read symlink wd -> ID */
        len = readlinkat(dirfd, wd_str, buf, sizeof(buf));
        if (len < 0) {
                r = -errno;
                log_debug_errno(r, "Failed to read symlink '" WATCH_DIR "/%s': %m", wd_str);
                goto finalize;
        }
        if ((size_t) len >= sizeof(buf)) {
                r = -EINVAL;
                log_debug_errno(r, "Invalid symlink '" WATCH_DIR "/%s'.", wd_str);
                goto finalize;
        }
        buf[len] = '\0';

        /* 3. check if the symlink wd -> ID is owned by the device. */
        if (!streq(buf, id)) {
                r = -ENOENT;
                log_debug_errno(r, "Symlink '" WATCH_DIR "/%s' is owned by another device '%s'.", wd_str, buf);
                goto finalize;
        }

        /* 4. remove symlink wd -> ID.
         * In the above, we already confirmed that the symlink is owned by us. Hence, no other workers remove
         * the symlink and cannot create a new symlink with the same filename but to a different ID. Hence,
         * the removal below is safe even the steps in this function are not atomic. */
        if (unlinkat(dirfd, wd_str, 0) < 0 && errno != ENOENT)
                log_debug_errno(errno, "Failed to remove '" WATCH_DIR "/%s', ignoring: %m", wd_str);

        if (ret_wd)
                *ret_wd = wd;
        r = 0;

finalize:
        /* 5. remove symlink ID -> wd.
         * The file is always owned by the device. Hence, it is safe to remove it unconditionally. */
        if (unlinkat(dirfd, id, 0) < 0 && errno != ENOENT)
                log_debug_errno(errno, "Failed to remove '" WATCH_DIR "/%s': %m", id);

        return r;
}

void udev_watch_begin(struct udev *udev __attribute__((unused)), struct udev_device *dev) {
        char wd_str[DECIMAL_STR_MAX(int)];
        _cleanup_close_ int dirfd = -1;
        const char *devnode, *id;
        int wd = -1, r;

        if (inotify_fd < 0)
                return;

        devnode = udev_device_get_devnode(dev);
        if (devnode == NULL)
                return;

        id = udev_device_get_id_filename(dev);
        if (id == NULL)
                return;

        r = udev_mkdir_p(WATCH_DIR, 0755);
        if (r < 0) {
                log_error_errno(r, "Failed to create " WATCH_DIR ": %m");
                return;
        }

        dirfd = open(WATCH_DIR, O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW | O_RDONLY);
        if (dirfd < 0) {
                log_error_errno(errno, "Failed to open " WATCH_DIR ": %m");
                return;
        }

        /* 1. Clear old symlinks */
        (void) udev_watch_clear(dev, dirfd, NULL);

        /* 2. Add inotify watch */
        log_debug("adding watch on '%s'", devnode);
        wd = inotify_add_watch(inotify_fd, devnode, IN_CLOSE_WRITE);
        if (wd < 0) {
                /* the device may already be gone, e.g. a partition removed right after it appeared */
                if (IN_SET(errno, ENOENT, ENODEV, ENXIO))
                        log_debug_errno(errno, "inotify_add_watch(%d, %s, %o) failed: %m",
                            inotify_fd, devnode, IN_CLOSE_WRITE);
                else
                        log_error_errno(errno, "inotify_add_watch(%d, %s, %o) failed: %m",
                            inotify_fd, devnode, IN_CLOSE_WRITE);
                return;
        }

        xsprintf(wd_str, "%d", wd);

        /* 3. Create new symlinks */
        if (symlinkat(wd_str, dirfd, id) < 0) {
                log_error_errno(errno, "Failed to create symlink '" WATCH_DIR "/%s' to '%s': %m", id, wd_str);
                goto on_failure;
        }

        if (symlinkat(id, dirfd, wd_str) < 0) {
                /* Possibly, the watch handle is previously assigned to another device, and udev_watch_end()
                 * is not called for the device yet. */
                log_error_errno(errno, "Failed to create symlink '" WATCH_DIR "/%s' to '%s': %m", wd_str, id);
                goto on_failure;
        }

        return;

on_failure:
        (void) unlinkat(dirfd, id, 0);
        (void) inotify_rm_watch(inotify_fd, wd);
}

void udev_watch_end(struct udev *udev __attribute__((unused)), struct udev_device *dev) {
        _cleanup_close_ int dirfd = -1;
        int wd = -1, r;

        if (inotify_fd < 0)
                return;

        if (udev_device_get_devnode(dev) == NULL)
                return;

        dirfd = open(WATCH_DIR, O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW | O_RDONLY);
        if (dirfd < 0) {
                if (errno != ENOENT)
                        log_debug_errno(errno, "Failed to open " WATCH_DIR ": %m");
                return;
        }

        /* First, clear symlinks. */
        r = udev_watch_clear(dev, dirfd, &wd);
        if (r < 0)
                return;

        /* Then, remove inotify watch. */
        if (wd >= 0) {
                log_debug("removing watch handle %i on '%s'", wd, udev_device_get_devnode(dev));
                (void) inotify_rm_watch(inotify_fd, wd);
        }
}

struct udev_device *udev_watch_lookup(struct udev *udev, int wd) {
        char filename[UTIL_PATH_SIZE];
        char device[UTIL_NAME_SIZE];
        ssize_t len;

        if (inotify_fd < 0 || wd < 0)
                return NULL;

        snprintf(filename, sizeof(filename), WATCH_DIR "/%d", wd);
        len = readlink(filename, device, sizeof(device));
        if (len <= 0 || (size_t)len == sizeof(device))
                return NULL;
        device[len] = '\0';

        return udev_device_new_from_device_id(udev, device);
}
