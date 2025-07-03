/*
 * Copyright (C) 2003-2013 Kay Sievers <kay@vrfy.org>
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <grp.h>
#include <dirent.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/file.h>

#include "path-util.h"
#include "mkdir.h"
#include "siphash24.h"
#include "udev.h"
#include "udev-util.h"
#include "smack-util.h"
#include "unaligned.h"

/* Three different errors for "this device does not quite exist" */
#define ERRNO_IS_DEVICE_ABSENT(r) IN_SET(abs(r), ENODEV, ENXIO, ENOENT)

#define UDEV_NODE_HASH_KEY ((const uint8_t[16]) { 0xb9, 0x6a, 0xf1, 0xce, 0x40, 0x31, 0x44, 0x1a, \
                                                   0x9e, 0x19, 0xec, 0x8b, 0xae, 0xf3, 0xe3, 0x2f })

static int node_remove_symlink(struct udev_device *dev, const char *slink) {
        assert(dev);
        assert(slink);

        if (unlink(slink) < 0 && errno != ENOENT)
                return log_debug_errno(errno, "Failed to remove '%s': %m", slink);

        (void) rmdir_parents(slink, "/dev");
        return 0;
}

static int node_create_symlink(struct udev_device *dev, const char *devnode, const char *slink) {
        struct stat st;
        int r;

        assert(dev);
        assert(slink);

        if (!devnode) {
                devnode = udev_device_get_devnode(dev);
                if (!devnode)
                        return log_debug_errno(ENOENT, "Failed to get device node: %m");
        }

        if (lstat(slink, &st) >= 0) {
                if (!S_ISLNK(st.st_mode))
                        return log_debug_errno(EEXIST,
                                               "Conflicting inode '%s' found, symlink to '%s' will not be created.",
                                               slink, devnode);
        } else if (errno != ENOENT)
                return log_debug_errno(errno, "Failed to lstat() '%s': %m", slink);

        r = mkdir_parents_label(slink, 0755);
        if (r < 0)
                return log_debug_errno(r, "Failed to create parent directory of '%s': %m", slink);

        /* use relative link */
        r = symlink_atomic_full_label(devnode, slink, /* make_relative = */ true);
        if (r < 0)
                return log_debug_errno(r, "Failed to create symlink '%s' to '%s': %m", slink, devnode);

        log_debug("Successfully created symlink '%s' to '%s'", slink, devnode);
        return 0;
}

static int stack_directory_read_one(struct udev *udev, int dirfd, const char *id, char **devnode, int *priority) {
        _cleanup_free_ char *buf = NULL;
        int tmp_prio, r;

        assert(udev);
        assert(dirfd >= 0);
        assert(id);
        assert(priority);

        /* This reads priority and device node from the symlink under /run/udev/links (or udev database).
         * If 'devnode' is NULL, obtained priority is always set to '*priority'. If 'devnode' is non-NULL,
         * this updates '*devnode' and '*priority'. */

        /* First, let's try to read the entry with the new format, which should replace the old format pretty
         * quickly. */
        r = readlinkat_malloc(dirfd, id, &buf);
        if (r >= 0) {
                char *colon;

                /* With the new format, the devnode and priority can be obtained from symlink itself. */

                colon = strchr(buf, ':');
                if (!colon || colon == buf)
                        return -EINVAL;

                *colon = '\0';

                /* Of course, this check is racy, but it is not necessary to be perfect. Even if the device
                 * node will be removed after this check, we will receive 'remove' uevent, and the invalid
                 * symlink will be removed during processing the event. The check is just for shortening the
                 * timespan that the symlink points to a non-existing device node. */
                if (access(colon + 1, F_OK) < 0)
                        return -ENODEV;

                r = safe_atoi(buf, &tmp_prio);
                if (r < 0)
                        return r;

                if (!devnode)
                        goto finalize;

                if (*devnode && tmp_prio <= *priority)
                        return 0; /* Unchanged */

                r = free_and_strdup(devnode, colon + 1);
                if (r < 0)
                        return r;

        } else if (r == -EINVAL) { /* Not a symlink ? try the old format */
                _cleanup_udev_device_unref_ struct udev_device *dev = NULL;
                const char *val;

                /* Old format. The devnode and priority must be obtained from uevent and udev database. */

                dev = udev_device_new_from_device_id(udev, id);
                if (!dev)
                        return errno > 0 ? -errno : -ENODEV;

                tmp_prio = udev_device_get_devlink_priority(dev);

                if (!devnode)
                        goto finalize;

                if (*devnode && tmp_prio <= *priority)
                        return 0; /* Unchanged */

                val = udev_device_get_devnode(dev);
                if (!val)
                        return -ENOENT;

                r = free_and_strdup(devnode, val);
                if (r < 0)
                        return r;

        } else
                return r == -ENOENT ? -ENODEV : r;

finalize:
        *priority = tmp_prio;
        return 1; /* Updated */
}

static int stack_directory_find_prioritized_devnode(struct udev_device *dev, int dirfd, bool add, char **ret) {
        struct udev *udev = udev_device_get_udev(dev);
        _cleanup_closedir_ DIR *dir = NULL;
        _cleanup_free_ char *devnode = NULL;
        struct dirent *de;
        int r, priority = 0;
        const char *id;

        assert(dev);
        assert(dirfd >= 0);
        assert(ret);

        /* Find device node of device with highest priority. This returns 1 if a device found, 0 if no
         * device found, or a negative errno on error. */

        if (add) {
                const char *n;

                priority = udev_device_get_devlink_priority(dev);

                n = udev_device_get_devnode(dev);
                if (!n)
                        return -ENOENT;

                devnode = strdup(n);
                if (!devnode)
                        return -ENOMEM;
        }

        dir = xopendirat(dirfd, ".", O_NOFOLLOW);
        if (!dir)
                return -errno;

        id = udev_device_get_id_filename(dev);
        if (!id)
                return -ENODEV;

        for (de = readdir(dir); de; de = readdir(dir)) {
                if (hidden_file(de->d_name))
                        continue;

                /* skip ourself */
                if (streq(de->d_name, id))
                        continue;

                r = stack_directory_read_one(udev, dirfd, de->d_name, &devnode, &priority);
                if (r < 0 && r != -ENODEV)
                        log_debug_errno(r, "Failed to read '%s', ignoring: %m", de->d_name);
        }

        *ret = TAKE_PTR(devnode);
        return !!*ret;
}

static int stack_directory_update(struct udev_device *dev, int fd, bool add) {
        const char *id;

        assert(dev);
        assert(fd >= 0);

        id = udev_device_get_id_filename(dev);
        if (!id)
                return -ENODEV;

        if (add) {
                _cleanup_free_ char *data = NULL, *buf = NULL;
                const char *devname;
                int priority;

                devname = udev_device_get_devnode(dev);
                if (!devname)
                        return -ENOENT;

                priority = udev_device_get_devlink_priority(dev);

                if (asprintf(&data, "%i:%s", priority, devname) < 0)
                        return -ENOMEM;

                if (readlinkat_malloc(fd, id, &buf) >= 0 && streq(buf, data))
                        return 0; /* Unchanged. */

                (void) unlinkat(fd, id, 0);

                if (symlinkat(data, fd, id) < 0)
                        return -errno;

        } else {
                if (unlinkat(fd, id, 0) < 0) {
                        if (errno == ENOENT)
                                return 0; /* Unchanged. */
                        return -errno;
                }
        }

        return 1; /* Updated. */
}

static char urlsafe_base64char(int x) {
        static const char table[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                      "abcdefghijklmnopqrstuvwxyz"
                                      "0123456789-_";
        return table[x & 63];
}

static size_t udev_node_escape_path(const char *src, char *dest, size_t size) {
        size_t i, j;
        uint8_t out[8];
        uint64_t h;

        assert(src);
        assert(dest);
        assert(size >= 12);

        for (i = 0, j = 0; src[i] != '\0'; i++) {
                if (src[i] == '/') {
                        if (j+4 >= size - 12 + 1)
                                goto toolong;
                        memcpy(&dest[j], "\\x2f", 4);
                        j += 4;
                } else if (src[i] == '\\') {
                        if (j+4 >= size - 12 + 1)
                                goto toolong;
                        memcpy(&dest[j], "\\x5c", 4);
                        j += 4;
                } else {
                        if (j+1 >= size - 12 + 1)
                                goto toolong;
                        dest[j] = src[i];
                        j++;
                }
        }
        dest[j] = '\0';
        return j;

toolong:
        /* If the input path is too long to encode as a filename, then let's suffix with a string
         * generated from the hash of the path. */

        siphash24(out, src, strlen(src) + 1, UDEV_NODE_HASH_KEY);
        h = unaligned_read_le64(out);

        for (unsigned k = 0; k <= 10; k++)
                dest[size - k - 2] = urlsafe_base64char((h >> (k * 6)) & 63);

        dest[size - 1] = '\0';
        return size - 1;
}

static int stack_directory_get_name(const char *slink, char **ret) {
        _cleanup_free_ char *s = NULL;
        char name_enc[NAME_MAX+1];
        char *t;
        const char *name;

        assert(slink);
        assert(ret);

        s = strdup(slink);
        if (!s)
                return -ENOMEM;

        path_simplify(s);

        if (!path_is_normalized(s))
                return -EINVAL;

        name = path_startswith(s, "/dev");
        if (empty_or_root(name))
                return -EINVAL;

        /* The name of the stack directory is the escaped path below /dev including its leading
         * slash, e.g. \x2fdisk\x2fby-id\x2f..., as eudev has always named it. */
        udev_node_escape_path(strjoina("/", name), name_enc, sizeof(name_enc));

        t = strdup(name_enc);
        if (!t)
                return -ENOMEM;

        *ret = t;
        return 0;
}

static int stack_directory_open_and_lock(
                const char *slink,
                char **ret_dirpath,
                int *ret_dirfd,
                LockFile *ret_lockfile) {

        static const char *const dirs[] = {
                UDEV_ROOT_RUN "/udev/links/",
                UDEV_ROOT_RUN "/udev/links.lock/",
        };
        _cleanup_(release_lock_file) LockFile lockfile = LOCK_FILE_INIT;
        _cleanup_close_ int dirfd = -1;
        _cleanup_free_ char *name = NULL, *dirpath = NULL, *lockname = NULL;
        int r;

        assert(slink);
        assert(ret_dirpath);
        assert(ret_dirfd);
        assert(ret_lockfile);

        r = stack_directory_get_name(slink, &name);
        if (r < 0)
                return log_debug_errno(r, "Failed to build stack directory name for '%s': %m", slink);

        for (size_t i = 0; i < ELEMENTSOF(dirs); i++) {
                r = udev_mkdir_p(dirs[i], 0755);
                if (r < 0)
                        return log_debug_errno(r, "Failed to create '%s': %m", dirs[i]);
        }

        /* 1. Take a lock for the stack directory. */
        lockname = path_join(UDEV_ROOT_RUN "/udev/links.lock/", name);
        if (!lockname)
                return -ENOMEM;

        r = make_lock_file(lockname, LOCK_EX, &lockfile);
        if (r < 0)
                return log_debug_errno(r, "Failed to create and lock '%s': %m", lockname);

        /* 2. Create and open the stack directory. Do not create the stack directory before taking a lock,
         * otherwise the directory may be removed by another worker. */
        dirpath = path_join(UDEV_ROOT_RUN "/udev/links/", name);
        if (!dirpath)
                return -ENOMEM;

        dirfd = open_mkdir_at(AT_FDCWD, dirpath, O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW | O_RDONLY, 0755);
        if (dirfd < 0)
                return log_debug_errno(dirfd, "Failed to open stack directory '%s': %m", dirpath);

        *ret_dirpath = TAKE_PTR(dirpath);
        *ret_dirfd = TAKE_FD(dirfd);
        *ret_lockfile = lockfile;
        lockfile = LOCK_FILE_INIT;
        return 0;
}

/* Like systemd's sd_device_new_from_devname(): finds the device whose device node the specified
 * path below /dev/, e.g. a device node symlink, resolves to. */
static int device_new_from_devname(struct udev *udev, const char *devname, struct udev_device **ret) {
        _cleanup_udev_device_unref_ struct udev_device *dev = NULL;
        _cleanup_free_ char *resolved = NULL;
        struct stat st;

        assert(udev);
        assert(devname);
        assert(ret);

        if (isempty(path_startswith(devname, "/dev/")))
                return -EINVAL;

        resolved = realpath(devname, NULL);
        if (!resolved)
                return ERRNO_IS_DEVICE_ABSENT(errno) ? -ENODEV : -errno;

        if (isempty(path_startswith(resolved, "/dev/")))
                return -EINVAL;

        if (stat(resolved, &st) < 0)
                return ERRNO_IS_DEVICE_ABSENT(errno) ? -ENODEV : -errno;

        if (!S_ISCHR(st.st_mode) && !S_ISBLK(st.st_mode))
                return -ENOTTY;

        if (major(st.st_rdev) == 0)
                return -ENODEV;

        dev = udev_device_new_from_devnum(udev, S_ISBLK(st.st_mode) ? 'b' : 'c', st.st_rdev);
        if (!dev)
                return -ENODEV;

        if (udev_device_get_devnum(dev) != st.st_rdev)
                return -ENXIO;

        if (streq_ptr(udev_device_get_subsystem(dev), "block") != !!S_ISBLK(st.st_mode))
                return -ENXIO;

        *ret = TAKE_PTR(dev);
        return 0;
}

static int node_get_current(struct udev *udev, const char *slink, int dirfd, char **ret_id, int *ret_prio) {
        _cleanup_udev_device_unref_ struct udev_device *dev = NULL;
        _cleanup_free_ char *id_dup = NULL;
        const char *id;
        int r;

        assert(udev);
        assert(slink);
        assert(dirfd >= 0);
        assert(ret_id);

        r = device_new_from_devname(udev, slink, &dev);
        if (r < 0)
                return r;

        id = udev_device_get_id_filename(dev);
        if (!id)
                return -ENODEV;

        id_dup = strdup(id);
        if (!id_dup)
                return -ENOMEM;

        if (ret_prio) {
                r = stack_directory_read_one(udev, dirfd, id, NULL, ret_prio);
                if (r < 0)
                        return r;
        }

        *ret_id = TAKE_PTR(id_dup);
        return 0;
}

static int link_update(struct udev_device *dev, const char *slink, bool add) {
        /* On cleaning up,
         * 1. close the stack directory,
         * 2. remove the stack directory if it is empty,
         * 3. then finally release the lock.
         * Hence, the variables must be declared in the reverse order. */
        _cleanup_(release_lock_file) LockFile lockfile = LOCK_FILE_INIT; /* #3 */
        _cleanup_(rmdir_and_freep) char *dirpath = NULL; /* #2 */
        _cleanup_close_ int dirfd = -1; /* #1 */
        _cleanup_free_ char *current_id = NULL, *devnode = NULL;
        int r, current_prio;

        assert(dev);
        assert(slink);

        r = stack_directory_open_and_lock(slink, &dirpath, &dirfd, &lockfile);
        if (r < 0)
                return r;

        r = node_get_current(udev_device_get_udev(dev), slink, dirfd, &current_id, add ? &current_prio : NULL);
        if (r < 0 && !ERRNO_IS_DEVICE_ABSENT(r))
                return log_debug_errno(r, "Failed to get the current device node priority for '%s': %m", slink);

        r = stack_directory_update(dev, dirfd, add);
        if (r < 0)
                return log_debug_errno(r, "Failed to update stack directory for '%s': %m", slink);

        if (current_id) {
                const char *id;

                id = udev_device_get_id_filename(dev);
                if (!id)
                        return log_debug_errno(ENODEV, "Failed to get device id: %m");

                if (add) {
                        int prio;

                        prio = udev_device_get_devlink_priority(dev);

                        if (streq(current_id, id)) {
                                if (current_prio <= prio)
                                        /* The devlink is ours and already exists, and the new priority is
                                         * equal or higher than the previous. Hence, it is not necessary to
                                         * recreate it. */
                                        return 0;

                                /* The devlink priority is downgraded. Another device may have a higher
                                 * priority now. Let's find the device node with the highest priority. */
                        } else {
                                if (current_prio > prio)
                                        /* The devlink with a higher priority already exists and is owned by
                                         * another device. Hence, it is not necessary to recreate it. */
                                        return 0;

                                /* This device has the equal or a higher priority than the current. Let's
                                 * create the devlink to our device node. */
                                return node_create_symlink(dev, /* devnode = */ NULL, slink);
                        }

                } else {
                        if (!streq(current_id, id))
                                /* The devlink already exists and is owned by another device. Hence, it is
                                 * not necessary to recreate it. */
                                return 0;

                        /* The current devlink is ours, and the target device will be removed. Hence, we need
                         * to search the device that has the highest priority. and update the devlink. */
                }
        } else {
                /* The requested devlink does not exist, or the target device does not exist and the devlink
                 * points to a non-existing device. Let's search the device that has the highest priority,
                 * and update the devlink. */
                ;
        }

        r = stack_directory_find_prioritized_devnode(dev, dirfd, add, &devnode);
        if (r < 0)
                return log_debug_errno(r, "Failed to determine device node with the highest priority for '%s': %m", slink);
        if (r > 0)
                return node_create_symlink(dev, devnode, slink);

        log_debug("No reference left for '%s', removing", slink);
        return node_remove_symlink(dev, slink);
}

static bool device_has_devlink(struct udev_device *dev, const char *devlink) {
        return udev_list_entry_get_by_name(udev_device_get_devlinks_list_entry(dev), devlink) != NULL;
}

static void device_get_devpath_by_devnum(struct udev_device *dev, char *buf, size_t size) {
        snprintf(buf, size, "/dev/%s/%u:%u",
                 streq(udev_device_get_subsystem(dev), "block") ? "block" : "char",
                 major(udev_device_get_devnum(dev)), minor(udev_device_get_devnum(dev)));
}

int udev_node_update(struct udev_device *dev, struct udev_device *dev_old) {
        char filename[UTIL_PATH_SIZE];
        struct udev_list_entry *list_entry;
        int r;

        assert(dev);

        /* update possible left-over symlinks */
        udev_list_entry_foreach(list_entry, dev_old ? udev_device_get_devlinks_list_entry(dev_old) : NULL) {
                const char *devlink = udev_list_entry_get_name(list_entry);

                /* check if old link name still belongs to this device */
                if (device_has_devlink(dev, devlink))
                        continue;

                log_debug("Removing/updating old device symlink '%s', which is no longer belonging to this device.",
                          devlink);

                r = link_update(dev, devlink, /* add = */ false);
                if (r < 0)
                        log_warning_errno(r, "Failed to remove/update device symlink '%s', ignoring: %m",
                                          devlink);
        }

        /* create/update symlinks, add symlinks to name index */
        udev_list_entry_foreach(list_entry, udev_device_get_devlinks_list_entry(dev)) {
                const char *devlink = udev_list_entry_get_name(list_entry);

                r = link_update(dev, devlink, /* add = */ true);
                if (r < 0)
                        log_warning_errno(r, "Failed to create/update device symlink '%s', ignoring: %m",
                                          devlink);
        }

        device_get_devpath_by_devnum(dev, filename, sizeof(filename));

        /* always add /dev/{block,char}/$major:$minor */
        r = node_create_symlink(dev, /* devnode = */ NULL, filename);
        if (r < 0)
                return log_warning_errno(r, "Failed to create device symlink '%s': %m", filename);

        return 0;
}

int udev_node_remove(struct udev_device *dev) {
        char filename[UTIL_PATH_SIZE];
        struct udev_list_entry *list_entry;
        int r;

        assert(dev);

        /* remove/update symlinks, remove symlinks from name index */
        udev_list_entry_foreach(list_entry, udev_device_get_devlinks_list_entry(dev)) {
                const char *devlink = udev_list_entry_get_name(list_entry);

                r = link_update(dev, devlink, /* add = */ false);
                if (r < 0)
                        log_warning_errno(r, "Failed to remove/update device symlink '%s', ignoring: %m",
                                          devlink);
        }

        device_get_devpath_by_devnum(dev, filename, sizeof(filename));

        /* remove /dev/{block,char}/$major:$minor */
        return node_remove_symlink(dev, filename);
}

/* Like systemd's sd_device_open() with O_PATH: opens the device node of the device with O_PATH, and
 * checks that it is a block or character device node, as the subsystem of the device says, with the
 * device number of the device. */
static int device_open_node_opath(struct udev_device *dev) {
        _cleanup_close_ int fd = -1;
        const char *devnode;
        struct stat st;
        dev_t devnum;

        assert(dev);

        devnode = udev_device_get_devnode(dev);
        devnum = udev_device_get_devnum(dev);
        if (!devnode || major(devnum) == 0)
                return -ENOEXEC;

        fd = open(devnode, O_PATH|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        if (fstat(fd, &st) < 0)
                return -errno;

        if (st.st_rdev != devnum)
                return -ENXIO;

        if (streq_ptr(udev_device_get_subsystem(dev), "block") ? !S_ISBLK(st.st_mode) : !S_ISCHR(st.st_mode))
                return -ENXIO;

        return TAKE_FD(fd);
}

static int udev_node_apply_permissions_impl(
                int node_fd,
                const char *devnode,
                bool apply_mac,
                mode_t mode,
                uid_t uid,
                gid_t gid,
                struct udev_list *seclabel_list) {

        bool apply_mode, apply_uid, apply_gid;
        struct stat stats;
        struct udev_list_entry *entry;
        int r;

        assert(node_fd >= 0);
        assert(devnode);

        if (fstat(node_fd, &stats) < 0)
                return log_debug_errno(errno, "cannot stat() node %s: %m", devnode);

        /* If group is set, but mode is not set, "upgrade" mode for the group. */
        if (mode == MODE_INVALID && gid != GID_INVALID && gid > 0)
                mode = 0660;

        apply_mode = mode != MODE_INVALID && (stats.st_mode & 0777) != (mode & 0777);
        apply_uid = uid != UID_INVALID && stats.st_uid != uid;
        apply_gid = gid != GID_INVALID && stats.st_gid != gid;

        if (apply_mode || apply_uid || apply_gid || apply_mac) {
                bool selinux = false;
                bool smack = false;

                if (apply_mode || apply_uid || apply_gid) {
                        log_debug("Setting permissions %s, uid=" UID_FMT ", gid=" GID_FMT ", mode=%#o",
                                  devnode,
                                  uid != UID_INVALID ? uid : stats.st_uid,
                                  gid != GID_INVALID ? gid : stats.st_gid,
                                  mode != MODE_INVALID ? mode & 0777 : stats.st_mode & 0777);

                        r = fchmod_and_chown(node_fd, mode, uid, gid);
                        if (r < 0)
                                log_full_errno(r == -ENOENT ? LOG_DEBUG : LOG_ERR, r,
                                               "Failed to set owner/mode of %s to uid=" UID_FMT
                                               ", gid=" GID_FMT ", mode=%#o: %m",
                                               devnode,
                                               uid != UID_INVALID ? uid : stats.st_uid,
                                               gid != GID_INVALID ? gid : stats.st_gid,
                                               mode != MODE_INVALID ? mode & 0777 : stats.st_mode & 0777);
                } else
                        log_debug("Preserve permissions of %s, uid=" UID_FMT ", gid=" GID_FMT ", mode=%#o",
                                  devnode,
                                  uid != UID_INVALID ? uid : stats.st_uid,
                                  gid != GID_INVALID ? gid : stats.st_gid,
                                  mode != MODE_INVALID ? mode & 0777 : stats.st_mode & 0777);

                /* apply SECLABEL{$module}=$label */
                udev_list_entry_foreach(entry, seclabel_list ? udev_list_get_entry(seclabel_list) : NULL) {
                        const char *name, *label;
                        int q;

                        name = udev_list_entry_get_name(entry);
                        label = udev_list_entry_get_value(entry);

                        if (streq(name, "selinux")) {
                                selinux = true;

                                q = mac_selinux_apply_fd(node_fd, devnode, label);
                                if (q < 0)
                                        log_full_errno(q == -ENOENT ? LOG_DEBUG : LOG_ERR, q,
                                                       "SECLABEL: failed to set SELinux label '%s': %m", label);
                                else
                                        log_debug("SECLABEL: set SELinux label '%s'", label);

                        } else if (streq(name, "smack")) {
                                smack = true;

                                q = mac_smack_apply_fd(node_fd, label);
                                if (q < 0)
                                        log_full_errno(q == -ENOENT ? LOG_DEBUG : LOG_ERR, q,
                                                       "SECLABEL: failed to set SMACK label '%s': %m", label);
                                else
                                        log_debug("SECLABEL: set SMACK label '%s'", label);

                        } else
                                log_error("SECLABEL: unknown subsystem, ignoring '%s'='%s'", name, label);
                }

                /* set the defaults */
                if (!selinux)
                        (void) mac_selinux_fix_fd(node_fd, devnode, false);
                if (!smack)
                        (void) mac_smack_apply_fd(node_fd, NULL);
        }

        /* always update timestamp when we re-use the node, like on media change events */
        r = futimens_opath(node_fd, NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to adjust timestamp of node %s: %m", devnode);

        return 0;
}

int udev_node_apply_permissions(struct udev_device *dev, bool apply_mac,
                                mode_t mode, uid_t uid, gid_t gid,
                                struct udev_list *seclabel_list) {
        _cleanup_close_ int node_fd = -1;
        const char *devnode;

        assert(dev);

        devnode = udev_device_get_devnode(dev);
        if (!devnode)
                return log_debug_errno(ENOENT, "Failed to get devname: %m");

        node_fd = device_open_node_opath(dev);
        if (node_fd < 0) {
                if (ERRNO_IS_DEVICE_ABSENT(node_fd)) {
                        log_debug_errno(node_fd, "Device node %s is missing, skipping handling.", devnode);
                        return 0; /* This is necessarily racey, so ignore missing the device */
                }

                return log_debug_errno(node_fd, "Cannot open node %s: %m", devnode);
        }

        return udev_node_apply_permissions_impl(node_fd, devnode, apply_mac, mode, uid, gid, seclabel_list);
}

int static_node_apply_permissions(
                const char *name,
                mode_t mode,
                uid_t uid,
                gid_t gid,
                char **tags) {

        _cleanup_free_ char *unescaped_filename = NULL;
        _cleanup_close_ int node_fd = -1;
        const char *devnode;
        struct stat stats;
        char **t;
        int r;

        assert(name);

        if (uid == UID_INVALID && gid == GID_INVALID && mode == MODE_INVALID && !tags)
                return 0;

        devnode = strjoina("/dev/", name);

        node_fd = open(devnode, O_PATH|O_CLOEXEC);
        if (node_fd < 0) {
                bool ignore = ERRNO_IS_DEVICE_ABSENT(errno);
                r = -errno;

                log_full_errno(ignore ? LOG_DEBUG : LOG_WARNING, r,
                               "Failed to open device node '%s'%s: %m",
                               devnode, ignore ? ", ignoring" : "");
                return ignore ? 0 : r;
        }

        if (fstat(node_fd, &stats) < 0)
                return log_error_errno(errno, "Failed to stat %s: %m", devnode);

        if (!S_ISBLK(stats.st_mode) && !S_ISCHR(stats.st_mode)) {
                log_warning("%s is neither block nor character device, ignoring.", devnode);
                return 0;
        }

        if (!strv_isempty(tags)) {
                unescaped_filename = xescape(name, "/.");
                if (!unescaped_filename)
                        return log_oom();
        }

        /* export the tags to a directory as symlinks, allowing otherwise dead nodes to be tagged */
        STRV_FOREACH(t, tags) {
                _cleanup_free_ char *p = NULL;

                p = path_join(UDEV_ROOT_RUN "/udev/static_node-tags/", *t, unescaped_filename);
                if (!p)
                        return log_oom();

                r = mkdir_parents(p, 0755);
                if (r < 0)
                        return log_error_errno(r, "Failed to create parent directory for %s: %m", p);

                r = symlink(devnode, p);
                if (r < 0 && errno != EEXIST)
                        return log_error_errno(errno, "Failed to create symlink %s -> %s: %m", p, devnode);
        }

        return udev_node_apply_permissions_impl(node_fd, devnode, false, mode, uid, gid, NULL);
}
