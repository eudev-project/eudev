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

#include "path-util.h"
#include "mkdir.h"
#include "siphash24.h"
#include "udev.h"
#include "udev-util.h"
#include "smack-util.h"
#include "unaligned.h"

#define CREATE_LINK_MAX_RETRIES        128
#define CREATE_STACK_LINK_MAX_RETRIES  128
/* Three different errors for "this device does not quite exist" */
#define ERRNO_IS_DEVICE_ABSENT(r) IN_SET(abs(r), ENODEV, ENXIO, ENOENT)

#define UDEV_NODE_HASH_KEY ((const uint8_t[16]) { 0xb9, 0x6a, 0xf1, 0xce, 0x40, 0x31, 0x44, 0x1a, \
                                                   0x9e, 0x19, 0xec, 0x8b, 0xae, 0xf3, 0xe3, 0x2f })

static int create_symlink(const char *target, const char *slink) {
        int r = -ENOENT;

        assert(target);
        assert(slink);

        for (unsigned i = 0; i < CREATE_LINK_MAX_RETRIES; i++) {
                r = mkdir_parents_label(slink, 0755);
                if (r == -ENOENT)
                        continue;
                if (r < 0)
                        return r;

                mac_selinux_create_file_prepare(slink, S_IFLNK);
                r = RET_NERRNO(symlink(target, slink));
                mac_selinux_create_file_clear();
                if (r != -ENOENT)
                        return r;
        }

        return r;
}

static int node_symlink(struct udev_device *dev, const char *node, const char *slink) {
        struct stat stats;
        char target[UTIL_PATH_SIZE];
        char *s;
        size_t l;
        const char *id, *slink_tmp;
        int i = 0;
        int tail = 0;
        int r;

        assert(dev);
        assert(node);
        assert(slink);

        if (lstat(slink, &stats) >= 0) {
                if (!S_ISLNK(stats.st_mode))
                        return log_debug_errno(EEXIST,
                                               "Conflicting inode '%s' found, link to '%s' will not be created.", slink, node);
        } else if (errno != ENOENT)
                return log_debug_errno(errno, "Failed to lstat() '%s': %m", slink);

        /* use relative link */
        target[0] = '\0';
        while (node[i] && (node[i] == slink[i])) {
                if (node[i] == '/')
                        tail = i+1;
                i++;
        }
        s = target;
        l = sizeof(target);
        while (slink[i] != '\0') {
                if (slink[i] == '/')
                        l = strpcpy(&s, l, "../");
                i++;
        }
        l = strscpy(s, l, &node[tail]);
        if (l == 0)
                return log_debug_errno(EINVAL, "Failed to get relative path from '%s' to '%s': %m", slink, node);

        id = udev_device_get_id_filename(dev);
        if (!id)
                return log_debug_errno(ENODEV, "Failed to get device id: %m");

        slink_tmp = strjoina(slink, ".tmp-", id);
        (void) unlink(slink_tmp);

        r = create_symlink(target, slink_tmp);
        if (r < 0)
                return log_debug_errno(r, "Failed to create symlink '%s' to '%s': %m", slink_tmp, target);

        if (rename(slink_tmp, slink) < 0) {
                r = log_debug_errno(errno, "Failed to rename '%s' to '%s': %m", slink_tmp, slink);
                (void) unlink(slink_tmp);
                return r;
        }

        return 0;
}

static int link_find_prioritized(struct udev_device *dev, bool add, const char *stackdir, char **ret) {
        struct udev *udev = udev_device_get_udev(dev);
        _cleanup_closedir_ DIR *dir = NULL;
        _cleanup_free_ char *target = NULL;
        struct dirent *dent;
        int r, priority = 0;
        const char *id;

        assert(dev);
        assert(stackdir);
        assert(ret);

        /* Find device node of device with highest priority. This returns 1 if a device found, 0 if no
         * device found, or a negative errno. */

        if (add) {
                const char *devnode;

                priority = udev_device_get_devlink_priority(dev);

                devnode = udev_device_get_devnode(dev);
                if (!devnode)
                        return -ENOENT;

                target = strdup(devnode);
                if (!target)
                        return -ENOMEM;
        }

        dir = opendir(stackdir);
        if (!dir) {
                if (errno == ENOENT) {
                        *ret = TAKE_PTR(target);
                        return !!*ret;
                }

                return -errno;
        }

        id = udev_device_get_id_filename(dev);
        if (!id)
                return -ENODEV;

        for (dent = readdir(dir); dent; dent = readdir(dir)) {
                _cleanup_free_ char *path = NULL, *buf = NULL;
                int tmp_prio;

                if (dent->d_name[0] == '.')
                        continue;

                /* skip ourself */
                if (streq(dent->d_name, id))
                        continue;

                path = path_join(stackdir, dent->d_name);
                if (!path)
                        return -ENOMEM;

                if (readlink_malloc(path, &buf) >= 0) {
                        char *devnode;

                        /* New format. The devnode and priority can be obtained from symlink. */

                        devnode = strchr(buf, ':');
                        if (!devnode || devnode == buf)
                                continue;

                        *(devnode++) = '\0';
                        if (!path_startswith(devnode, "/dev"))
                                continue;

                        if (safe_atoi(buf, &tmp_prio) < 0)
                                continue;

                        if (target && tmp_prio <= priority)
                                continue;

                        r = free_and_strdup(&target, devnode);
                        if (r < 0)
                                return r;
                } else {
                        _cleanup_udev_device_unref_ struct udev_device *tmp_dev = NULL;
                        const char *devnode;

                        /* Old format. The devnode and priority must be obtained from uevent and
                         * udev database files. */

                        tmp_dev = udev_device_new_from_device_id(udev, dent->d_name);
                        if (!tmp_dev)
                                continue;

                        tmp_prio = udev_device_get_devlink_priority(tmp_dev);

                        if (target && tmp_prio <= priority)
                                continue;

                        devnode = udev_device_get_devnode(tmp_dev);
                        if (!devnode)
                                continue;

                        r = free_and_strdup(&target, devnode);
                        if (r < 0)
                                return r;
                }

                priority = tmp_prio;
        }

        *ret = TAKE_PTR(target);
        return !!*ret;
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

static int update_stack_directory(struct udev_device *dev, const char *dirname, bool add) {
        _cleanup_free_ char *filename = NULL, *data = NULL, *buf = NULL;
        const char *devname, *id;
        int priority, r;

        assert(dev);
        assert(dirname);

        id = udev_device_get_id_filename(dev);
        if (!id)
                return log_debug_errno(ENODEV, "Failed to get device id: %m");

        filename = path_join(dirname, id);
        if (!filename)
                return log_oom();

        if (!add) {
                if (unlink(filename) < 0 && errno != ENOENT)
                        log_debug_errno(errno, "Failed to remove %s, ignoring: %m", filename);

                (void) rmdir(dirname);
                return 0;
        }

        devname = udev_device_get_devnode(dev);
        if (!devname)
                return log_debug_errno(ENOENT, "Failed to get device node: %m");

        priority = udev_device_get_devlink_priority(dev);

        if (asprintf(&data, "%i:%s", priority, devname) < 0)
                return log_oom();

        if (readlink_malloc(filename, &buf) >= 0 && streq(buf, data))
                return 0;

        if (unlink(filename) < 0 && errno != ENOENT)
                log_debug_errno(errno, "Failed to remove %s, ignoring: %m", filename);

        for (unsigned j = 0; j < CREATE_STACK_LINK_MAX_RETRIES; j++) {
                /* This may fail with -ENOENT when the parent directory is removed during
                 * creating the file by another udevd worker. */
                r = udev_mkdir_p(dirname, 0755);
                if (r == -ENOENT)
                        continue;
                if (r < 0)
                        return log_debug_errno(r, "Failed to create directory %s: %m", dirname);

                if (symlink(data, filename) < 0) {
                        if (errno == ENOENT)
                                continue;
                        return log_debug_errno(errno, "Failed to create symbolic link %s: %m", filename);
                }

                return 0;
        }

        return log_debug_errno(ELOOP, "Failed to create symbolic link %s: %m", filename);
}

/* manage "stack of names" with possibly specified device priorities */
static int link_update(struct udev_device *dev, const char *slink_in, bool add) {
        _cleanup_free_ char *slink = NULL, *dirname = NULL, *target = NULL;
        const char *slink_name;
        char name_enc[NAME_MAX+1];
        int r;

        assert(dev);
        assert(slink_in);

        slink = strdup(slink_in);
        if (!slink)
                return log_oom();

        path_simplify(slink);

        slink_name = path_startswith(slink, "/dev");
        if (!slink_name ||
            empty_or_root(slink_name) ||
            !path_is_normalized(slink_name)) {
                log_debug("Invalid symbolic link of device node: %s", slink);
                return -EINVAL;
        }

        /* The name of the stack directory is the escaped path below /dev including its leading
         * slash, e.g. \x2fdisk\x2fby-id\x2f..., as eudev has always named it. */
        (void) udev_node_escape_path(strjoina("/", slink_name), name_enc, sizeof(name_enc));
        dirname = path_join(UDEV_ROOT_RUN "/udev/links", name_enc);
        if (!dirname)
                return log_oom();

        r = update_stack_directory(dev, dirname, add);
        if (r < 0)
                return r;

        r = link_find_prioritized(dev, add, dirname, &target);
        if (r < 0)
                return log_debug_errno(r, "Failed to determine highest priority for symlink '%s': %m", slink);
        if (r == 0) {
                log_debug("No reference left for '%s', removing", slink);

                if (unlink(slink) < 0 && errno != ENOENT)
                        log_debug_errno(errno, "Failed to remove '%s', ignoring: %m", slink);

                (void) rmdir_parents(slink, "/dev");
                return 0;
        }

        return node_symlink(dev, target, slink);
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
        const char *devnode;
        int r;

        assert(dev);

        devnode = udev_device_get_devnode(dev);
        if (!devnode)
                return log_debug_errno(ENOENT, "Failed to get devnode: %m");

        log_debug("Handling device node '%s', devnum=%s", devnode, udev_device_get_id_filename(dev) ?: "n/a");

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
        r = node_symlink(dev, devnode, filename);
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
        if (unlink(filename) < 0 && errno != ENOENT)
                return log_debug_errno(errno, "Failed to remove '%s': %m", filename);

        return 0;
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
