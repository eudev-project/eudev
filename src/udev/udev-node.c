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
#include "siphash24.h"
#include "udev.h"
#include "smack-util.h"
#include "unaligned.h"

#define UDEV_NODE_HASH_KEY ((const uint8_t[16]) { 0xb9, 0x6a, 0xf1, 0xce, 0x40, 0x31, 0x44, 0x1a, \
                                                   0x9e, 0x19, 0xec, 0x8b, 0xae, 0xf3, 0xe3, 0x2f })

static int node_symlink(struct udev_device *dev, const char *node, const char *slink) {
        struct stat stats;
        char target[UTIL_PATH_SIZE];
        char *s;
        size_t l;
        char slink_tmp[UTIL_PATH_SIZE + 32];
        int i = 0;
        int tail = 0;
        int err = 0;

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
        if (l == 0) {
                err = -EINVAL;
                goto exit;
        }

        if (lstat(slink, &stats) == 0) {
                char buf[UTIL_PATH_SIZE];
                int len;

                if (!S_ISLNK(stats.st_mode)) {
                        log_debug("Conflicting inode '%s' found, link to '%s' will not be created.", slink, node);
                        err = -EEXIST;
                        goto exit;
                }

                len = readlink(slink, buf, sizeof(buf));
                if (len > 0 && len < (int)sizeof(buf)) {
                        buf[len] = '\0';
                        if (streq(target, buf)) {
                                /* preserve link with correct target, do not replace node of other device */
                                log_debug("preserve already existing symlink '%s' to '%s'", slink, target);
                                label_fix(slink, true, false);
                                utimensat(AT_FDCWD, slink, NULL, AT_SYMLINK_NOFOLLOW);
                                goto exit;
                        }
                }
        } else {
                log_debug("creating symlink '%s' to '%s'", slink, target);
                do {
                        err = mkdir_parents_label(slink, 0755);
                        if (err != 0 && err != -ENOENT)
                                break;
                        mac_selinux_create_file_prepare(slink, S_IFLNK);
                        err = symlink(target, slink);
                        if (err != 0)
                                err = -errno;
                        mac_selinux_create_file_clear();
                } while (err == -ENOENT);
                if (err == 0)
                        goto exit;
        }

        log_debug("atomically replace '%s'", slink);
        strscpyl(slink_tmp, sizeof(slink_tmp), slink, ".tmp-", udev_device_get_id_filename(dev), NULL);
        unlink(slink_tmp);
        do {
                err = mkdir_parents_label(slink_tmp, 0755);
                if (err != 0 && err != -ENOENT)
                        break;
                mac_selinux_create_file_prepare(slink_tmp, S_IFLNK);
                err = symlink(target, slink_tmp);
                if (err != 0)
                        err = -errno;
                mac_selinux_create_file_clear();
        } while (err == -ENOENT);
        if (err != 0) {
                log_error_errno(errno, "symlink '%s' '%s' failed: %m", target, slink_tmp);
                goto exit;
        }
        err = rename(slink_tmp, slink);
        if (err != 0) {
                log_error_errno(errno, "rename '%s' '%s' failed: %m", slink_tmp, slink);
                unlink(slink_tmp);
        }
exit:
        return err;
}

/* find device node of device with highest priority */
static const char *link_find_prioritized(struct udev_device *dev, bool add, const char *stackdir, char *buf, size_t bufsize) {
        struct udev *udev = udev_device_get_udev(dev);
        DIR *dir;
        int priority = 0;
        const char *target = NULL;

        if (add) {
                priority = udev_device_get_devlink_priority(dev);
                strscpy(buf, bufsize, udev_device_get_devnode(dev));
                target = buf;
        }

        dir = opendir(stackdir);
        if (dir == NULL)
                return target;
        for (;;) {
                struct udev_device *dev_db;
                struct dirent *dent;

                dent = readdir(dir);
                if (dent == NULL || dent->d_name[0] == '\0')
                        break;
                if (dent->d_name[0] == '.')
                        continue;

                log_debug("found '%s' claiming '%s'", dent->d_name, stackdir);

                /* did we find ourself? */
                if (streq(dent->d_name, udev_device_get_id_filename(dev)))
                        continue;

                dev_db = udev_device_new_from_device_id(udev, dent->d_name);
                if (dev_db != NULL) {
                        const char *devnode;

                        devnode = udev_device_get_devnode(dev_db);
                        if (devnode != NULL) {
                                if (target == NULL || udev_device_get_devlink_priority(dev_db) > priority) {
                                        log_debug("'%s' claims priority %i for '%s'",
                                                  udev_device_get_syspath(dev_db), udev_device_get_devlink_priority(dev_db), stackdir);
                                        priority = udev_device_get_devlink_priority(dev_db);
                                        strscpy(buf, bufsize, devnode);
                                        target = buf;
                                }
                        }
                        udev_device_unref(dev_db);
                }
        }
        closedir(dir);
        return target;
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

/* manage "stack of names" with possibly specified device priorities */
static int link_update(struct udev_device *dev, const char *slink_in, bool add) {
        _cleanup_free_ char *slink = NULL;
        char name_enc[NAME_MAX+1];
        char filename[UTIL_PATH_SIZE * 2];
        char dirname[UTIL_PATH_SIZE];
        const char *slink_name, *target;
        char buf[UTIL_PATH_SIZE];
        int r = 0;

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
        strscpyl(dirname, sizeof(dirname), UDEV_ROOT_RUN "/udev/links/", name_enc, NULL);
        strscpyl(filename, sizeof(filename), dirname, "/", udev_device_get_id_filename(dev), NULL);

        if (!add && unlink(filename) == 0)
                rmdir(dirname);

        target = link_find_prioritized(dev, add, dirname, buf, sizeof(buf));
        if (target == NULL) {
                log_debug("no reference left, remove '%s'", slink);
                if (unlink(slink) == 0)
                        rmdir_parents(slink, "/dev");
        } else {
                log_debug("creating link '%s' to '%s'", slink, target);
                r = node_symlink(dev, target, slink);
        }

        if (add) {
                int err;

                do {
                        int fd;

                        err = mkdir_parents(filename, 0755);
                        if (err != 0 && err != -ENOENT)
                                break;
                        fd = open(filename, O_WRONLY|O_CREAT|O_CLOEXEC|O_TRUNC|O_NOFOLLOW, 0444);
                        if (fd >= 0)
                                close(fd);
                        else
                                err = -errno;
                } while (err == -ENOENT);
        }

        return r;
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

int udev_node_apply_permissions(struct udev_device *dev, bool apply_mac,
                                mode_t mode, uid_t uid, gid_t gid,
                                struct udev_list *seclabel_list) {
        const char *devnode = udev_device_get_devnode(dev);
        dev_t devnum = udev_device_get_devnum(dev);
        bool apply_mode, apply_uid, apply_gid;
        _cleanup_close_ int node_fd = -1;
        struct stat stats;
        struct udev_list_entry *entry;
        int r;

        if (streq(udev_device_get_subsystem(dev), "block"))
                mode |= S_IFBLK;
        else
                mode |= S_IFCHR;

        node_fd = open(devnode, O_PATH|O_NOFOLLOW|O_CLOEXEC);
        if (node_fd < 0) {
                if (errno == ENOENT) {
                        log_debug_errno(errno, "Device node %s is missing, skipping handling.", devnode);
                        return 0; /* This is necessarily racey, so ignore missing the device */
                }

                return log_debug_errno(errno, "Cannot open node %s: %m", devnode);
        }

        if (fstat(node_fd, &stats) < 0)
                return log_debug_errno(errno, "cannot stat() node %s: %m", devnode);

        if ((mode != MODE_INVALID && (stats.st_mode & S_IFMT) != (mode & S_IFMT)) || stats.st_rdev != devnum) {
                log_debug("Found node '%s' with non-matching devnum %s, skipping handling.",
                          devnode, udev_device_get_id_filename(dev));
                return 0; /* We might process a device that already got replaced by the time we have a look
                           * at it, handle this gracefully and step away. */
        }

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
                udev_list_entry_foreach(entry, udev_list_get_entry(seclabel_list)) {
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
