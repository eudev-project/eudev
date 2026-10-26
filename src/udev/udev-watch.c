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
#include <limits.h>
#include <stdio.h>
#include <dirent.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include "udev.h"
#include "mkdir.h"
#include "set.h"
#include "strv.h"

#define WATCH_DIR UDEV_ROOT_RUN "/udev/watch"

/* The suffix of the name of the symlink wd -> ID of a watch handle that udev_watch_suspend() removed: it is kept
 * until udevd handles IN_IGNORED of the watch handle, see udev_watch_ignored(). */
#define REMOVED_SUFFIX ".removed"
#define REMOVED_NAME_MAX (DECIMAL_STR_MAX(int) + STRLEN(REMOVED_SUFFIX))

/* Reads the symlink name in dirfd, a watch handle or an ID, into buf (size n). */
static int read_link(int dirfd, const char *name, char *buf, size_t n) {
        ssize_t len;

        len = readlinkat(dirfd, name, buf, n);
        if (len < 0)
                return -errno;
        if ((size_t) len >= n)
                return -EINVAL;
        buf[len] = '\0';
        return 0;
}

/* Whether the symlink ID -> wd of the device id in dirfd points to the watch handle wd, i.e. a removed watch
 * handle wd is the one of an event that a worker is processing, see udev_watch_suspend(). */
static bool watch_handle_is_current(int dirfd, const char *id, int wd) {
        char wd_str[DECIMAL_STR_MAX(int)];
        int w;

        return read_link(dirfd, id, wd_str, sizeof(wd_str)) >= 0 && safe_atoi(wd_str, &w) >= 0 && w == wd;
}

static int inotify_fd = -1;

/* The watch directory of this udevd, which it creates and opens when it starts, see udev_watch_restore(), and again
 * when it was removed or replaced while udevd runs, see udev_watch_check_dir(); the workers have it from udevd, and use
 * the new one then, see watch_dir_get(). A worker of an udevd that exited, e.g. one that could not be killed when udevd
 * was restarted, does not change the watch directory, and as it has the directory of that udevd, which the new one
 * renamed, empties and removes, it cannot change the new one either. */
static int watch_dirfd = -1;

/* The inotify watch of the parent directory of the watch directory, so that udevd wakes up when the watch directory
 * is removed or moved, see udev_watch_check_dir(). The IN_DELETE_SELF of a watch of the watch directory itself would
 * come only once no process has the directory open anymore. */
static int watch_parent_wd = -1;

/* the main process of udevd, see udev_watch_restore() */
static pid_t watch_main_pid = 0;

/* udevd: whether it cannot create the watch directory, so that it logs that at warning level only once, see
 * udev_watch_check_dir() */
static bool watch_dir_failing = false;

/* The device and inode number of the watch directory of udevd, in memory that it shares with its workers, so that a
 * worker can tell the directory that udevd created again from one that another process created, see watch_dir_get();
 * seq is odd while udevd changes them. */
struct watch_dir_identity {
        unsigned seq;
        volatile dev_t dev;
        volatile ino_t ino;
};
static struct watch_dir_identity *watch_dir_shared = NULL;

/* After an overflow of the inotify queue, see udev_watch_overflow(): the names and targets of the symlinks <wd>.removed
 * whose watch handles were freed already, so that their IN_IGNORED was queued, or lost in the overflow, and the
 * watch handle of the barrier, whose IN_IGNORED tells that the ones that were queued were read. */
static char **overflow_links = NULL;
static int barrier_wd = -1;

/* At most this many watch handles are tried for a watch, and this many times a watch is added when the device node is
 * replaced meanwhile, see udev_watch_begin() */
#define WATCH_HANDLE_TRIES 16
#define WATCH_NODE_TRIES 4

/* At most this many times the watch directory of an earlier start of udevd is emptied, see watch_dir_drain() */
#define WATCH_DRAIN_PASSES 16

/* inotify descriptor, will be shared with rules directory;
 * set to cloexec since we need our children to be able to add
 * watches for us; returns it, or a negative errno after logging
 * the error, like manager_init_inotify() of systemd v261
 */
int udev_watch_init(struct udev *udev __attribute__((unused))) {
        int fd;

        fd = inotify_init1(IN_CLOEXEC);
        if (fd < 0)
                return log_error_errno(errno, "Failed to create inotify descriptor: %m");

        inotify_fd = fd;
        return fd;
}

/* Reads the watch handles of the inotify instance that are not removed, from /proc/self/fdinfo/, into *ret. */
static int read_watch_handles(Set **ret) {
        char path[STRLEN("/proc/self/fdinfo/") + DECIMAL_STR_MAX(int)];
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_set_free_ Set *handles = NULL;
        char line[LINE_MAX];
        int r;

        xsprintf(path, "/proc/self/fdinfo/%d", inotify_fd);
        f = fopen(path, "re");
        if (!f)
                return -errno;

        r = set_ensure_allocated(&handles, NULL);
        if (r < 0)
                return r;

        while (fgets(line, sizeof(line), f)) {
                unsigned long wd;
                char *end;

                if (!startswith(line, "inotify wd:"))
                        continue;

                errno = 0;
                wd = strtoul(line + STRLEN("inotify wd:"), &end, 16);
                if (errno != 0 || end == line + STRLEN("inotify wd:") || *end != ' ' || wd > INT_MAX)
                        return -EBADMSG;

                r = set_put(handles, UINT_TO_PTR((unsigned) wd));
                if (r < 0)
                        return r;
        }

        if (ferror(f))
                return -EIO;

        *ret = TAKE_PTR(handles);
        return 0;
}

/* Whether this process is a worker of an udevd that exited, e.g. one that could not be killed when udevd was restarted.
 * A parent PID of 0 means that udevd is in another PID namespace. */
static bool watch_main_exited(void) {
        pid_t ppid;

        if (watch_main_pid <= 0 || getpid() == watch_main_pid)
                return false;

        ppid = getppid();
        return ppid != 0 && ppid != watch_main_pid;
}

/* udevd: stores the identity of watch_dirfd in the memory shared with the workers */
static void watch_dir_publish(void) {
        struct stat st;

        if (!watch_dir_shared || watch_dirfd < 0 || fstat(watch_dirfd, &st) < 0)
                return;

        __atomic_add_fetch(&watch_dir_shared->seq, 1, __ATOMIC_SEQ_CST);
        watch_dir_shared->dev = st.st_dev;
        watch_dir_shared->ino = st.st_ino;
        __atomic_add_fetch(&watch_dir_shared->seq, 1, __ATOMIC_SEQ_CST);
}

/* a worker: reads the identity of the watch directory of udevd from the memory shared with it */
static bool watch_dir_published(dev_t *ret_dev, ino_t *ret_ino) {
        unsigned i, seq;

        for (i = 0; i < 1000; i++) {
                seq = __atomic_load_n(&watch_dir_shared->seq, __ATOMIC_SEQ_CST);
                if (seq & 1)
                        continue;

                *ret_dev = watch_dir_shared->dev;
                *ret_ino = watch_dir_shared->ino;
                __atomic_thread_fence(__ATOMIC_SEQ_CST);
                if (__atomic_load_n(&watch_dir_shared->seq, __ATOMIC_SEQ_CST) == seq)
                        return true;
        }

        return false;
}

/* The watch directory for a change of the watch of the device node devnode, or -1. udevd itself uses its directory. A
 * worker gets -1 when udevd exited, e.g. as it was restarted, while the worker could not be killed, so that it does not
 * change the directory of the new udevd, logged at debug level. When udevd created the directory again, as it was
 * removed or replaced, see udev_watch_check_dir(), the worker uses the new one; when the directory was removed, and
 * udevd did not create it again yet, it waits up to a second for that, and gets -1 then, like when udevd has no watch
 * directory, as it cannot create it: when the device is not watched then (watching), that is logged at warning level
 * once, and then at debug level, until the worker has a watch directory again, like udevd logs that it cannot create
 * it, see udev_watch_check_dir(). Without the memory shared with udevd, the worker uses its directory only while it is
 * the watch directory, and udevd restarts the workers when it creates the directory again. */
static int watch_dir_get(const char *devnode, bool watching) {
        /* the identity of a removed directory that the worker waited for in vain, so that it does not wait again */
        static dev_t waited_dev = 0;
        static ino_t waited_ino = 0;
        /* whether the worker logged at warning level that it has no watch directory, see above */
        static bool warned = false;
        _cleanup_free_ char *lesc1 = NULL;
        const char *what = watching ? "not watching" : "not changing the watch of";
        struct stat a, b;
        dev_t dev = 0;
        ino_t ino = 0;
        unsigned i;
        int level;

        if (watch_main_pid <= 0 || getpid() == watch_main_pid)
                return watch_dirfd;

        if (watch_main_exited()) {
                log_debug("udevd ["PID_FMT"] that started this process exited, e.g. as udevd was restarted, %s device node '%s'",
                          watch_main_pid, what, utf8_escape_for_log(devnode, &lesc1));
                return -1;
        }

        for (i = 0; i < 100; i++) {
                bool have;
                int fd;

                if (i > 0)
                        (void) usleep(10 * USEC_PER_MSEC);

                have = watch_dirfd >= 0 && fstat(watch_dirfd, &a) >= 0;

                if (!watch_dir_shared) {
                        if (have && a.st_nlink > 0 && stat(WATCH_DIR, &b) >= 0 &&
                            a.st_dev == b.st_dev && a.st_ino == b.st_ino) {
                                warned = false;
                                return watch_dirfd;
                        }
                        break;
                }

                if (!watch_dir_published(&dev, &ino))
                        continue;
                if (dev == 0 && ino == 0)
                        break; /* udevd has no watch directory */

                if (have && a.st_dev == dev && a.st_ino == ino) {
                        if (a.st_nlink > 0) {
                                warned = false;
                                return watch_dirfd;
                        }
                        /* removed, and udevd did not create it again yet */
                        if ((dev == waited_dev && ino == waited_ino) || watch_main_exited())
                                break;
                        continue;
                }

                /* udevd created it again */
                fd = open(WATCH_DIR, O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW | O_RDONLY);
                if (fd < 0)
                        continue;
                if (fstat(fd, &b) >= 0 && b.st_dev == dev && b.st_ino == ino) {
                        log_debug("using the watch directory " WATCH_DIR " that udevd created again");
                        safe_close(watch_dirfd);
                        watch_dirfd = fd;
                        warned = false;
                        return watch_dirfd;
                }
                safe_close(fd);
        }

        waited_dev = dev;
        waited_ino = ino;

        level = watching && !warned && !watch_main_exited() ? LOG_WARNING : LOG_DEBUG;
        if (level == LOG_WARNING)
                warned = true;
        if (watch_dir_shared && dev == 0 && ino == 0)
                log_full(level, "udevd has no watch directory " WATCH_DIR ", e.g. as it cannot create it, %s device node '%s'",
                         what, utf8_escape_for_log(devnode, &lesc1));
        else
                log_full(level, "The watch directory " WATCH_DIR " of udevd was removed or replaced, %s device node '%s'",
                         what, utf8_escape_for_log(devnode, &lesc1));
        return -1;
}

/* Removes the entries of the watch directory path of an earlier start of udevd. If ids is not NULL, the IDs of the
 * devices whose watches are to be restored are added to *ids: like systemd, the devices with a symlink ID -> wd, also
 * when the symlink wd -> ID does not exist, as the event of the device was being processed, see udev_watch_suspend(),
 * and for backward compatibility the ones with a symlink wd -> ID of an old layout without symlinks ID -> wd; the
 * symlinks <wd>.removed of watches that were removed are not used. If remove is true, the directory is removed then:
 * as a worker of that udevd that still processes an event may add entries meanwhile, until it notices that udevd
 * exited, see watch_dir_get(), the directory is emptied again then, a few times; once it is removed, nothing can be
 * added to it anymore. */
static void watch_dir_drain(const char *path, Set **ids, bool remove) {
        int pass;

        for (pass = 1;; pass++) {
                _cleanup_closedir_ DIR *dir = NULL;
                struct dirent *ent;
                int dfd;

                dir = opendir(path);
                if (!dir) {
                        if (errno != ENOENT)
                                log_error_errno(errno, "Failed to open %s, old watches will not be restored: %m", path);
                        return;
                }
                dfd = dirfd(dir);
                assert(dfd >= 0);

                for (ent = readdir(dir); ent != NULL; ent = readdir(dir)) {
                        char device[UTIL_PATH_SIZE] = "";
                        int wd;

                        if (ent->d_name[0] == '.')
                                continue;

                        if (ids && !endswith(ent->d_name, REMOVED_SUFFIX)) {
                                if (safe_atoi(ent->d_name, &wd) >= 0) {
                                        if (read_link(dfd, ent->d_name, device, sizeof(device)) < 0)
                                                device[0] = '\0';
                                } else if (strlen(ent->d_name) < sizeof(device))
                                        strcpy(device, ent->d_name);

                                if (device[0] != '\0' &&
                                    (set_ensure_allocated(ids, &string_hash_ops) < 0 || set_put_strdup(*ids, device) < 0))
                                        log_oom();
                        }

                        (void) unlinkat(dfd, ent->d_name, 0);
                }

                if (!remove || rmdir(path) >= 0 || errno == ENOENT)
                        return;

                if (!IN_SET(errno, ENOTEMPTY, EEXIST) || pass >= WATCH_DRAIN_PASSES) {
                        log_warning_errno(errno, "Failed to remove %s, ignoring: %m", path);
                        return;
                }

                log_debug("Entries were added to %s meanwhile, emptying it again", path);
        }
}

/* Creates the watch directory, unless it exists, and opens it; returns the descriptor, or -1 after logging at level. */
static int watch_dir_open(int level) {
        int fd, r;

        r = udev_mkdir_p(WATCH_DIR, 0755);
        if (r < 0) {
                log_full_errno(level, r, "Failed to create " WATCH_DIR ": %m");
                return -1;
        }

        fd = open(WATCH_DIR, O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW | O_RDONLY);
        if (fd < 0)
                log_full_errno(level, errno, "Failed to open " WATCH_DIR ": %m");
        return fd;
}

/* Watches the parent directory of the watch directory with the inotify descriptor, so that udevd wakes up when the
 * watch directory is removed or moved, see udev_watch_check_dir(). */
static void watch_dir_watch(void) {
        if (watch_parent_wd >= 0)
                (void) inotify_rm_watch(inotify_fd, watch_parent_wd);

        watch_parent_wd = inotify_add_watch(inotify_fd, UDEV_ROOT_RUN "/udev", IN_DELETE | IN_MOVED_FROM | IN_ONLYDIR | IN_DONT_FOLLOW);
        if (watch_parent_wd < 0)
                log_debug_errno(errno, "Failed to watch " UDEV_ROOT_RUN "/udev, ignoring: %m");
}

/* Moves the watch directory of an earlier start of udevd out of the way, creates and opens a new one, and restores
 * the watches of the old one, see watch_dir_drain(). */
void udev_watch_restore(struct udev *udev) {
        _cleanup_free_ char *lesc1 = NULL;
        _cleanup_set_free_free_ Set *ids = NULL;
        bool moved = false, in_place = false;
        Iterator i;
        char *id;

        if (inotify_fd < 0)
                return;

        watch_main_pid = getpid();
        if (!watch_dir_shared) {
                void *p = mmap(NULL, sizeof(struct watch_dir_identity), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);

                if (p == MAP_FAILED)
                        log_debug_errno(errno, "Failed to map memory to share the watch directory with the workers, ignoring: %m");
                else
                        watch_dir_shared = p;
        }

        /* the one of an earlier start that could not be removed, see watch_dir_drain(); its watches were restored */
        watch_dir_drain(WATCH_DIR ".old", NULL, true);

        if (rename(WATCH_DIR, WATCH_DIR ".old") >= 0)
                moved = true;
        else if (errno != ENOENT) {
                log_error_errno(errno, "unable to move watches dir " WATCH_DIR "; old watches are restored from it in place: %m");
                in_place = true;
        }

        watch_dirfd = watch_dir_open(LOG_ERR);
        if (watch_dirfd >= 0) {
                watch_dir_watch();
                watch_dir_publish();
        } else
                watch_dir_failing = true;

        if (moved)
                watch_dir_drain(WATCH_DIR ".old", &ids, true);
        else if (in_place)
                watch_dir_drain(WATCH_DIR, &ids, false);

        SET_FOREACH(id, ids, i) {
                struct udev_device *dev;

                dev = udev_device_new_from_device_id(udev, id);
                if (dev == NULL)
                        continue;

                log_debug("restoring old watch on '%s'",
                          utf8_escape_for_log(udev_device_get_devnode(dev), &lesc1));
                udev_watch_begin(udev, dev);
                udev_device_unref(dev);
        }
}

/* A watch of the inotify instance, with the device and inode number of what it watches, see read_watch_inodes() */
struct watch_inode {
        int wd;
        dev_t dev;
        ino_t ino;
};

/* Reads the watches of the inotify instance, with the device and inode number of what they watch, from
 * /proc/self/fdinfo/; the kernel prints the device number in its internal encoding. */
static int read_watch_inodes(struct watch_inode **ret, size_t *ret_n) {
        char path[STRLEN("/proc/self/fdinfo/") + DECIMAL_STR_MAX(int)];
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ struct watch_inode *w = NULL;
        size_t n = 0, allocated = 0;
        char line[LINE_MAX];

        xsprintf(path, "/proc/self/fdinfo/%d", inotify_fd);
        f = fopen(path, "re");
        if (!f)
                return -errno;

        while (fgets(line, sizeof(line), f)) {
                unsigned wd, sdev;
                unsigned long ino;

                if (sscanf(line, "inotify wd:%x ino:%lx sdev:%x", &wd, &ino, &sdev) != 3)
                        continue;

                if (!GREEDY_REALLOC(w, allocated, n + 1))
                        return -ENOMEM;

                w[n++] = (struct watch_inode) {
                        .wd = (int) wd,
                        .dev = makedev(sdev >> 20, sdev & 0xfffff),
                        .ino = (ino_t) ino,
                };
        }

        if (ferror(f))
                return -EIO;

        *ret = TAKE_PTR(w);
        *ret_n = n;
        return 0;
}

/* the symlinks of the watch handle wd of the device with the device number devnum, see watch_dir_recover() */
static void watch_dir_recover_one(struct udev *udev, int dirfd, int wd, char type, dev_t devnum) {
        _cleanup_free_ char *lesc1 = NULL;
        char wd_str[DECIMAL_STR_MAX(int)];
        struct udev_device *dev;
        const char *id;

        dev = udev_device_new_from_devnum(udev, type, devnum);
        if (!dev)
                return;

        id = udev_device_get_id_filename(dev);
        if (id) {
                xsprintf(wd_str, "%d", wd);
                if ((symlinkat(wd_str, dirfd, id) < 0 && errno != EEXIST) ||
                    (symlinkat(id, dirfd, wd_str) < 0 && errno != EEXIST))
                        log_debug_errno(errno, "Failed to create the symlinks of watch handle %i of device node '%s' again, ignoring: %m",
                                        wd, utf8_escape_for_log(udev_device_get_devnode(dev), &lesc1));
                else
                        log_debug("created the symlinks of watch handle %i of device node '%s' again",
                                  wd, utf8_escape_for_log(udev_device_get_devnode(dev), &lesc1));
        }

        udev_device_unref(dev);
}

/* the device nodes in the directory fd (taken) and its subdirectories on the same file system, see
 * watch_dir_recover() */
static void watch_dir_recover_scan(struct udev *udev, int wdirfd, int fd, dev_t fs, unsigned depth,
                                   const struct watch_inode *w, size_t n) {
        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *ent;
        int dfd;

        d = fdopendir(fd);
        if (!d) {
                safe_close(fd);
                return;
        }
        dfd = dirfd(d);
        assert(dfd >= 0);

        for (ent = readdir(d); ent != NULL; ent = readdir(d)) {
                struct stat st;
                size_t i;

                if (streq(ent->d_name, ".") || streq(ent->d_name, ".."))
                        continue;

                if (fstatat(dfd, ent->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0)
                        continue;

                if (S_ISDIR(st.st_mode)) {
                        int sub;

                        if (depth >= 8 || st.st_dev != fs)
                                continue;

                        sub = openat(dfd, ent->d_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
                        if (sub >= 0)
                                watch_dir_recover_scan(udev, wdirfd, sub, fs, depth + 1, w, n);
                        continue;
                }

                if (!S_ISBLK(st.st_mode) && !S_ISCHR(st.st_mode))
                        continue;

                for (i = 0; i < n; i++)
                        if (w[i].dev == st.st_dev && w[i].ino == st.st_ino)
                                watch_dir_recover_one(udev, wdirfd, w[i].wd, S_ISBLK(st.st_mode) ? 'b' : 'c',
                                                      st.st_rdev);
        }
}

/* After the watch directory was created again, see udev_watch_check_dir(): creates the symlinks of the watches that the
 * inotify instance still has in it again, for the device nodes under /dev whose inodes they watch, which the fdinfo of
 * the inotify instance tells. Without the fdinfo, a device is watched again with its next event. */
static void watch_dir_recover(struct udev *udev, int dirfd) {
        _cleanup_free_ struct watch_inode *w = NULL;
        struct stat st;
        size_t n = 0;
        int fd, r;

        r = read_watch_inodes(&w, &n);
        if (r < 0) {
                log_debug_errno(r, "Failed to read the watches of the inotify instance, not creating their symlinks again: %m");
                return;
        }
        if (n == 0)
                return;

        fd = open("/dev", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd < 0)
                return;
        if (fstat(fd, &st) < 0) {
                safe_close(fd);
                return;
        }

        watch_dir_recover_scan(udev, dirfd, fd, st.st_dev, 0, w, n);
}

/* Called by udevd in each iteration of its main loop: when the watch directory was removed or replaced while udevd
 * runs, e.g. with "rm -rf /run/udev", it is created again, a directory that another process put there moved out of
 * the way and emptied first, the symlinks of the watches that the inotify instance still has are created in it again,
 * see watch_dir_recover(), and the workers use it then, see watch_dir_get(). Returns 1 when the workers have to be
 * restarted to use it, without the memory shared with them. */
int udev_watch_check_dir(struct udev *udev) {
        struct stat a, b;
        int fd, level;

        if (inotify_fd < 0 || watch_main_pid != getpid())
                return 0;

        if (watch_dirfd >= 0 && fstat(watch_dirfd, &a) >= 0 && a.st_nlink > 0 && lstat(WATCH_DIR, &b) >= 0 &&
            a.st_dev == b.st_dev && a.st_ino == b.st_ino)
                return 0;

        /* at warning level once, then at debug level while it cannot be created */
        level = watch_dir_failing ? LOG_DEBUG : LOG_WARNING;
        if (watch_dirfd >= 0)
                log_full(level, "The watch directory " WATCH_DIR " was removed or replaced, creating it again");
        else
                log_full(level, "udevd has no watch directory " WATCH_DIR ", creating it");

        if (lstat(WATCH_DIR, &b) >= 0) {
                watch_dir_drain(WATCH_DIR ".old", NULL, true);
                if (rename(WATCH_DIR, WATCH_DIR ".old") >= 0)
                        watch_dir_drain(WATCH_DIR ".old", NULL, true);
                else
                        watch_dir_drain(WATCH_DIR, NULL, false);
        }

        fd = watch_dir_open(level);
        if (fd < 0) {
                watch_dir_failing = true;
                return 0;
        }
        if (watch_dir_failing)
                log_info("Created the watch directory " WATCH_DIR);
        watch_dir_failing = false;

        watch_dir_recover(udev, fd);

        safe_close(watch_dirfd);
        watch_dirfd = fd;
        watch_dir_watch();
        watch_dir_publish();

        return watch_dir_shared ? 0 : 1;
}

static int udev_watch_clear(struct udev_device *dev, int dirfd, int *ret_wd) {
        _cleanup_free_ char *lesc1 = NULL, *lesc2 = NULL;
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
                log_debug_errno(r, "Failed to read symlink '" WATCH_DIR "/%s': %m", utf8_escape_for_log(id, &lesc1));
                goto finalize;
        }
        if ((size_t) len >= sizeof(wd_str)) {
                r = -EINVAL;
                log_debug_errno(r, "Invalid symlink '" WATCH_DIR "/%s'.", utf8_escape_for_log(id, &lesc1));
                goto finalize;
        }
        wd_str[len] = '\0';

        r = safe_atoi(wd_str, &wd);
        if (r < 0) {
                log_debug_errno(r, "Failed to parse watch handle from symlink '" WATCH_DIR "/%s': %m",
                                utf8_escape_for_log(id, &lesc1));
                goto finalize;
        }

        if (wd < 0) {
                r = -EBADF;
                log_debug_errno(r, "Invalid watch handle %i.", wd);
                goto finalize;
        }

        /* 2. read symlink wd -> ID */
        len = readlinkat(dirfd, wd_str, buf, sizeof(buf));
        if (len < 0 && errno == ENOENT) {
                char removed[REMOVED_NAME_MAX];

                /* The watch handle was removed by udev_watch_suspend(), and udevd removes its symlink wd -> ID
                 * when it handles IN_IGNORED of it, or did already; only the symlink ID -> wd is removed here. */
                xsprintf(removed, "%s" REMOVED_SUFFIX, wd_str);
                r = read_link(dirfd, removed, buf, sizeof(buf));
                if (r == -ENOENT || (r >= 0 && streq(buf, id))) {
                        if (ret_wd)
                                *ret_wd = -1;
                        r = 0;
                        goto finalize;
                }
                errno = ENOENT;
        }
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
                log_debug_errno(r, "Symlink '" WATCH_DIR "/%s' is owned by another device '%s'.",
                                wd_str, utf8_escape_for_log(buf, &lesc2));
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
                log_debug_errno(errno, "Failed to remove '" WATCH_DIR "/%s': %m", utf8_escape_for_log(id, &lesc1));

        return r;
}

/* The symlink wd -> ID of a watch handle that the kernel allocated again, while the symlink of its old watch was not
 * removed, e.g. as the kernel removed the old watch with the device node, but no 'remove' event of the device was
 * processed: udev_watch_begin() removed its new watch of the handle again, so that no watch has the handle anymore,
 * which the fdinfo of the inotify instance confirms, and no worker can be creating the symlink of a watch with it.
 * The symlink is removed, if it still points to id. Without the watch handles in the fdinfo, only when the symlink
 * ID -> wd of the device does not point to the handle, like in udev_watch_overflow(). */
static void watch_remove_stale_symlink(int dirfd, int wd, const char *id) {
        _cleanup_free_ char *lesc1 = NULL;
        _cleanup_set_free_ Set *handles = NULL;
        char wd_str[DECIMAL_STR_MAX(int)];
        char buf[UTIL_PATH_SIZE];

        if (read_watch_handles(&handles) >= 0 && !set_isempty(handles)) {
                if (set_contains(handles, UINT_TO_PTR((unsigned) wd)))
                        return;
        } else if (watch_handle_is_current(dirfd, id, wd))
                return;

        xsprintf(wd_str, "%d", wd);
        if (read_link(dirfd, wd_str, buf, sizeof(buf)) < 0 || !streq(buf, id))
                return;

        if (unlinkat(dirfd, wd_str, 0) < 0)
                log_debug_errno(errno, "Failed to remove stale symlink '" WATCH_DIR "/%s', ignoring: %m", wd_str);
        else
                log_debug("removed stale symlink '" WATCH_DIR "/%s' to '%s', no watch has the handle",
                          wd_str, utf8_escape_for_log(id, &lesc1));
}

/* Steps 2 to 4 of udev_watch_begin(). Returns 0 when the device node is watched, 1 when it does not exist (anymore),
 * -ESTALE when it was replaced or removed meanwhile, -EBUSY when no watch handle without a symlink of another watch
 * was found, or another negative errno; the details are logged at debug level. */
static int watch_add(int dirfd, const char *devnode, const char *id) {
        _cleanup_free_ char *lesc1 = NULL, *lesc2 = NULL;
        char wd_str[DECIMAL_STR_MAX(int)];
        char removed[REMOVED_NAME_MAX];
        char buf[UTIL_PATH_SIZE];
        int wd, tries, r;

        /* 2. Add inotify watch, first for IN_DELETE_SELF only, so that no close after writing of the device node is
         * reported for the watch handle before its symlinks exist, and only with a watch handle that has no symlink of
         * another watch: the kernel allocates the handles cyclically, so that a handle is used again only after a
         * long time, but then the symlink <wd>.removed of an old watch, see udev_watch_suspend(), or a symlink of a
         * watch that the kernel removed, may still exist, and an event of the handle could be attributed to another
         * device. Such a handle is removed again, its IN_IGNORED makes udevd remove the symlink <wd>.removed, see
         * udev_watch_ignored(), a stale symlink wd -> ID is removed, see watch_remove_stale_symlink(), and another
         * handle is tried. */
        for (tries = 1;; tries++) {
                wd = inotify_add_watch(inotify_fd, devnode, IN_DELETE_SELF);
                if (wd < 0) {
                        r = -errno;
                        log_debug_errno(r, "inotify_add_watch(%d, %s, %o) failed: %m",
                                        inotify_fd, utf8_escape_for_log(devnode, &lesc1), IN_DELETE_SELF);
                        /* the device may already be gone, e.g. a partition removed right after it appeared */
                        return IN_SET(r, -ENOENT, -ENODEV, -ENXIO) ? 1 : r;
                }

                xsprintf(wd_str, "%d", wd);
                xsprintf(removed, "%d" REMOVED_SUFFIX, wd);
                if (read_link(dirfd, removed, buf, sizeof(buf)) != -ENOENT)
                        r = -EEXIST;
                else {
                        r = read_link(dirfd, wd_str, buf, sizeof(buf));
                        if (r == -ENOENT)
                                break;
                }

                log_debug("watch handle %i for '%s' has a symlink of another watch, %s", wd,
                          utf8_escape_for_log(devnode, &lesc1),
                          tries < WATCH_HANDLE_TRIES ? "trying another one" : "giving up");
                (void) inotify_rm_watch(inotify_fd, wd);
                if (r >= 0)
                        watch_remove_stale_symlink(dirfd, wd, buf);
                if (tries >= WATCH_HANDLE_TRIES)
                        return -EBUSY;
        }

        /* 3. Create new symlinks */
        if (symlinkat(wd_str, dirfd, id) < 0) {
                r = -errno;
                log_debug_errno(r, "Failed to create symlink '" WATCH_DIR "/%s' to '%s': %m",
                                utf8_escape_for_log(id, &lesc1), wd_str);
                goto fail;
        }

        if (symlinkat(id, dirfd, wd_str) < 0) {
                r = -errno;
                log_debug_errno(r, "Failed to create symlink '" WATCH_DIR "/%s' to '%s': %m",
                                wd_str, utf8_escape_for_log(id, &lesc2));
                goto fail_id;
        }

        /* 4. Report closes after writing: the mask of the watch of the device node is replaced, so that the same
         * handle is returned, unless the device node was replaced or removed meanwhile. */
        r = inotify_add_watch(inotify_fd, devnode, IN_CLOSE_WRITE);
        if (r == wd)
                return 0;
        if (r >= 0) {
                log_debug("device node '%s' was replaced while its watch was added",
                          utf8_escape_for_log(devnode, &lesc1));
                (void) inotify_rm_watch(inotify_fd, r);
                r = -ESTALE;
        } else {
                r = -errno;
                log_debug_errno(r, "inotify_add_watch(%d, %s, %o) failed: %m",
                                inotify_fd, utf8_escape_for_log(devnode, &lesc1), IN_CLOSE_WRITE);
                if (IN_SET(r, -ENOENT, -ENODEV, -ENXIO))
                        r = -ESTALE;
        }

        (void) unlinkat(dirfd, wd_str, 0);
fail_id:
        (void) unlinkat(dirfd, id, 0);
fail:
        (void) inotify_rm_watch(inotify_fd, wd);
        return r;
}

void udev_watch_begin(struct udev *udev __attribute__((unused)), struct udev_device *dev) {
        _cleanup_free_ char *lesc1 = NULL;
        const char *devnode, *id;
        int dirfd, tries, r, level;

        if (inotify_fd < 0)
                return;

        devnode = udev_device_get_devnode(dev);
        if (devnode == NULL)
                return;

        id = udev_device_get_id_filename(dev);
        if (id == NULL)
                return;

        dirfd = watch_dir_get(devnode, /* watching= */ true);
        if (dirfd < 0)
                return;

        /* 1. Clear old symlinks */
        (void) udev_watch_clear(dev, dirfd, NULL);

        /* 2. to 4., again when the device node was replaced meanwhile */
        log_debug("adding watch on '%s'", utf8_escape_for_log(devnode, &lesc1));
        for (tries = 1;; tries++) {
                r = watch_add(dirfd, devnode, id);
                if (r != -ESTALE || tries >= WATCH_NODE_TRIES)
                        break;

                log_debug("device node '%s' was replaced or removed while its watch was added, trying again",
                          utf8_escape_for_log(devnode, &lesc1));
        }

        if (r >= 0)
                return;

        /* at debug level in a worker of an udevd that exited meanwhile, see watch_dir_get() */
        level = watch_main_exited() ? LOG_DEBUG : LOG_WARNING;
        if (r == -EBUSY)
                log_full(level, "Each of %i watch handles for device node '%s' had a symlink of another watch, not watching it",
                         WATCH_HANDLE_TRIES, utf8_escape_for_log(devnode, &lesc1));
        else if (r == -ESTALE)
                log_full(level, "Device node '%s' was replaced or removed %i times while its watch was added, not watching it",
                         utf8_escape_for_log(devnode, &lesc1), WATCH_NODE_TRIES);
        else
                log_full_errno(level, r, "Failed to watch device node '%s', not watching it: %m",
                               utf8_escape_for_log(devnode, &lesc1));
}

void udev_watch_end(struct udev *udev __attribute__((unused)), struct udev_device *dev) {
        _cleanup_free_ char *lesc1 = NULL;
        int dirfd;
        int wd = -1, r;

        if (inotify_fd < 0)
                return;

        if (udev_device_get_devnode(dev) == NULL)
                return;

        dirfd = watch_dir_get(udev_device_get_devnode(dev), /* watching= */ false);
        if (dirfd < 0)
                return;

        /* First, clear symlinks. */
        r = udev_watch_clear(dev, dirfd, &wd);
        if (r < 0)
                return;

        /* Then, remove inotify watch. */
        if (wd >= 0) {
                log_debug("removing watch handle %i on '%s'",
                          wd, utf8_escape_for_log(udev_device_get_devnode(dev), &lesc1));
                (void) inotify_rm_watch(inotify_fd, wd);
        }
}

/* Removes the inotify watch of the device while an event of the device is processed, but unlike udev_watch_end(),
 * keeps its symlinks, so that the main process can still find the device of an inotify event of the watch that
 * the kernel queued before, e.g. IN_CLOSE_WRITE of a close right before the event started, also when it reads the
 * event only after the event was processed: the symlink wd -> ID is renamed to wd.removed, which udevd removes
 * when it handles IN_IGNORED of the watch handle, see udev_watch_ignored(); udev_watch_begin() or udev_watch_end()
 * removes the symlink ID -> wd when the event is processed. inotify allocates the watch handles cyclically, so
 * that the handle is not reused meanwhile. */
void udev_watch_suspend(struct udev *udev __attribute__((unused)), struct udev_device *dev) {
        _cleanup_free_ char *lesc1 = NULL, *lesc2 = NULL;
        char wd_str[DECIMAL_STR_MAX(int)];
        char removed[REMOVED_NAME_MAX];
        char buf[UTIL_PATH_SIZE];
        bool renamed = true;
        int dirfd;
        const char *id;
        ssize_t len;
        int wd;

        if (inotify_fd < 0)
                return;

        if (udev_device_get_devnode(dev) == NULL)
                return;

        id = udev_device_get_id_filename(dev);
        if (id == NULL)
                return;

        dirfd = watch_dir_get(udev_device_get_devnode(dev), /* watching= */ false);
        if (dirfd < 0)
                return;

        /* the symlink ID -> wd */
        len = readlinkat(dirfd, id, wd_str, sizeof(wd_str));
        if (len < 0) {
                if (errno != ENOENT)
                        log_debug_errno(errno, "Failed to read symlink '" WATCH_DIR "/%s': %m",
                                        utf8_escape_for_log(id, &lesc1));
                return;
        }
        if ((size_t) len >= sizeof(wd_str)) {
                log_debug("Invalid symlink '" WATCH_DIR "/%s'.", utf8_escape_for_log(id, &lesc1));
                return;
        }
        wd_str[len] = '\0';

        if (safe_atoi(wd_str, &wd) < 0 || wd < 0) {
                log_debug("Failed to parse watch handle from symlink '" WATCH_DIR "/%s'.", utf8_escape_for_log(id, &lesc1));
                return;
        }

        /* like udev_watch_clear(): only a watch handle whose symlink wd -> ID is owned by the device */
        len = readlinkat(dirfd, wd_str, buf, sizeof(buf));
        if (len < 0) {
                log_debug_errno(errno, "Failed to read symlink '" WATCH_DIR "/%s': %m", wd_str);
                return;
        }
        if ((size_t) len >= sizeof(buf)) {
                log_debug("Invalid symlink '" WATCH_DIR "/%s'.", wd_str);
                return;
        }
        buf[len] = '\0';

        if (!streq(buf, id)) {
                log_debug("Symlink '" WATCH_DIR "/%s' is owned by another device '%s'.",
                          wd_str, utf8_escape_for_log(buf, &lesc2));
                return;
        }

        /* Keep the symlink wd -> ID under another name until udevd handles IN_IGNORED of the watch handle,
         * which the kernel queues when the watch is removed, after the earlier events of the watch, so that
         * udevd can still find the device of an event of the watch that the kernel queued before, also after
         * the event was processed, see udev_watch_ignored(). Without it, the symlinks are kept until the event
         * was processed. */
        xsprintf(removed, "%s" REMOVED_SUFFIX, wd_str);
        if (renameat(dirfd, wd_str, dirfd, removed) < 0) {
                log_debug_errno(errno, "Failed to rename '" WATCH_DIR "/%s' to '%s', ignoring: %m", wd_str, removed);
                renamed = false;
        }

        log_debug("removing watch handle %i on '%s'",
                  wd, utf8_escape_for_log(udev_device_get_devnode(dev), &lesc1));
        if (inotify_rm_watch(inotify_fd, wd) < 0 && renamed) {
                /* The watch was removed already, e.g. as the device node was removed: its IN_IGNORED may be
                 * handled already. */
                if (renameat(dirfd, removed, dirfd, wd_str) < 0 && errno != ENOENT)
                        log_debug_errno(errno, "Failed to rename '" WATCH_DIR "/%s' to '%s', ignoring: %m",
                                        removed, wd_str);
        }
}

static void overflow_barrier_reached(void);

/* Called by udevd for IN_IGNORED of the watch handle wd: the kernel removed the watch, and there are no events of
 * it anymore, so the symlink wd -> ID that udev_watch_suspend() kept is removed. The symlinks of a watch that was
 * removed as the device node was removed are removed by the worker of the 'remove' event, see udev_watch_end(). */
void udev_watch_ignored(int wd) {
        char removed[REMOVED_NAME_MAX];

        if (wd < 0 || watch_dirfd < 0)
                return;

        if (wd == barrier_wd) {
                overflow_barrier_reached();
                return;
        }

        xsprintf(removed, "%d" REMOVED_SUFFIX, wd);
        if (unlinkat(watch_dirfd, removed, 0) < 0) {
                if (errno != ENOENT)
                        log_debug_errno(errno, "Failed to remove '" WATCH_DIR "/%s', ignoring: %m", removed);
        } else
                log_debug("removed watch handle %i forgotten", wd);
}

/* Called by udevd for IN_Q_OVERFLOW: events were lost, maybe IN_IGNORED of watch handles that udev_watch_suspend()
 * removed, whose symlinks <wd>.removed then were never removed. They cannot be removed now, as the IN_IGNORED of
 * some may only be queued behind the overflow, possibly behind a close after writing of the device, which udevd
 * still has to find. So the symlinks <wd>.removed whose watch handles were freed already, as they are not in the
 * fdinfo of the inotify instance, and cannot be removed, are remembered, and a barrier is set up: a watch that is
 * added and removed at once, whose IN_IGNORED is queued behind the IN_IGNORED of all of them that were not lost.
 * When udevd handles it, see overflow_barrier_reached(), the ones that still exist lost their IN_IGNORED, and are
 * removed, also when the event of their device is still being processed. Without the fdinfo, only the ones of
 * events that were processed are remembered. A new overflow before the barrier starts again. */
void udev_watch_overflow(void) {
        _cleanup_set_free_ Set *handles = NULL;
        _cleanup_closedir_ DIR *dir = NULL;
        struct dirent *ent;
        int b, r, dfd;

        if (inotify_fd < 0 || watch_dirfd < 0)
                return;

        overflow_links = strv_free(overflow_links);
        barrier_wd = -1;

        r = read_watch_handles(&handles);
        if (r < 0)
                log_debug_errno(r, "Failed to read the watch handles of the inotify instance, ignoring: %m");

        dir = xopendirat(watch_dirfd, ".", 0);
        if (!dir) {
                log_debug_errno(errno, "Failed to open " WATCH_DIR ", ignoring: %m");
                return;
        }
        dfd = dirfd(dir);
        assert(dfd >= 0);

        for (ent = readdir(dir); ent != NULL; ent = readdir(dir)) {
                char wd_str[DECIMAL_STR_MAX(int)];
                char device[UTIL_PATH_SIZE];
                const char *suffix;
                int wd;

                suffix = endswith(ent->d_name, REMOVED_SUFFIX);
                if (!suffix || (size_t) (suffix - ent->d_name) >= sizeof(wd_str))
                        continue;
                memcpy(wd_str, ent->d_name, suffix - ent->d_name);
                wd_str[suffix - ent->d_name] = '\0';
                if (safe_atoi(wd_str, &wd) < 0 || wd < 0)
                        continue;

                if (read_link(dfd, ent->d_name, device, sizeof(device)) < 0)
                        continue;

                if (handles) {
                        if (set_contains(handles, UINT_TO_PTR((unsigned) wd)))
                                continue;

                        /* The handle leaves the fdinfo when the removal of the watch starts, but the kernel queues
                         * IN_IGNORED of it only a moment later, and then frees the handle: as long as removing the
                         * handle once more succeeds, its IN_IGNORED is maybe still to come. */
                        if (inotify_rm_watch(inotify_fd, wd) >= 0 || errno != EINVAL)
                                continue;
                } else if (watch_handle_is_current(dfd, device, wd))
                        continue;

                if (strv_extend(&overflow_links, ent->d_name) < 0 || strv_extend(&overflow_links, device) < 0) {
                        log_oom_debug();
                        overflow_links = strv_free(overflow_links);
                        return;
                }
        }

        if (strv_isempty(overflow_links)) {
                log_debug("inotify event queue overflowed, no symlink of a removed watch handle may have lost its IN_IGNORED");
                return;
        }

        b = inotify_add_watch(inotify_fd, "/", IN_DELETE_SELF | IN_ONLYDIR);
        if (b < 0) {
                log_debug_errno(errno, "Failed to add the watch of the barrier after an overflow of the inotify event queue, ignoring: %m");
                overflow_links = strv_free(overflow_links);
                return;
        }
        if (inotify_rm_watch(inotify_fd, b) < 0) {
                log_debug_errno(errno, "Failed to remove the watch of the barrier after an overflow of the inotify event queue, ignoring: %m");
                overflow_links = strv_free(overflow_links);
                return;
        }

        barrier_wd = b;
        log_debug("inotify event queue overflowed, %u symlink(s) of removed watch handles may have lost their IN_IGNORED, barrier watch handle %i",
                  strv_length(overflow_links) / 2, b);
}

/* IN_IGNORED of the barrier, see udev_watch_overflow(): the IN_IGNORED of the remembered symlinks that was not lost
 * was handled, so the ones that still exist, with the same target, are removed. */
static void overflow_barrier_reached(void) {
        int dirfd = watch_dirfd;
        char **name, **target;

        barrier_wd = -1;

        for (name = overflow_links, target = name ? name + 1 : NULL; name && *name && *target;
             name += 2, target += 2) {
                char buf[UTIL_PATH_SIZE];

                if (read_link(dirfd, *name, buf, sizeof(buf)) < 0 || !streq(buf, *target))
                        continue;

                if (unlinkat(dirfd, *name, 0) < 0)
                        log_debug_errno(errno, "Failed to remove '" WATCH_DIR "/%s', ignoring: %m", *name);
                else
                        log_debug("removed '" WATCH_DIR "/%s', whose IN_IGNORED was lost in an overflow of the inotify event queue",
                                  *name);
        }

        overflow_links = strv_free(overflow_links);
}

/* The device of the watch handle, for the main process of udevd, which handles it without reading its uevent file:
 * on some kernels, a read of a uevent file waits while a driver probes or releases the device, which can take
 * minutes, and udevd would handle no events meanwhile, see udev_device_new_from_devnum(). The lookup by the device
 * number checks it without the file, and the subsystem is taken from its link here, so that
 * udev_device_get_subsystem() does not read the file for it either; the property SUBSYSTEM comes first then,
 * which does not matter for this device. In the main process, only these read uevent files: the re-read of the
 * partition table of a disk, when udevd re-reads it itself rather than in a child, see synthesize_change(); for a
 * watched device that is no whole disk, or a disk of the device mapper, synthesize_change_one(), to tell whether
 * its change uevent fits with the UUID and the caller arguments, on the kernels not known to take the lock of the
 * device to fill its uevent file, see uevent_room_of_device(); while events wait for a locked disk,
 * manager_requeue_locked_events_by_device() for a block device, which needs the device node of its disk; when
 * udevd creates the watch directory again while it runs, see udev_watch_check_dir(), watch_dir_recover_one() for
 * the ID of each watched device, and for its device node in the debug messages; and at startup,
 * udev_watch_restore() for the device node and the ID of each device whose watch it restores. */
struct udev_device *udev_watch_lookup(struct udev *udev, int wd) {
        char name[REMOVED_NAME_MAX];
        char device[UTIL_NAME_SIZE];
        struct udev_device *dev;
        int r;

        if (inotify_fd < 0 || watch_dirfd < 0 || wd < 0)
                return NULL;

        xsprintf(name, "%d", wd);
        r = read_link(watch_dirfd, name, device, sizeof(device));
        if (r == -ENOENT) {
                /* removed by udev_watch_suspend(), and IN_IGNORED of it not handled yet */
                xsprintf(name, "%d" REMOVED_SUFFIX, wd);
                r = read_link(watch_dirfd, name, device, sizeof(device));
        }
        if (r < 0 || device[0] == '\0')
                return NULL;

        dev = udev_device_new_from_device_id(udev, device);
        if (dev)
                (void) udev_device_get_subsystem_without_uevent(dev);
        return dev;
}
