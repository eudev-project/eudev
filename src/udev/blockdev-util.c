/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#ifdef HAVE_LINUX_BTRFS_H
#include <linux/btrfs.h>
#include <linux/magic.h>
#endif

#include "blockdev-util.h"
#include "fileio.h"
#include "libudev-private.h"
#include "log.h"
#include "util.h"

#define SYS_BLOCK_PATH_MAX(suffix) (sizeof("/sys/dev/block/") + DECIMAL_STR_MAX(unsigned) * 2 + sizeof(":") + strlen(suffix))
#define xsprintf_sys_block_path(buf, suffix, devno) \
        xsprintf(buf, "/sys/dev/block/%u:%u%s", major(devno), minor(devno), strempty(suffix))

static const char *strempty(const char *s) {
        return s ?: "";
}

int block_device_is_whole_disk(struct udev_device *dev) {
        assert(dev);

        if (!streq_ptr(udev_device_get_subsystem(dev), "block"))
                return -ENOTBLK;

        return streq_ptr(udev_device_get_devtype(dev), "disk");
}

int blockdev_partscan_enabled(struct udev_device *dev) {
        unsigned capability;
        int r, ext_range;

        /* Checks if partition scanning is correctly enabled on the block device.
         *
         * The 'GENHD_FL_NO_PART_SCAN' flag was introduced by
         * https://github.com/torvalds/linux/commit/d27769ec3df1a8de9ca450d2dcd72d1ab259ba32 (v3.2).
         * But at that time, the flag is also effectively implied when 'minors' element of 'struct gendisk'
         * is 1, which can be check with 'ext_range' sysfs attribute. Explicit flag ('GENHD_FL_NO_PART_SCAN')
         * can be obtained from 'capability' sysattr.
         *
         * With https://github.com/torvalds/linux/commit/46e7eac647b34ed4106a8262f8bedbb90801fadd (v5.17),
         * the flag is renamed to GENHD_FL_NO_PART.
         *
         * With https://github.com/torvalds/linux/commit/1ebe2e5f9d68e94c524aba876f27b945669a7879 (v5.17),
         * we can check the flag from 'ext_range' sysfs attribute directly.
         *
         * With https://github.com/torvalds/linux/commit/430cc5d3ab4d0ba0bd011cfbb0035e46ba92920c (v5.17),
         * the value of GENHD_FL_NO_PART is changed from 0x0200 to 0x0004.
         * Note, the new value was used by the GENHD_FL_MEDIA_CHANGE_NOTIFY flag, which was introduced by
         * 86ce18d7b7925bfd6b64c061828ca2a857ee83b8 (v2.6.22), and removed by
         * 9243c6f3e012a92dd900d97ef45efaf8a8edc448 (v5.7). If we believe the commit message of
         * e81cd5a983bb35dabd38ee472cf3fea1c63e0f23, the flag was never used. So, fortunately, we can use
         * both the new and old values safely.
         *
         * With https://github.com/torvalds/linux/commit/b9684a71fca793213378dd410cd11675d973eaa1 (v5.19),
         * another flag GD_SUPPRESS_PART_SCAN is introduced for loopback block device, and partition scanning
         * is done only when both GENHD_FL_NO_PART and GD_SUPPRESS_PART_SCAN are not set. Before the commit,
         * LO_FLAGS_PARTSCAN flag was directly tied with GENHD_FL_NO_PART. But with this change now it is
         * tied with GD_SUPPRESS_PART_SCAN. So, LO_FLAGS_PARTSCAN cannot be obtained from 'ext_range'
         * sysattr, which corresponds to GENHD_FL_NO_PART, and we need to read 'loop/partscan'.
         *
         * With https://github.com/torvalds/linux/commit/e81cd5a983bb35dabd38ee472cf3fea1c63e0f23 (v6.3),
         * the 'capability' sysfs attribute is deprecated, hence we cannot check flags from it.
         *
         * With https://github.com/torvalds/linux/commit/a4217c6740dc64a3eb6815868a9260825e8c68c6 (v6.10,
         * backported to v6.6+), the partscan status is directly exposed as 'partscan' sysattr.
         *
         * To support both old and new kernels, we need to do the following:
         * 1) check 'partscan' sysfs attribute where the information is made directly available,
         * 2) check if the blockdev refers to a partition, where partscan is not supported,
         * 3) check 'loop/partscan' sysfs attribute for loopback block devices, and if '0' we can conclude
         *    partition scanning is disabled,
         * 4) check 'ext_range' sysfs attribute, and if '1' we can conclude partition scanning is disabled,
         * 5) otherwise check 'capability' sysfs attribute for ancient version. */

        assert(dev);

        if (!streq_ptr(udev_device_get_subsystem(dev), "block"))
                return -ENOTBLK;

        /* For v6.10 or newer. */
        r = device_get_sysattr_bool(dev, "partscan");
        if (r != -ENOENT)
                return r;

        /* Partition block devices never have partition scanning on, there's no concept of sub-partitions for
         * partitions. */
        if (streq_ptr(udev_device_get_devtype(dev), "partition"))
                return false;

        /* For loopback block device, especially for v5.19 or newer. Even if this is enabled, we also need to
         * check GENHD_FL_NO_PART flag through 'ext_range' and 'capability' sysfs attributes below. */
        if (device_get_sysattr_bool(dev, "loop/partscan") == 0)
                return false;

        r = device_get_sysattr_int(dev, "ext_range", &ext_range);
        if (r == -ENOENT) /* If the ext_range file doesn't exist then we are most likely looking at a
                           * partition block device, not the whole block device. And that means we have no
                           * partition scanning on for it (we do for its parent, but not for the partition
                           * itself). */
                return false;
        if (r < 0)
                return r;

        if (ext_range <= 1) /* The value should be always positive, but the kernel uses '%d' for the
                             * attribute. Let's gracefully handle zero or negative. */
                return false;

        r = device_get_sysattr_unsigned_full(dev, "capability", 16, &capability);
        if (r == -ENOENT)
                return false;
        if (r < 0)
                return r;

#define GENHD_FL_NO_PART_OLD 0x0200
#define GENHD_FL_NO_PART_NEW 0x0004
        /* If one of the NO_PART flags is set, part scanning is definitely off. */
        if ((capability & (GENHD_FL_NO_PART_OLD | GENHD_FL_NO_PART_NEW)) != 0)
                return false;

        /* Otherwise, assume part scanning is on, we have no further checks available. Assume the best. */
        return true;
}

static int parse_devnum(const char *s, dev_t *ret) {
        unsigned x, y;
        char c;

        assert(s);
        assert(ret);

        if (sscanf(s, "%u:%u%c", &x, &y, &c) != 2)
                return -EINVAL;

        *ret = makedev(x, y);
        return 0;
}

int block_get_whole_disk(dev_t d, dev_t *ret) {
        char p[SYS_BLOCK_PATH_MAX("/partition")];
        _cleanup_free_ char *s = NULL;
        dev_t devt;
        int r;

        assert(ret);

        if (major(d) == 0)
                return -ENODEV;

        /* If it has a queue this is good enough for us */
        xsprintf_sys_block_path(p, "/queue", d);
        if (access(p, F_OK) >= 0) {
                *ret = d;
                return 0;
        }
        if (errno != ENOENT)
                return -errno;

        /* If it is a partition find the originating device */
        xsprintf_sys_block_path(p, "/partition", d);
        if (access(p, F_OK) < 0)
                return -errno;

        /* Get parent dev_t */
        xsprintf_sys_block_path(p, "/../dev", d);
        r = read_one_line_file(p, &s);
        if (r < 0)
                return r;

        r = parse_devnum(s, &devt);
        if (r < 0)
                return r;

        /* Only return this if it is really good enough for us. */
        xsprintf_sys_block_path(p, "/queue", devt);
        if (access(p, F_OK) < 0)
                return -errno;

        *ret = devt;
        return 1;
}

static int block_get_originating_one(dev_t dt, dev_t *ret) {
        char p[SYS_BLOCK_PATH_MAX("/slaves")];
        _cleanup_closedir_ DIR *d = NULL;
        dev_t first = 0, first_whole = 0;
        bool found = false;
        struct dirent *de;

        /* For the specified block device tries to chase it through the layers, in case LUKS-style DM
         * stacking is used, trying to find the next underlying layer. */

        xsprintf_sys_block_path(p, "/slaves", dt);
        d = opendir(p);
        if (!d)
                return -errno;

        for (;;) {
                _cleanup_free_ char *s = NULL;
                char *q;
                dev_t t, w;

                errno = 0;
                de = readdir(d);
                if (!de) {
                        if (errno > 0)
                                return -errno;
                        break;
                }

                if (streq(de->d_name, ".") || streq(de->d_name, ".."))
                        continue;

                if (!IN_SET(de->d_type, DT_LNK, DT_UNKNOWN))
                        continue;

                q = strjoina(p, "/", de->d_name, "/dev");
                if (read_one_line_file(q, &s) < 0)
                        continue;

                if (parse_devnum(s, &t) < 0)
                        continue;

                if (block_get_whole_disk(t, &w) < 0)
                        continue;

                if (!found) {
                        first = t;
                        first_whole = w;
                        found = true;
                        continue;
                }

                /* We found a device backed by multiple other devices. We don't really support automatic
                 * discovery on such setups, with the exception of dm-verity partitions. In this case there
                 * are two backing devices: the data partition and the hash partition. We are fine with such
                 * setups, however, only if both partitions are on the same physical device. Hence, let's
                 * verify this by iterating over every node in the 'slaves/' directory and comparing them with
                 * the first that gets returned by readdir(), to ensure they all point to the same device. */
                if (w != first_whole)
                        return -ENOTUNIQ;
        }

        if (!found)
                return -ENOENT;

        *ret = first;
        return 0;
}

int block_get_originating(dev_t dt, dev_t *ret) {
        dev_t current = dt;
        int r;

        assert(ret);

        /* Chases the block device through all layers */
        for (;;) {
                dev_t origin;

                r = block_get_originating_one(current, &origin);
                if (r == -ENOENT)
                        break;
                if (r < 0)
                        return r;

                current = origin;
        }

        if (current == dt)
                return -ENOENT;

        *ret = current;
        return 0;
}

static int btrfs_get_block_device_fd(int fd, dev_t *ret) {
#ifdef HAVE_LINUX_BTRFS_H
        struct btrfs_ioctl_fs_info_args fsi = {};
        struct statfs sfs;
        uint64_t id;

        assert(fd >= 0);
        assert(ret);

        if (fstatfs(fd, &sfs) < 0)
                return -errno;
        if (!F_TYPE_EQUAL(sfs.f_type, BTRFS_SUPER_MAGIC))
                return -ENOTTY;

        if (ioctl(fd, BTRFS_IOC_FS_INFO, &fsi) < 0)
                return -errno;

        /* We won't do this for btrfs RAID */
        if (fsi.num_devices != 1) {
                *ret = 0;
                return 0;
        }

        for (id = 1; id <= fsi.max_id; id++) {
                struct btrfs_ioctl_dev_info_args di = {
                        .devid = id,
                };
                struct stat st;

                if (ioctl(fd, BTRFS_IOC_DEV_INFO, &di) < 0) {
                        if (errno == ENODEV)
                                continue;

                        return -errno;
                }

                /* For the root fs — when no initrd is involved — btrfs returns /dev/root on any kernels from
                 * the past few years. That sucks, as we have no API to determine the actual root then. let's
                 * return an recognizable error for this case, so that the caller can maybe print a nice
                 * message about this.
                 *
                 * https://bugzilla.kernel.org/show_bug.cgi?id=89721 */
                if (streq((char*) di.path, "/dev/root"))
                        return -EUCLEAN;

                if (stat((char*) di.path, &st) < 0)
                        return -errno;

                if (!S_ISBLK(st.st_mode))
                        return -ENOTBLK;

                if (major(st.st_rdev) == 0)
                        return -ENODEV;

                *ret = st.st_rdev;
                return 1;
        }

        return -ENODEV;
#else
        return -ENOTTY;
#endif
}

static int get_block_device_fd(int fd, dev_t *ret) {
        struct stat st;
        int r;

        assert(fd >= 0);
        assert(ret);

        /* Gets the block device directly backing a file system. If the block device is encrypted, returns
         * the device mapper block device. */

        if (fstat(fd, &st))
                return -errno;

        if (major(st.st_dev) != 0) {
                *ret = st.st_dev;
                return 1;
        }

        r = btrfs_get_block_device_fd(fd, ret);
        if (r != -ENOTTY) /* ENOTTY: not btrfs */
                return r;

        *ret = 0;
        return 0;
}

int get_block_device_harder(const char *path, dev_t *ret) {
        _cleanup_close_ int fd = -1;
        int r;

        assert(path);
        assert(ret);

        /* Gets the backing block device for a file system, and handles LUKS encrypted file systems, looking
         * for its underlying physical device, if there is one. */

        fd = open(path, O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        r = get_block_device_fd(fd, ret);
        if (r <= 0)
                return r;

        r = block_get_originating(*ret, ret);
        if (r < 0 && r != -ENOENT)
                log_debug_errno(r, "Failed to chase block device, ignoring: %m");

        return 1;
}

static int btrfs_log_dev_root(int level, int ret, const char *p) {
        return log_full_errno(level, ret,
                              "File system behind %s is reported by btrfs to be backed by pseudo-device /dev/root, which is not a valid userspace accessible device node. "
                              "Cannot determine correct backing block device.", p);
}

int blockdev_get_root(int level, dev_t *ret) {
        char p[PATH_MAX];
        dev_t devno;
        ssize_t n;
        int r;

        /* Returns the device node backing the root file system. Traces through
         * dm-crypt/dm-verity/... Returns > 0 and the devno of the device on success. If there's no block
         * device (or multiple) returns 0 and a devno of 0. Failure otherwise.
         *
         * If the root mount has been replaced by some form of volatile file system (overlayfs), the original
         * root block device node is symlinked in /run/systemd/volatile-root. Let's read that here. */
        n = readlink("/run/systemd/volatile-root", p, sizeof(p) - 1);
        if (n < 0 && errno == ENOENT) { /* volatile-root not found */
                r = get_block_device_harder("/", &devno);
                if (r == -EUCLEAN)
                        return btrfs_log_dev_root(level, r, "root file system");
                if (r < 0)
                        return log_full_errno(level, r, "Failed to determine block device of root file system: %m");
                if (r == 0) { /* Not backed by a single block device. (Could be NFS or so, or could be multi-device RAID or so) */
                        r = get_block_device_harder("/usr", &devno);
                        if (r == -EUCLEAN)
                                return btrfs_log_dev_root(level, r, "/usr");
                        if (r < 0)
                                return log_full_errno(level, r, "Failed to determine block device of /usr/ file system: %m");
                        if (r == 0) { /* /usr/ not backed by single block device, either. */
                                log_debug("Neither root nor /usr/ file system are on a (single) block device.");

                                if (ret)
                                        *ret = 0;

                                return 0;
                        }
                }
        } else if (n < 0)
                return log_full_errno(level, errno, "Failed to read symlink /run/systemd/volatile-root: %m");
        else {
                const char *s;

                p[n] = 0;

                s = startswith(p, "/dev/block/");
                if (!s || parse_devnum(s, &devno) < 0)
                        return log_full_errno(level, EINVAL, "Failed to parse major/minor device node: %m");
        }

        if (ret)
                *ret = devno;

        return 1;
}
