/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Tests of the devices that libudev builds from the properties of an event: from a message received by a
 * monitor, with udev_device_new_from_nulstr(), and from the environment of a program started by a rule, with
 * the public udev_device_new_from_environment(). They must keep the values of the event: the uevent file of
 * the device in sysfs describes the device as it is now, maybe a new device with the same devpath, so it is
 * not read for them, like in systemd before v258 (its devices of an event are sealed).
 *
 * udev_device_get_devtype() of an event without DEVTYPE read the uevent file, which replaced DEVTYPE, DEVNAME,
 * MAJOR/MINOR and any other key of the file with the current values, and freed the strings that callers
 * still used, e.g. the device node of an event in udevd.
 *
 * The test runs in a new mount namespace, and in a new user namespace when it is not run as root, with the
 * test sysfs test/sys mounted on /sys. It exits with 77 (skipped) where that is not possible.
 */

#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "libudev.h"
#include "libudev-private.h"
#include "fileio.h"
#include "udev-util.h"
#include "util.h"

#ifndef HAVE_UNSHARE
#include <sys/syscall.h>
static inline int unshare(int flags) { return syscall(SYS_unshare, flags); }
#endif

#define EXIT_TEST_SKIP 77

/* a partition of the test sysfs, whose uevent file has MAJOR=8, MINOR=1, DEVTYPE=partition, DEVNAME=sda1 */
#define DEVPATH "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1"

static int failures;

static int enter_namespace(void) {
        char map[STRLEN("0  1") + 2 * DECIMAL_STR_MAX(unsigned) + 1];
        uid_t uid = getuid();
        gid_t gid = getgid();
        int r;

        if (unshare(uid == 0 ? CLONE_NEWNS : CLONE_NEWUSER|CLONE_NEWNS) < 0) {
                r = -errno;
                fprintf(stderr, "cannot create a mount namespace: %m, skipping\n");
                return r;
        }

        if (uid != 0) {
                /* setgroups does not exist before Linux 3.19 */
                r = write_string_file("/proc/self/setgroups", "deny");
                if (r < 0 && r != -ENOENT) {
                        fprintf(stderr, "cannot write /proc/self/setgroups: %s, skipping\n", strerror(-r));
                        return r;
                }

                xsprintf(map, "0 %u 1", (unsigned) uid);
                r = write_string_file("/proc/self/uid_map", map);
                if (r >= 0) {
                        xsprintf(map, "0 %u 1", (unsigned) gid);
                        r = write_string_file("/proc/self/gid_map", map);
                }
                if (r < 0) {
                        fprintf(stderr, "cannot map the user and group IDs: %s, skipping\n", strerror(-r));
                        return r;
                }
        }

        /* The source and the type are ignored when changing the propagation and for bind mounts, but pass
         * strings instead of NULL, which valgrind reports as invalid. */
        if (mount("none", "/", "none", MS_PRIVATE|MS_REC, NULL) < 0 ||
            mount("test/sys", "/sys", "none", MS_BIND|MS_REC, NULL) < 0) {
                r = -errno;
                fprintf(stderr, "cannot mount the test sysfs on /sys: %m, skipping\n");
                return r;
        }

        return 0;
}

static void expect_str(const char *name, const char *what, const char *got, const char *expected) {
        if (streq_ptr(got, expected))
                return;

        fprintf(stderr, "%s: %s is %s%s%s, expected %s%s%s\n", name, what,
                got ? "\"" : "", got ?: "NULL", got ? "\"" : "",
                expected ? "\"" : "", expected ?: "NULL", expected ? "\"" : "");
        failures++;
}

static void expect_devnum(const char *name, dev_t got, dev_t expected) {
        if (got == expected)
                return;

        fprintf(stderr, "%s: the device number is %u:%u, expected %u:%u\n", name,
                major(got), minor(got), major(expected), minor(expected));
        failures++;
}

/* the device of the event below: no DEVTYPE, and DEVNAME, MAJOR and MINOR differ from the uevent file */
static void check_event_device(const char *name, struct udev_device *dev) {
        if (!dev) {
                fprintf(stderr, "%s: the device was refused: %m\n", name);
                failures++;
                return;
        }

        /* the only getter that read the uevent file of such a device */
        expect_str(name, "udev_device_get_devtype()", udev_device_get_devtype(dev), NULL);

        expect_str(name, "the property DEVTYPE", udev_device_get_property_value(dev, "DEVTYPE"), NULL);
        expect_str(name, "the device node", udev_device_get_devnode(dev), "/dev/fake");
        expect_str(name, "the property DEVNAME", udev_device_get_property_value(dev, "DEVNAME"), "/dev/fake");
        expect_str(name, "the property MAJOR", udev_device_get_property_value(dev, "MAJOR"), "8");
        expect_str(name, "the property MINOR", udev_device_get_property_value(dev, "MINOR"), "99");
        expect_devnum(name, udev_device_get_devnum(dev), makedev(8, 99));
        expect_str(name, "the subsystem", udev_device_get_subsystem(dev), "block");
        expect_str(name, "the devpath", udev_device_get_devpath(dev), DEVPATH);
        expect_str(name, "the property FOO", udev_device_get_property_value(dev, "FOO"), "bar");
}

int main(int argc __attribute__((unused)), char *argv[] __attribute__((unused))) {
        _cleanup_udev_unref_ struct udev *udev = NULL;
        _cleanup_free_ char *uevent = NULL;
        struct udev_device *dev;
        int r;

        r = enter_namespace();
        if (r < 0)
                return EXIT_TEST_SKIP;

        /* test/sys is a directory, which libudev refuses as sysfs by default */
        if (setenv("UDEV_DEVICE_VERIFY_SYSFS", "0", 1) < 0) {
                fprintf(stderr, "setenv() failed: %m\n");
                return EXIT_FAILURE;
        }

        /* the uevent file that must not be read */
        r = read_full_file("/sys" DEVPATH "/uevent", &uevent, NULL);
        if (r < 0) {
                fprintf(stderr, "cannot read the uevent file of the test sysfs: %s\n", strerror(-r));
                return EXIT_FAILURE;
        }
        if (!strstr(uevent, "DEVTYPE=partition") || !strstr(uevent, "DEVNAME=sda1")) {
                fprintf(stderr, "unexpected uevent file in the test sysfs:\n%s", uevent);
                return EXIT_FAILURE;
        }

        udev = udev_new();
        if (!udev) {
                fprintf(stderr, "udev_new() failed: %m\n");
                return EXIT_FAILURE;
        }

        /* a device read from sysfs gets the values of the uevent file */
        dev = udev_device_new_from_syspath(udev, "/sys" DEVPATH);
        if (!dev) {
                fprintf(stderr, "sysfs: the device was refused: %m\n");
                return EXIT_FAILURE;
        }
        expect_str("sysfs", "udev_device_get_devtype()", udev_device_get_devtype(dev), "partition");
        expect_str("sysfs", "the device node", udev_device_get_devnode(dev), "/dev/sda1");
        expect_devnum("sysfs", udev_device_get_devnum(dev), makedev(8, 1));
        udev_device_unref(dev);

        /* a message of a monitor, the properties as NUL-terminated strings */
        {
                char nulstr[] = "ACTION=change\0DEVPATH=" DEVPATH "\0SUBSYSTEM=block\0DEVNAME=/dev/fake\0"
                                "MAJOR=8\0MINOR=99\0SEQNUM=4242\0FOO=bar";

                dev = udev_device_new_from_nulstr(udev, nulstr, sizeof(nulstr));
                check_event_device("nulstr", dev);
                udev_device_unref(dev);
        }

        /* the environment of a program started by a rule */
        {
                char *env[] = {
                        (char *) "ACTION=change",
                        (char *) "DEVPATH=" DEVPATH,
                        (char *) "SUBSYSTEM=block",
                        (char *) "DEVNAME=/dev/fake",
                        (char *) "MAJOR=8",
                        (char *) "MINOR=99",
                        (char *) "SEQNUM=4242",
                        (char *) "FOO=bar",
                        NULL,
                };
                char **saved = environ;

                environ = env;
                dev = udev_device_new_from_environment(udev);
                environ = saved;
                check_event_device("environment", dev);
                udev_device_unref(dev);
        }

        if (failures > 0) {
                fprintf(stderr, "%i check(s) failed\n", failures);
                return EXIT_FAILURE;
        }

        printf("all checks passed\n");
        return EXIT_SUCCESS;
}
