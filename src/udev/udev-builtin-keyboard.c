/***
  This file is part of systemd.

  Copyright 2013 Kay Sievers <kay@vrfy.org>

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

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/limits.h>
/* eudev's copy of the header of Linux in src/include/uapi/, with the input event codes, like systemd */
#include <linux/input.h>

#include "udev.h"

#include "keyboard-keys-from-name.h"

/* eudev: whether the force_release list of atkbd, e.g. "6,9-11", has the scan code. The kernel prints
 * its bitmap of the codes as such a list; anything else is taken as not having it. */
static bool force_release_has_code(const char *list, unsigned code) {
        const char *p = list;

        for (;;) {
                unsigned long first, last;
                char *end;

                p += strspn(p, ", \t\n");
                if (!ascii_isdigit(*p))
                        return false;

                errno = 0;
                first = last = strtoul(p, &end, 10);
                if (errno != 0)
                        return false;
                if (*end == '-') {
                        p = end + 1;
                        if (!ascii_isdigit(*p))
                                return false;
                        last = strtoul(p, &end, 10);
                        if (errno != 0)
                                return false;
                }

                if (code >= first && code <= last)
                        return true;
                p = end;
        }
}

static int install_force_release(struct udev_device *dev, const unsigned *release, unsigned release_count) {
        struct udev_device *atkbd;
        const char *cur;
        char codes[4096];
        char *s;
        size_t l;
        unsigned i, added = 0;
        int ret;

        atkbd = udev_device_get_parent_with_subsystem_devtype(dev, "serio", NULL);
        if (!atkbd)
                return log_device_error_errno(dev, errno, "Failed to get serio parent: %m");

        ret = device_get_sysattr_safe_string(atkbd, "force_release", &cur);
        if (ret < 0)
                return log_device_error_errno(atkbd, ret, "Failed to get force-release attribute: %m");

        s = codes;
        l = sizeof(codes);

        /* copy current content */
        l = strpcpy(&s, l, cur);

        /* append new codes; eudev: only the ones that the list does not have yet, and without an empty
         * first entry, while systemd appends all of them every time, after a comma */
        for (i = 0; i < release_count; i++) {
                if (force_release_has_code(codes, release[i]))
                        continue;

                l = strpcpyf(&s, l, "%s%u", s == codes ? "" : ",", release[i]);
                added++;
        }

        if (added == 0) {
                log_device_debug(atkbd, "keyboard: force-release list '%s' has all the codes already", cur);
                return 0;
        }

        log_device_debug(atkbd, "keyboard: updating force-release list with '%s'", codes);
        ret = udev_device_set_sysattr_value(atkbd, "force_release", codes);
        if (ret < 0)
                return log_device_error_errno(atkbd, ret, "Failed to set force-release attribute: %m");

        return 0;
}

static void map_keycode(struct udev_device *dev, int fd, int scancode, const char *keycode)
{
        struct {
                unsigned scan;
                unsigned key;
        } map;
        const struct key *k;
        unsigned keycode_num;
        int r;

        /* translate identifier to key code */
        k = keyboard_lookup_key(keycode, strlen(keycode));
        if (k) {
                keycode_num = k->id;
        } else {
                /* check if it's a numeric code already */
                r = safe_atou(keycode, &keycode_num);
                if (r < 0) {
                        log_device_error_errno(dev, r, "Failed to parse key identifier '%s': %m", keycode);
                        return;
                }
        }

        map.scan = scancode;
        map.key = keycode_num;

        log_device_debug(dev, "keyboard: mapping scan code %u (0x%x) to key code %u (0x%x)",
                         map.scan, map.scan, map.key, map.key);

        if (ioctl(fd, EVIOCSKEYCODE, &map) < 0)
                log_device_error_errno(dev, errno, "Failed to call EVIOCSKEYCODE with scan code 0x%x, and key code %u: %m", map.scan, map.key);
}

static inline char* parse_token(const char *current, int32_t *val_out) {
        char *next;
        int32_t val;

        if (!current)
                return NULL;

        val = strtol(current, &next, 0);
        if (*next && *next != ':')
                return NULL;

        if (next != current)
                *val_out = val;

        if (*next)
                next++;

        return next;
}

static void override_abs(struct udev_device *dev, int fd, unsigned evcode, const char *value) {
        struct input_absinfo absinfo;
        int rc;
        char *next;

        rc = ioctl(fd, EVIOCGABS(evcode), &absinfo);
        if (rc < 0) {
                log_device_error_errno(dev, errno, "Failed to call EVIOCGABS");
                return;
        }

        next = parse_token(value, &absinfo.minimum);
        next = parse_token(next, &absinfo.maximum);
        next = parse_token(next, &absinfo.resolution);
        next = parse_token(next, &absinfo.fuzz);
        next = parse_token(next, &absinfo.flat);
        if (!next) {
                log_device_error(dev, "Failed to parse EV_ABS override '%s'", value);
                return;
        }

        log_device_debug(dev, "keyboard: %x overridden with %"PRIi32"/%"PRIi32"/%"PRIi32"/%"PRIi32"/%"PRIi32,
                         evcode, absinfo.minimum, absinfo.maximum, absinfo.resolution, absinfo.fuzz, absinfo.flat);
        rc = ioctl(fd, EVIOCSABS(evcode), &absinfo);
        if (rc < 0)
                log_device_error_errno(dev, errno, "Failed to call EVIOCSABS");
}

static void set_trackpoint_sensitivity(struct udev_device *dev, const char *value)
{
        struct udev_device *pdev;
        char val_s[DECIMAL_STR_MAX(int)];
        int r, val_i;

        /* The sensitivity sysfs attr belongs to the serio parent device */
        pdev = udev_device_get_parent_with_subsystem_devtype(dev, "serio", NULL);
        if (!pdev) {
                log_device_error_errno(dev, errno, "Failed to get serio parent: %m");
                return;
        }

        r = safe_atoi(value, &val_i);
        if (r < 0) {
                log_device_error_errno(dev, r, "Failed to parse POINTINGSTICK_SENSITIVITY '%s': %m", value);
                return;
        } else if (val_i < 0 || val_i > 255) {
                log_device_error(dev, "POINTINGSTICK_SENSITIVITY %d outside range [0..255]", val_i);
                return;
        }

        xsprintf(val_s, "%d", val_i);

        r = udev_device_set_sysattr_value(pdev, "sensitivity", val_s);
        if (r < 0)
                log_device_error_errno(dev, r, "Failed to write 'sensitivity' attribute: %m");
}

/* the device node vanished or has no medium */
static bool errno_is_device_absent_or_empty(int r) {
        return IN_SET(abs(r), ENODEV, ENXIO, ENOENT, ENOMEDIUM);
}

static int open_device(struct udev_device *dev, const char *devnode) {
        int fd;

        fd = open(devnode, O_RDWR|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (fd < 0) {
                bool ignore = errno_is_device_absent_or_empty(errno);

                return log_device_full_errno(dev, ignore ? LOG_DEBUG : LOG_WARNING, errno,
                                             "Failed to open device '%s'%s: %m",
                                             devnode, ignore ? ", ignoring" : "");
        }

        return fd;
}

static int builtin_keyboard(struct udev_device *dev, int argc __attribute__((unused)), char *argv[] __attribute__((unused)), enum udev_event_mode mode) {
        struct udev_list_entry *entry;
        unsigned release[1024];
        unsigned release_count = 0;
        _cleanup_close_ int fd = -1;
        const char *node;
        int has_abs = -1;

        if (mode != EVENT_UDEV_WORKER) {
                log_device_debug(dev, "Running in test mode, skipping execution of 'keyboard' builtin command.");
                return EXIT_SUCCESS;
        }

        /* Like systemd, the errors are returned as negative error codes, with the reason. */
        node = udev_device_get_devnode(dev);
        if (!node)
                return log_device_error_errno(dev, ENOENT, "Failed to get device name: %m");

        udev_list_entry_foreach(entry, udev_device_get_properties_list_entry(dev)) {
                const char *key;
                int r;

                key = udev_list_entry_get_name(entry);
                if (startswith(key, "KEYBOARD_KEY_")) {
                        const char *keycode;
                        unsigned scancode;

                        /* KEYBOARD_KEY_<hex scan code>=<key identifier string> */
                        r = safe_atou_full(key + 13, 16, &scancode);
                        if (r < 0) {
                                log_device_warning_errno(dev, r, "Failed to parse scan code from \"%s\", ignoring: %m", key);
                                continue;
                        }

                        keycode = udev_list_entry_get_value(entry);

                        /* a leading '!' needs a force-release entry */
                        if (keycode[0] == '!') {
                                keycode++;

                                release[release_count] = scancode;
                                if (release_count <  ELEMENTSOF(release)-1)
                                        release_count++;

                                if (keycode[0] == '\0')
                                        continue;
                        }

                        if (fd == -1) {
                                fd = open_device(dev, node);
                                if (fd < 0)
                                        return errno_is_device_absent_or_empty(fd) ? EXIT_SUCCESS : fd;
                        }

                        map_keycode(dev, fd, scancode, keycode);
                } else if (startswith(key, "EVDEV_ABS_")) {
                        unsigned evcode;

                        /* EVDEV_ABS_<EV_ABS code>=<min>:<max>:<res>:<fuzz>:<flat> */
                        r = safe_atou_full(key + 10, 16, &evcode);
                        if (r < 0) {
                                log_device_warning_errno(dev, r, "Failed to parse EV_ABS code from \"%s\", ignoring: %m", key);
                                continue;
                        }

                        if (fd == -1) {
                                fd = open_device(dev, node);
                                if (fd < 0)
                                        return errno_is_device_absent_or_empty(fd) ? EXIT_SUCCESS : fd;
                        }

                        if (has_abs == -1) {
                                unsigned long bits;
                                int rc;

                                rc = ioctl(fd, EVIOCGBIT(0, sizeof(bits)), &bits);
                                if (rc < 0)
                                        return log_device_error_errno(dev, errno, "Failed to set EVIOCGBIT");

                                has_abs = !!(bits & (1 << EV_ABS));
                                if (!has_abs)
                                        log_device_warning(dev, "EVDEV_ABS override set but no EV_ABS present on device");
                        }

                        if (!has_abs)
                                continue;

                        override_abs(dev, fd, evcode, udev_list_entry_get_value(entry));
                } else if (streq(key, "POINTINGSTICK_SENSITIVITY")) {
                        set_trackpoint_sensitivity(dev, udev_list_entry_get_value(entry));
                }
        }

        /* install list of force-release codes */
        if (release_count > 0)
                (void) install_force_release(dev, release, release_count);

        return EXIT_SUCCESS;
}

const struct udev_builtin udev_builtin_keyboard = {
        .name = "keyboard",
        .cmd = builtin_keyboard,
        .help = "Keyboard scan code to key mapping",
};
