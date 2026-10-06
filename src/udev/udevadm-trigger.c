/*
 * Copyright (C) 2008-2009 Kay Sievers <kay@vrfy.org>
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

#include <ctype.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "pager.h"
#include "set.h"
#include "udev.h"
#include "udev-util.h"
#include "udevadm-util.h"
#include "util.h"
#include "virt.h"

static int verbose;
static int dry_run;
static bool arg_quiet = false;
static bool arg_uuid = false;
static bool arg_settle = false;
static bool arg_include_parents = false;

static enum {
        MATCH_INITIALIZED_ALL = -1, /* all devices */
        MATCH_INITIALIZED_NO,       /* only devices without a db entry */
        MATCH_INITIALIZED_YES,      /* only devices with a db entry */
} arg_initialized_match = MATCH_INITIALIZED_ALL;

/* "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" and the terminating NUL */
#define UUID_STRING_MAX 37

/* Like sd_device_get_trigger_uuid(): gets the UUID attached to a uevent triggered from userspace,
 * in lowercase UUID format. Returns -ENOENT if the uevent is not a synthetic one, and -ENODATA if
 * it was triggered without a UUID. */
static int device_get_trigger_uuid(struct udev_device *dev, char ret[static UUID_STRING_MAX]) {
        const char *s;
        size_t i, n = 0;
        bool dashes;

        s = udev_device_get_property_value(dev, "SYNTH_UUID");
        if (!s)
                return -ENOENT;

        /* SYNTH_UUID=0 is set whenever a device is triggered by userspace without specifying a UUID */
        if (streq(s, "0"))
                return -ENODATA;

        /* Accept the UUID format and 32 plain hexadecimal digits, as sd_id128_from_string() does. */
        dashes = strlen(s) == 36;
        if (!dashes && strlen(s) != 32)
                return -EINVAL;

        for (i = 0; s[i] != '\0'; i++) {
                if (dashes && IN_SET(i, 8, 13, 18, 23)) {
                        if (s[i] != '-')
                                return -EINVAL;
                        continue;
                }
                if (!isxdigit((unsigned char) s[i]))
                        return -EINVAL;
                if (IN_SET(n, 8, 13, 18, 23))
                        ret[n++] = '-';
                ret[n++] = tolower((unsigned char) s[i]);
        }
        ret[n] = '\0';

        return 0;
}

static int write_uevent(const char *filename, const char *action, const char *uuid) {
        _cleanup_close_ int fd = -1;
        const char *s;

        s = uuid ? strjoina(action, " ", uuid) : action;

        fd = open(filename, O_WRONLY|O_CLOEXEC);
        if (fd < 0)
                return -errno;
        if (write(fd, s, strlen(s)) < 0)
                return -errno;
        return 0;
}

/* Like sd-device-enumerator with prioritized subsystems: the devices of each prioritized subsystem
 * and their parents come first, in the order the subsystems were specified, then all other
 * devices. The devices within each group keep the order of the enumeration. */
static int prioritize_subsystems(struct udev *udev, char **list, char **prioritized_subsystems, char ***ret) {
        _cleanup_hashmap_free_ Hashmap *index = NULL;
        _cleanup_free_ bool *taken = NULL, *group = NULL;
        _cleanup_strv_free_ char **subsystems = NULL;
        char **sorted = NULL, **s;
        size_t n, i, k = 0;
        int r;

        n = strv_length(list);

        taken = new0(bool, n);
        group = new0(bool, n);
        subsystems = new0(char*, n + 1);
        sorted = new0(char*, n + 1);
        index = hashmap_new(&string_hash_ops);
        if (!taken || !group || !subsystems || !sorted || !index) {
                free(sorted);
                return -ENOMEM;
        }

        for (i = 0; i < n; i++) {
                _cleanup_udev_device_unref_ struct udev_device *dev = NULL;
                const char *subsystem = NULL;

                r = hashmap_put(index, list[i], UINT_TO_PTR(i + 1));
                if (r < 0 && r != -EEXIST) {
                        free(sorted);
                        return r;
                }

                dev = udev_device_new_from_syspath(udev, list[i]);
                if (dev)
                        subsystem = udev_device_get_subsystem(dev);
                /* Keep the array NULL terminated for strv_free(), use "" for no subsystem. */
                subsystems[i] = strdup(subsystem ?: "");
                if (!subsystems[i]) {
                        free(sorted);
                        return -ENOMEM;
                }
        }

        STRV_FOREACH(s, prioritized_subsystems) {
                for (i = 0; i < n; i++) {
                        _cleanup_free_ char *p = NULL;

                        if (taken[i] || !streq(subsystems[i], *s))
                                continue;

                        group[i] = true;

                        /* Also take the parents, which are in the list. */
                        p = strdup(list[i]);
                        if (!p) {
                                free(sorted);
                                return -ENOMEM;
                        }
                        for (;;) {
                                char *slash;
                                unsigned j;

                                slash = strrchr(p, '/');
                                if (!slash || slash == p)
                                        break;
                                *slash = '\0';

                                j = PTR_TO_UINT(hashmap_get(index, p));
                                if (j > 0 && !taken[j - 1])
                                        group[j - 1] = true;
                        }
                }

                for (i = 0; i < n; i++)
                        if (group[i]) {
                                sorted[k++] = list[i];
                                taken[i] = true;
                                group[i] = false;
                        }
        }

        for (i = 0; i < n; i++)
                if (!taken[i])
                        sorted[k++] = list[i];

        /* The strings are now owned by the new list. */
        for (i = 0; i < n; i++)
                list[i] = NULL;

        *ret = sorted;
        return 0;
}

/* Like sd_device_enumerator_add_all_parents(): adds the parents of the listed devices, even if they
 * do not match the filters, and sorts the list again in the order of the enumerator. */
static int include_parents(struct udev *udev, char ***list) {
        _cleanup_udev_enumerate_unref_ struct udev_enumerate *e = NULL;
        _cleanup_set_free_free_ Set *added = NULL;
        struct udev_list_entry *entry;
        char **l = NULL, **s;
        size_t n = 0;
        int r;

        e = udev_enumerate_new(udev);
        added = set_new(&string_hash_ops);
        if (!e || !added)
                return -ENOMEM;

        STRV_FOREACH(s, *list) {
                _cleanup_udev_device_unref_ struct udev_device *dev = NULL;
                struct udev_device *parent;

                /* The device may be gone already, this is necessarily racy, so skip it then. */
                dev = udev_device_new_from_syspath(udev, *s);
                if (!dev)
                        continue;

                (void) udev_enumerate_add_syspath(e, *s);

                for (parent = udev_device_get_parent(dev); parent; parent = udev_device_get_parent(parent)) {
                        const char *syspath = udev_device_get_syspath(parent);

                        /* All parents of an already added parent are added, too. */
                        if (set_contains(added, syspath))
                                break;

                        r = set_put_strdup(added, syspath);
                        if (r < 0)
                                return r;

                        (void) udev_enumerate_add_syspath(e, syspath);
                }
        }

        udev_list_entry_foreach(entry, udev_enumerate_get_list_entry(e))
                n++;

        l = new0(char*, n + 1);
        if (!l)
                return -ENOMEM;

        n = 0;
        udev_list_entry_foreach(entry, udev_enumerate_get_list_entry(e)) {
                l[n] = strdup(udev_list_entry_get_name(entry));
                if (!l[n]) {
                        strv_free(l);
                        return -ENOMEM;
                }
                n++;
        }

        strv_free(*list);
        *list = l;
        return 0;
}

/* Like add_device_match() of systemd: the device s, also below prefix, is a parent device whose devices are
 * triggered, see scan_devices(). */
static int add_device_match(struct udev *udev, const char *s, const char *prefix, char ***parents) {
        _cleanup_udev_device_unref_ struct udev_device *dev = NULL;

        dev = find_device(udev, s, prefix);
        if (!dev)
                return log_error_errno(errno > 0 ? errno : ENODEV, "Failed to open the device '%s': %m", s);

        if (strv_extend(parents, udev_device_get_syspath(dev)) < 0)
                return log_oom();

        return 0;
}

/* libudev matches only one parent device, so scan the devices below each parent, the results are
 * merged by the enumerator. */
static void scan_devices(struct udev *udev, struct udev_enumerate *udev_enumerate, char **parents) {
        char **p;

        if (strv_isempty(parents)) {
                udev_enumerate_scan_devices(udev_enumerate);
                return;
        }

        STRV_FOREACH(p, parents) {
                _cleanup_udev_device_unref_ struct udev_device *dev = NULL;

                dev = udev_device_new_from_syspath(udev, *p);
                if (!dev)
                        continue;

                udev_enumerate_add_match_parent(udev_enumerate, dev);
                udev_enumerate_scan_devices(udev_enumerate);
        }
}

/* Returns the syspaths of the devices to trigger, in the order to trigger them. */
static int build_list(struct udev *udev, struct udev_enumerate *udev_enumerate,
                      char **prioritized_subsystems, char ***ret) {
        _cleanup_strv_free_ char **list = NULL;
        struct udev_list_entry *entry;
        size_t n = 0;
        int r;

        udev_list_entry_foreach(entry, udev_enumerate_get_list_entry(udev_enumerate))
                n++;

        list = new0(char*, n + 1);
        if (!list)
                return -ENOMEM;

        n = 0;
        udev_list_entry_foreach(entry, udev_enumerate_get_list_entry(udev_enumerate)) {
                const char *syspath = udev_list_entry_get_name(entry);

                if (arg_initialized_match != MATCH_INITIALIZED_ALL) {
                        _cleanup_udev_device_unref_ struct udev_device *dev = NULL;

                        /* The device may be gone already, this is necessarily racy, so skip it then. */
                        dev = udev_device_new_from_syspath(udev, syspath);
                        if (!dev)
                                continue;

                        if ((udev_device_get_is_initialized(dev) > 0) != (arg_initialized_match == MATCH_INITIALIZED_YES))
                                continue;
                }

                list[n] = strdup(syspath);
                if (!list[n])
                        return -ENOMEM;
                n++;
        }

        if (arg_include_parents) {
                r = include_parents(udev, &list);
                if (r < 0)
                        return r;
        }

        if (!strv_isempty(prioritized_subsystems)) {
                char **sorted = NULL;

                r = prioritize_subsystems(udev, list, prioritized_subsystems, &sorted);
                if (r < 0)
                        return r;

                strv_free(list);
                list = sorted;
        }

        *ret = list;
        list = NULL;
        return 0;
}

static int exec_list(struct udev *udev, char **list, const char *action, Set *settle_set) {
        _cleanup_strv_free_ char **args = NULL;
        char **entry;
        bool warned_uuid = false;
        int r, ret = 0;

        r = device_build_default_trigger_args(/* with_timestamp= */ true, &args);
        if (r < 0)
                return log_oom();

        STRV_FOREACH(entry, list) {
                char filename[UTIL_PATH_SIZE];
                char id[UUID_STRING_MAX] = "";
                const char *syspath;
                bool with_uuid = false, sends;

                syspath = *entry;
                if (verbose)
                        printf("%s\n", syspath);
                if (dry_run)
                        continue;

                strscpyl(filename, sizeof(filename), syspath, "/uevent", NULL);

                /* Like systemd, trigger every uevent with a random UUID, which --settle uses to recognize our
                 * own uevent and --uuid prints, and with the arguments that tell who triggered it, which the
                 * kernel passes on as SYNTH_ARG_*=; the arguments need the UUID.
                 *
                 * eudev: systemd assumes that kernels before 4.13, which do not know the UUID logic, refuse
                 * the write with EINVAL, and then triggers the uevents without UUIDs. But they accept it,
                 * and send no uevent at all, so --settle would wait forever. On a kernel that reports a
                 * version before 4.13, which may have the support backported, uevent_trigger_with_args()
                 * finds out with the first uevent whether the kernel supports UUIDs (or with the next ones,
                 * as long as their uevents do not tell), and triggers the uevents without them and without
                 * the arguments if it does not; then --settle waits for an event of the device, as for a
                 * uevent that was triggered without a UUID before it was known.
                 *
                 * Also unlike systemd, which then prints a UUID and waits forever with --settle, a device
                 * without a subsystem or a hidden block device, for which the kernel sends no uevent, is
                 * triggered without a UUID, and not waited for, see syspath_sends_uevents(). */
                sends = syspath_sends_uevents(syspath);
                if (sends) {
                        r = uevent_trigger_with_args(udev, syspath, action, args, id);
                        with_uuid = r > 0;
                        if (r == 0 && arg_uuid) {
                                if (uevent_trigger_uuid_supported() != 0)
                                        /* e.g. the kernel refused the uevent with the UUID, as it did
                                         * not fit, see uevent_trigger_fitting(), or the uevents of the
                                         * probe did not tell whether the kernel supports UUIDs, e.g. as
                                         * the kernel suppresses the uevents of the device */
                                        log_warning("%s: Could not trigger the uevent with a UUID, triggered it without one.",
                                                    eudev_basename(syspath));
                                else if (!warned_uuid) {
                                        log_warning("The kernel does not support UUIDs of synthetic uevents (its synthetic uevents carry no SYNTH_UUID=, as before Linux 4.13), triggering uevents without them.");
                                        warned_uuid = true;
                                }
                        }
                } else
                        r = write_uevent(filename, action, NULL);
                if (r < 0) {
                        /* ENOENT may be returned when a device does not have /uevent or is already
                         * removed. Hence, this is logged at debug level and ignored.
                         *
                         * ENODEV may be returned by some buggy device drivers e.g. /sys/devices/vio.
                         * See,
                         * https://github.com/systemd/systemd/issues/13652#issuecomment-535129791 and
                         * https://bugs.launchpad.net/ubuntu/+source/linux/+bug/1845319.
                         * So, this error is ignored, but logged at warning level to encourage people to
                         * fix the driver.
                         *
                         * EROFS is returned when /sys is read only. In that case, all subsequent
                         * writes will also fail, hence return immediately.
                         *
                         * EACCES or EPERM may be returned when this is invoked by non-privileged user.
                         * We do NOT return immediately, but continue operation and propagate the error.
                         * Why? Some device can be owned by a user, e.g., network devices configured in
                         * a network namespace. See, https://github.com/systemd/systemd/pull/18559 and
                         * https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=ebb4a4bf76f164457184a3f43ebc1552416bc823
                         *
                         * All other errors are logged at error level, but let's continue the operation,
                         * and propagate the error.
                         */

                        bool ignore = IN_SET(r, -ENOENT, -ENODEV);
                        int level =
                                arg_quiet ? LOG_DEBUG :
                                r == -ENOENT ? LOG_DEBUG :
                                r == -ENODEV ? LOG_WARNING : LOG_ERR;

                        log_full_errno(level, r, "%s: Failed to write '%s' to '%s'%s: %m",
                                       eudev_basename(syspath), action, filename, ignore ? ", ignoring" : "");

                        if (r == -EROFS)
                                return r;
                        if (ret == 0 && !ignore)
                                ret = r;
                        continue;
                } else
                        log_debug("%s: Triggered device with action '%s'.", eudev_basename(syspath), action);

                /* If the user asked for it, write event UUID to stdout */
                if (arg_uuid && with_uuid)
                        printf("%s\n", id);

                /* Wait for the UUID if the kernel supports it, as the device may be renamed while the
                 * event is processed. Otherwise, wait for an event for the device. */
                if (settle_set != NULL && !sends)
                        log_debug("%s: The device has no subsystem or is a hidden block device, the kernel sends no uevent for it, not waiting for it.",
                                  eudev_basename(syspath));
                else if (settle_set != NULL && set_put_strdup(settle_set, with_uuid ? id : syspath) < 0)
                        return log_oom();
        }

        return ret;
}

/* Returns true if the event is one of the triggered ones, and removes it from the set. */
static bool settle_device(Set *settle_set, struct udev_device *dev) {
        _cleanup_free_ char *saved = NULL;
        char id[UUID_STRING_MAX] = "";
        const char *syspath;

        syspath = udev_device_get_syspath(dev);

        if (device_get_trigger_uuid(dev, id) >= 0) {
                saved = set_remove(settle_set, id);
                if (!saved) {
                        log_debug("Got uevent not matching expected UUID, ignoring.");
                        return false;
                }
        } else {
                saved = set_remove(settle_set, syspath);
                if (!saved) {
                        const char *old_sysname;

                        /* When the device is renamed, the new name is broadcast, and the old name is saved
                         * in INTERFACE_OLD. */
                        old_sysname = udev_device_get_property_value(dev, "INTERFACE_OLD");
                        if (old_sysname) {
                                _cleanup_free_ char *dir = NULL, *old_syspath = NULL;

                                dir = dirname_malloc(syspath);
                                if (dir)
                                        old_syspath = strjoin(dir, "/", old_sysname, NULL);
                                if (!old_syspath) {
                                        log_oom();
                                        return false;
                                }

                                saved = set_remove(settle_set, old_syspath);
                        }
                }
                if (!saved) {
                        log_debug("Got uevent for unexpected device, ignoring.");
                        return false;
                }
        }

        if (verbose)
                printf("settle %s\n", syspath);

        /* without UUIDs, see exec_list(), there is none to print */
        if (arg_uuid && id[0] != '\0')
                printf("settle %s\n", id);

        return true;
}

static const char *keyval(const char *str, const char **val, char *buf, size_t size) {
        char *pos;

        strscpy(buf, size,str);
        pos = strchr(buf, '=');
        if (pos != NULL) {
                pos[0] = 0;
                pos++;
        }
        *val = pos;
        return buf;
}

static void help(void) {
        pager_open(0);

        printf("%s trigger OPTIONS\n\n"
               "Request events from the kernel.\n\n"
               "  -h --help                         Show this help\n"
               "  -V --version                      Show package version\n"
               "  -v --verbose                      Print the list of devices while running\n"
               "  -n --dry-run                      Do not actually trigger the events\n"
               "  -q --quiet                        Suppress error logging in triggering events\n"
               "  -t --type=                        Type of events to trigger\n"
               "          devices                     sysfs devices (default)\n"
               "          subsystems                  sysfs subsystems and drivers\n"
               "          all                         sysfs devices, subsystems, and drivers\n"
               "  -c --action=ACTION|help           Event action value, default is \"change\"\n"
               "  -s --subsystem-match=SUBSYSTEM    Trigger devices from a matching subsystem\n"
               "  -S --subsystem-nomatch=SUBSYSTEM  Exclude devices from a matching subsystem\n"
               "  -a --attr-match=FILE[=VALUE]      Trigger devices with a matching attribute\n"
               "  -A --attr-nomatch=FILE[=VALUE]    Exclude devices with a matching attribute\n"
               "  -p --property-match=KEY=VALUE     Trigger devices with a matching property\n"
               "  -g --tag-match=TAG                Trigger devices with a matching tag\n"
               "  -y --sysname-match=NAME           Trigger devices with this /sys path\n"
               "     --name-match=NAME              Trigger devices with this /dev name\n"
               "  -b --parent-match=NAME            Trigger devices with that parent device\n"
               "     --include-parents              Trigger parent devices of found devices\n"
               "     --initialized-match            Trigger devices that are already initialized\n"
               "     --initialized-nomatch          Trigger devices that are not initialized yet\n"
               "  -w --settle                       Wait for the triggered events to complete\n"
               "     --wait-daemon[=SECONDS]        Wait for udevd daemon to be initialized\n"
               "                                    before triggering uevents\n"
               "     --uuid                         Print synthetic uevent UUID\n"
               "     --prioritized-subsystem=SUBSYSTEM[,SUBSYSTEM…]\n"
               "                                    Trigger devices from a matching subsystem first\n"
               , program_invocation_short_name);
        print_man_page_link();
}

static int adm_trigger(struct udev *udev, int argc, char *argv[]) {
        enum {
                ARG_NAME = 0x100,
                ARG_PING,
                ARG_UUID,
                ARG_PRIORITIZED_SUBSYSTEM,
                ARG_INITIALIZED_MATCH,
                ARG_INITIALIZED_NOMATCH,
                ARG_INCLUDE_PARENTS,
        };

        static const struct option options[] = {
                { "help",              no_argument,       NULL, 'h'      },
                { "version",           no_argument,       NULL, 'V'      },
                { "verbose",           no_argument,       NULL, 'v'      },
                { "dry-run",           no_argument,       NULL, 'n'      },
                { "quiet",             no_argument,       NULL, 'q'      },
                { "type",              required_argument, NULL, 't'      },
                { "action",            required_argument, NULL, 'c'      },
                { "subsystem-match",   required_argument, NULL, 's'      },
                { "subsystem-nomatch", required_argument, NULL, 'S'      },
                { "attr-match",        required_argument, NULL, 'a'      },
                { "attr-nomatch",      required_argument, NULL, 'A'      },
                { "property-match",    required_argument, NULL, 'p'      },
                { "tag-match",         required_argument, NULL, 'g'      },
                { "sysname-match",     required_argument, NULL, 'y'      },
                { "name-match",        required_argument, NULL, ARG_NAME },
                { "parent-match",      required_argument, NULL, 'b'      },
                { "include-parents",   no_argument,       NULL, ARG_INCLUDE_PARENTS },
                { "initialized-match", no_argument,       NULL, ARG_INITIALIZED_MATCH },
                { "initialized-nomatch", no_argument,     NULL, ARG_INITIALIZED_NOMATCH },
                { "settle",            no_argument,       NULL, 'w'      },
                { "wait-daemon",       optional_argument, NULL, ARG_PING },
                { "uuid",              no_argument,       NULL, ARG_UUID },
                { "prioritized-subsystem", required_argument, NULL, ARG_PRIORITIZED_SUBSYSTEM },
                {}
        };
        enum {
                TYPE_DEVICES,
                TYPE_SUBSYSTEMS,
                TYPE_ALL,
        } device_type = TYPE_DEVICES;
        const char *action = "change";
        _cleanup_udev_enumerate_unref_ struct udev_enumerate *udev_enumerate = NULL;
        _cleanup_udev_monitor_unref_ struct udev_monitor *udev_monitor = NULL;
        _cleanup_close_ int fd_ep = -1;
        int fd_udev = -1;
        struct epoll_event ep_udev;
        usec_t ping_timeout_usec = 5 * USEC_PER_SEC;
        bool ping = false;
        _cleanup_set_free_free_ Set *settle_set = NULL;
        _cleanup_strv_free_ char **list = NULL, **prioritized_subsystems = NULL, **parents = NULL;
        _cleanup_strv_free_ char **parent_match = NULL, **name_match = NULL;
        char **m;
        int c, r;

        udev_enumerate = udev_enumerate_new(udev);
        if (udev_enumerate == NULL)
                return 1;

        while ((c = getopt_long_log(argc, argv, "vnqt:c:s:S:a:A:p:g:y:b:whV", options)) >= 0) {
                const char *key;
                const char *val;
                char buf[UTIL_PATH_SIZE];

                switch (c) {
                case 'v':
                        verbose = 1;
                        break;
                case 'n':
                        dry_run = 1;
                        break;
                case 'q':
                        arg_quiet = true;
                        break;
                case 't':
                        if (streq(optarg, "devices"))
                                device_type = TYPE_DEVICES;
                        else if (streq(optarg, "subsystems"))
                                device_type = TYPE_SUBSYSTEMS;
                        else if (streq(optarg, "all"))
                                device_type = TYPE_ALL;
                        else {
                                log_error("unknown type --type=%s", optarg);
                                return 2;
                        }
                        break;
                case 'c':
                        r = parse_device_action(optarg, &action);
                        if (r < 0)
                                return 1;
                        if (r == 0)
                                return 0;
                        break;
                case 's':
                        udev_enumerate_add_match_subsystem(udev_enumerate, optarg);
                        break;
                case 'S':
                        udev_enumerate_add_nomatch_subsystem(udev_enumerate, optarg);
                        break;
                case 'a':
                        key = keyval(optarg, &val, buf, sizeof(buf));
                        udev_enumerate_add_match_sysattr(udev_enumerate, key, val);
                        break;
                case 'A':
                        key = keyval(optarg, &val, buf, sizeof(buf));
                        udev_enumerate_add_nomatch_sysattr(udev_enumerate, key, val);
                        break;
                case 'p':
                        key = keyval(optarg, &val, buf, sizeof(buf));
                        udev_enumerate_add_match_property(udev_enumerate, key, val);
                        break;
                case 'g':
                        udev_enumerate_add_match_tag(udev_enumerate, optarg);
                        break;
                case 'y':
                        udev_enumerate_add_match_sysname(udev_enumerate, optarg);
                        break;
                case 'b':
                        /* the device is looked up after the check for a chroot */
                        if (strv_extend(&parent_match, optarg) < 0) {
                                log_oom();
                                return 1;
                        }
                        break;
                case 'w':
                        arg_settle = true;
                        break;

                case ARG_UUID:
                        arg_uuid = true;
                        break;

                case ARG_INCLUDE_PARENTS:
                        arg_include_parents = true;
                        break;

                case ARG_INITIALIZED_MATCH:
                case ARG_INITIALIZED_NOMATCH:
                        arg_initialized_match = c == ARG_INITIALIZED_MATCH ? MATCH_INITIALIZED_YES : MATCH_INITIALIZED_NO;
                        break;

                case ARG_PRIORITIZED_SUBSYSTEM:
                        r = strv_split_and_extend(&prioritized_subsystems, optarg, ",", true);
                        if (r < 0) {
                                log_error_errno(r, "Failed to parse prioritized subsystem '%s': %m", optarg);
                                return 1;
                        }
                        break;

                case ARG_PING:
                        ping = true;
                        if (optarg) {
                                r = parse_sec(optarg, &ping_timeout_usec);
                                if (r < 0) {
                                        log_error_errno(r, "Failed to parse timeout value '%s': %m", optarg);
                                        return 1;
                                }
                        }
                        break;

                case ARG_NAME:
                        /* the device is looked up after the check for a chroot */
                        if (strv_extend(&name_match, optarg) < 0) {
                                log_oom();
                                return 1;
                        }
                        break;

                case 'h':
                        help();
                        return 0;
                case 'V':
                        printf("%s\n", UDEV_VERSION);
                        return 0;
                case '?':
                        return 1;
                default:
                        assert_not_reached("Unknown option");
                }
        }

        log_command_call(&udevadm_trigger);

        /* Unlike systemd, the options are parsed first, so that --help, --version and invalid options
         * work in a chroot too, and only the action is skipped there. */
        if (running_in_chroot() > 0) {
                log_info("Running in chroot, ignoring request.");
                return 0;
        }

        /* Like setup_matches() of systemd: the devices given as arguments, then the ones of --name-match=,
         * then the ones of --parent-match=, before udevd is pinged. */
        for (; optind < argc; optind++)
                if (add_device_match(udev, argv[optind], NULL, &parents) < 0)
                        return 1;

        STRV_FOREACH(m, name_match)
                if (add_device_match(udev, *m, "/dev/", &parents) < 0)
                        return 1;

        STRV_FOREACH(m, parent_match)
                if (add_device_match(udev, *m, "/sys", &parents) < 0)
                        return 1;

        if (ping) {
                _cleanup_udev_ctrl_unref_ struct udev_ctrl *uctrl = NULL;
                bool sent;
                int timeout;

                uctrl = udev_ctrl_new(udev);
                if (!uctrl) {
                        log_error_errno(errno > 0 ? errno : ENOMEM, "Failed to initialize udev control: %m");
                        return 1;
                }

                /* The control socket takes the timeout in seconds, round up. */
                if (ping_timeout_usec == USEC_INFINITY || ping_timeout_usec / USEC_PER_SEC >= INT_MAX / MSEC_PER_SEC)
                        timeout = -1;
                else
                        timeout = (ping_timeout_usec + USEC_PER_SEC - 1) / USEC_PER_SEC;

                /* Like systemd v261, unlike settle, a failure to reach udevd, also because it does not run,
                 * is an error; one of waiting for its reply is told apart. */
                r = udev_ctrl_send_ping_full(uctrl, timeout, &sent);
                if (r < 0) {
                        log_error_errno(r, sent ? "Failed to wait for daemon to reply: %m" :
                                                  "Failed to connect to udev daemon: %m");
                        return 1;
                }
        }

        if (arg_settle) {
                fd_ep = epoll_create1(EPOLL_CLOEXEC);
                if (fd_ep < 0) {
                        log_error_errno(errno, "error creating epoll fd: %m");
                        return 1;
                }

                udev_monitor = udev_monitor_new_from_netlink(udev, "udev");
                if (udev_monitor == NULL) {
                        log_error("error: unable to create netlink socket");
                        return 3;
                }
                fd_udev = udev_monitor_get_fd(udev_monitor);

                if (udev_monitor_enable_receiving(udev_monitor) < 0) {
                        log_error("error: unable to subscribe to udev events");
                        return 4;
                }

                ep_udev = (struct epoll_event) { .events = EPOLLIN, .data.fd = fd_udev };
                if (epoll_ctl(fd_ep, EPOLL_CTL_ADD, fd_udev, &ep_udev) < 0) {
                        log_error_errno(errno, "fail to add fd to epoll: %m");
                        return 5;
                }

                settle_set = set_new(&string_hash_ops);
                if (settle_set == NULL) {
                        log_oom();
                        return 1;
                }
        }

        switch (device_type) {
        case TYPE_SUBSYSTEMS:
                udev_enumerate_scan_subsystems(udev_enumerate);
                break;
        case TYPE_DEVICES:
                scan_devices(udev, udev_enumerate, parents);
                break;
        case TYPE_ALL:
                udev_enumerate_scan_subsystems(udev_enumerate);
                scan_devices(udev, udev_enumerate, parents);
                break;
        default:
                assert_not_reached("device_type");
        }
        r = build_list(udev, udev_enumerate, prioritized_subsystems, &list);
        if (r < 0) {
                log_error_errno(r, "Failed to list the devices to trigger: %m");
                return 1;
        }

        r = exec_list(udev, list, action, settle_set);
        if (r < 0)
                return 1;

        while (!set_isempty(settle_set)) {
                int fdcount;
                struct epoll_event ev[4];
                int i;

                fdcount = epoll_wait(fd_ep, ev, ELEMENTSOF(ev), -1);
                if (fdcount < 0) {
                        if (errno != EINTR)
                                log_error_errno(errno, "error receiving uevent message: %m");
                        continue;
                }

                for (i = 0; i < fdcount; i++) {
                        if (ev[i].data.fd == fd_udev && ev[i].events & EPOLLIN) {
                                _cleanup_udev_device_unref_ struct udev_device *device = NULL;

                                device = udev_monitor_receive_device(udev_monitor);
                                if (device == NULL)
                                        continue;

                                (void) settle_device(settle_set, device);
                        }
                }
        }

        return 0;
}

const struct udevadm_cmd udevadm_trigger = {
        .name = "trigger",
        .cmd = adm_trigger,
        .help = "Request events from the kernel",
};
