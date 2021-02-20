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

#include "set.h"
#include "udev.h"
#include "udev-util.h"
#include "udevadm-util.h"
#include "util.h"

static int verbose;
static int dry_run;
static bool arg_quiet = false;

static int write_uevent(const char *filename, const char *action) {
        _cleanup_close_ int fd = -1;

        fd = open(filename, O_WRONLY|O_CLOEXEC);
        if (fd < 0)
                return -errno;
        if (write(fd, action, strlen(action)) < 0)
                return -errno;
        return 0;
}

static int exec_list(struct udev_enumerate *udev_enumerate, const char *action, Set *settle_set) {
        struct udev_list_entry *entry;
        int r, ret = 0;

        udev_list_entry_foreach(entry, udev_enumerate_get_list_entry(udev_enumerate)) {
                char filename[UTIL_PATH_SIZE];
                const char *syspath;

                syspath = udev_list_entry_get_name(entry);
                if (verbose)
                        printf("%s\n", syspath);
                if (dry_run)
                        continue;

                strscpyl(filename, sizeof(filename), syspath, "/uevent", NULL);
                r = write_uevent(filename, action);
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
                }

                if (settle_set != NULL && set_put_strdup(settle_set, syspath) < 0)
                        return log_oom();
        }

        return ret;
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
        printf("%s trigger OPTIONS\n\n"
               "Request events from the kernel.\n\n"
               "  -h --help                         Show this help\n"
               "     --version                      Show package version\n"
               "  -v --verbose                      Print the list of devices while running\n"
               "  -n --dry-run                      Do not actually trigger the events\n"
               "  -q --quiet                        Suppress error logging in triggering events\n"
               "  -t --type=                        Type of events to trigger\n"
               "          devices                     sysfs devices (default)\n"
               "          subsystems                  sysfs subsystems and drivers\n"
               "          all                         sysfs devices, subsystems, and drivers\n"
               "  -c --action=ACTION                Event action value, default is \"change\"\n"
               "  -s --subsystem-match=SUBSYSTEM    Trigger devices from a matching subsystem\n"
               "  -S --subsystem-nomatch=SUBSYSTEM  Exclude devices from a matching subsystem\n"
               "  -a --attr-match=FILE[=VALUE]      Trigger devices with a matching attribute\n"
               "  -A --attr-nomatch=FILE[=VALUE]    Exclude devices with a matching attribute\n"
               "  -p --property-match=KEY=VALUE     Trigger devices with a matching property\n"
               "  -g --tag-match=TAG                Trigger devices with a matching tag\n"
               "  -y --sysname-match=NAME           Trigger devices with this /sys path\n"
               "     --name-match=NAME              Trigger devices with this /dev name\n"
               "  -b --parent-match=NAME            Trigger devices with that parent device\n"
               "  -w --settle                       Wait for the triggered events to complete\n"
               "     --wait-daemon[=SECONDS]        Wait for udevd daemon to be initialized\n"
               "                                    before triggering uevents\n"
               , program_invocation_short_name);
}

static int adm_trigger(struct udev *udev, int argc, char *argv[]) {
        enum {
                ARG_NAME = 0x100,
                ARG_PING,
        };

        static const struct option options[] = {
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
                { "settle",            no_argument,       NULL, 'w'      },
                { "wait-daemon",       optional_argument, NULL, ARG_PING },
                { "help",              no_argument,       NULL, 'h'      },
                { "version",           no_argument,       NULL, 'V'      },
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
        bool settle = false, ping = false;
        _cleanup_set_free_free_ Set *settle_set = NULL;
        int c, r;

        udev_enumerate = udev_enumerate_new(udev);
        if (udev_enumerate == NULL)
                return 1;

        while ((c = getopt_long(argc, argv, "vnqt:c:s:S:a:A:p:g:y:b:wh", options, NULL)) >= 0) {
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
                        if (!nulstr_contains("add\0" "remove\0" "change\0", optarg)) {
                                log_error("unknown action '%s'", optarg);
                                return 2;
                        } else
                                action = optarg;

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
                case 'b': {
                        _cleanup_udev_device_unref_ struct udev_device *dev;

                        dev = find_device(udev, optarg, "/sys");
                        if (dev == NULL) {
                                log_error("unable to open the device '%s'", optarg);
                                return 2;
                        }

                        udev_enumerate_add_match_parent(udev_enumerate, dev);
                        break;
                }
                case 'w':
                        settle = true;
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

                case ARG_NAME: {
                        _cleanup_udev_device_unref_ struct udev_device *dev;

                        dev = find_device(udev, optarg, "/dev/");
                        if (dev == NULL) {
                                log_error("unable to open the device '%s'", optarg);
                                return 2;
                        }

                        udev_enumerate_add_match_parent(udev_enumerate, dev);
                        break;
                }

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

        if (ping) {
                _cleanup_udev_ctrl_unref_ struct udev_ctrl *uctrl = NULL;
                int timeout;

                uctrl = udev_ctrl_new(udev);
                if (!uctrl) {
                        log_oom();
                        return 1;
                }

                /* The control socket takes the timeout in seconds, round up. */
                if (ping_timeout_usec == USEC_INFINITY || ping_timeout_usec / USEC_PER_SEC >= INT_MAX / MSEC_PER_SEC)
                        timeout = -1;
                else
                        timeout = (ping_timeout_usec + USEC_PER_SEC - 1) / USEC_PER_SEC;

                r = udev_ctrl_send_ping(uctrl, timeout);
                if (r < 0) {
                        log_error_errno(r, "Failed to connect to udev daemon: %m");
                        return 1;
                }
        }

        for (; optind < argc; optind++) {
                _cleanup_udev_device_unref_ struct udev_device *dev;

                dev = find_device(udev, argv[optind], NULL);
                if (dev == NULL) {
                        log_error("unable to open the device '%s'", argv[optind]);
                        return 2;
                }

                udev_enumerate_add_match_parent(udev_enumerate, dev);
        }

        if (settle) {
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
                udev_enumerate_scan_devices(udev_enumerate);
                break;
        case TYPE_ALL:
                udev_enumerate_scan_subsystems(udev_enumerate);
                udev_enumerate_scan_devices(udev_enumerate);
                break;
        default:
                assert_not_reached("device_type");
        }
        r = exec_list(udev_enumerate, action, settle_set);
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
                                const char *syspath = NULL;
                                char *saved;

                                device = udev_monitor_receive_device(udev_monitor);
                                if (device == NULL)
                                        continue;

                                syspath = udev_device_get_syspath(device);
                                if (verbose)
                                        printf("settle %s\n", syspath);
                                saved = set_remove(settle_set, syspath);
                                if (saved == NULL)
                                        log_debug("Got epoll event on syspath %s not present in syspath set", syspath);
                                free(saved);
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
