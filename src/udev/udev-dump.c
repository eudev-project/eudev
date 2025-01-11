/*
 * Copyright (C) 2003-2004 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2004-2008 Kay Sievers <kay@vrfy.org>
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
#include <stdio.h>
#include <unistd.h>
#include <grp.h>
#include <pwd.h>

#include "udev.h"
#include "terminal-util.h"

static bool use_colors(void) {
        static int cached = -1;

        if (cached < 0)
                cached = isatty(STDOUT_FILENO) > 0 && !getenv("NO_COLOR") && !streq_ptr(getenv("TERM"), "dumb");
        return cached;
}

static const char *ansi_highlight(void) {
        return use_colors() ? ANSI_HIGHLIGHT_ON : "";
}

static const char *ansi_normal(void) {
        return use_colors() ? ANSI_HIGHLIGHT_OFF : "";
}

void dump_event(struct udev_event *event, FILE *f) {
        struct udev_device *dev = event->dev;
        struct udev_list_entry *entry;
        const char *subsys, *str;
        int ifindex;

        if (!f)
                f = stdout;

        str = udev_device_get_devpath(dev);
        if (str)
                fprintf(f, "%sDevice path:%s\n  %s\n", ansi_highlight(), ansi_normal(), str);

        str = udev_device_get_sysname(dev);
        if (str)
                fprintf(f, "%sDevice name:%s\n  %s\n", ansi_highlight(), ansi_normal(), str);

        str = udev_device_get_sysnum(dev);
        if (str)
                fprintf(f, "%sDevice number:%s\n  %s\n", ansi_highlight(), ansi_normal(), str);

        str = udev_device_get_id_filename(dev);
        if (str)
                fprintf(f, "%sDevice ID:%s\n  %s\n", ansi_highlight(), ansi_normal(), str);

        subsys = udev_device_get_subsystem(dev);
        if (subsys)
                fprintf(f, "%sSubsystem:%s\n  %s\n", ansi_highlight(), ansi_normal(), subsys);

        str = udev_device_get_devtype(dev);
        if (str)
                fprintf(f, "%sDevice type:%s\n  %s\n", ansi_highlight(), ansi_normal(), str);

        str = udev_device_get_driver(dev);
        if (str)
                fprintf(f, "%sDevice driver:%s\n  %s\n", ansi_highlight(), ansi_normal(), str);

        str = udev_device_get_devnode(dev);
        if (str) {
                dev_t devnum = udev_device_get_devnum(dev);
                /* The owner, group and mode are not determined for remove events, see
                 * udev_event_execute_rules(). */
                bool perms = major(devnum) > 0 && !streq_ptr(udev_device_get_action(dev), "remove");
                /* When not set by the rules processed so far, udev_event_execute_rules() will use these. */
                uid_t uid = event->owner_set ? event->uid : udev_device_get_devnode_uid(dev);
                gid_t gid = event->group_set ? event->gid : udev_device_get_devnode_gid(dev);
                mode_t mode = event->mode_set ? event->mode :
                              udev_device_get_devnode_mode(dev) > 0 ? udev_device_get_devnode_mode(dev) :
                              gid > 0 ? 0660 : 0600;

                if (major(devnum) > 0)
                        fprintf(f, "%sDevice node:%s\n  %s (%s %u:%u)\n", ansi_highlight(), ansi_normal(), str,
                                streq_ptr(subsys, "block") ? "block" : "char", major(devnum), minor(devnum));

                if (perms) {
                        struct passwd *pw = getpwuid(uid);

                        fprintf(f, "%sDevice node owner user:%s\n  %s (uid="UID_FMT")\n", ansi_highlight(), ansi_normal(),
                                pw ? pw->pw_name : "n/a", uid);
                }

                if (perms) {
                        struct group *gr = getgrgid(gid);

                        fprintf(f, "%sDevice node owner group:%s\n  %s (gid="GID_FMT")\n", ansi_highlight(), ansi_normal(),
                                gr ? gr->gr_name : "n/a", gid);
                }

                if (perms)
                        fprintf(f, "%sDevice node permission:%s\n  %04o\n", ansi_highlight(), ansi_normal(), mode);

                if (udev_device_get_devlinks_list_entry(dev)) {
                        fprintf(f, "%sDevice node symlinks:%s (priority=%i)\n", ansi_highlight(), ansi_normal(),
                                udev_device_get_devlink_priority(dev));
                        udev_list_entry_foreach(entry, udev_device_get_devlinks_list_entry(dev))
                                fprintf(f, "  %s\n", udev_list_entry_get_name(entry));
                }

                if (udev_list_get_entry(&event->seclabel_list)) {
                        fprintf(f, "%sDevice node security label:%s\n", ansi_highlight(), ansi_normal());
                        udev_list_entry_foreach(entry, udev_list_get_entry(&event->seclabel_list))
                                fprintf(f, "  %s : %s\n", udev_list_entry_get_name(entry), udev_list_entry_get_value(entry));
                }

                fprintf(f, "%sInotify watch:%s\n  %s\n", ansi_highlight(), ansi_normal(),
                        event->inotify_watch ? "enabled" : "disabled");
        }

        ifindex = udev_device_get_ifindex(dev);
        if (ifindex > 0) {
                fprintf(f, "%sNetwork interface index:%s\n  %i\n", ansi_highlight(), ansi_normal(), ifindex);

                if (!isempty(event->name))
                        fprintf(f, "%sNetwork interface name:%s\n  %s\n", ansi_highlight(), ansi_normal(), event->name);
        }

        if (udev_list_get_entry(&event->written_sysattr_list)) {
                fprintf(f, "%sWritten sysfs attributes:%s\n", ansi_highlight(), ansi_normal());
                udev_list_entry_foreach(entry, udev_list_get_entry(&event->written_sysattr_list))
                        fprintf(f, "  %s : %s\n", udev_list_entry_get_name(entry), udev_list_entry_get_value(entry));
        }

        if (udev_list_get_entry(&event->written_sysctl_list)) {
                fprintf(f, "%sWritten sysctl entries:%s\n", ansi_highlight(), ansi_normal());
                udev_list_entry_foreach(entry, udev_list_get_entry(&event->written_sysctl_list))
                        fprintf(f, "  %s : %s\n", udev_list_entry_get_name(entry), udev_list_entry_get_value(entry));
        }

        if (udev_device_get_tags_list_entry(dev)) {
                fprintf(f, "%sTags:%s\n", ansi_highlight(), ansi_normal());
                udev_list_entry_foreach(entry, udev_device_get_tags_list_entry(dev))
                        fprintf(f, "  %s\n", udev_list_entry_get_name(entry));
        }

        if (udev_device_get_properties_list_entry(dev)) {
                fprintf(f, "%sProperties:%s\n", ansi_highlight(), ansi_normal());
                udev_list_entry_foreach(entry, udev_device_get_properties_list_entry(dev))
                        fprintf(f, "  %s=%s\n", udev_list_entry_get_name(entry), udev_list_entry_get_value(entry));
        }

        if (udev_list_get_entry(&event->run_list)) {
                fprintf(f, "%sQueued commands:%s\n", ansi_highlight(), ansi_normal());
                udev_list_entry_foreach(entry, udev_list_get_entry(&event->run_list)) {
                        if (udev_list_entry_get_num(entry) < UDEV_BUILTIN_MAX)
                                fprintf(f, "  RUN{builtin} : %s\n", udev_list_entry_get_name(entry));
                        else
                                fprintf(f, "  RUN{program} : %s\n", udev_list_entry_get_name(entry));
                }
        }
}
