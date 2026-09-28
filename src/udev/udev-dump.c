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
#include <string.h>
#include <unistd.h>
#include <grp.h>
#include <pwd.h>

#include "udev.h"
#include "strv.h"
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

static int str_compare(const void *a, const void *b) {
        return strcmp(*(char * const *) a, *(char * const *) b);
}

/* Returns the properties as "KEY=VALUE" strings, like systemd's device_get_properties_strv(): the
 * database version, which udevd passes with the properties, and all properties, sorted as strings,
 * as systemd's dump does. */
static char **dump_properties_strv(struct udev_device *dev) {
        _cleanup_strv_free_ char **l = NULL;
        struct udev_list_entry *entry;
        size_t n = 1, i = 0;

        udev_list_entry_foreach(entry, udev_device_get_properties_list_entry(dev))
                n++;

        l = new0(char *, n + 1);
        if (!l)
                return NULL;

        if (asprintf(&l[i++], "UDEV_DATABASE_VERSION=%u", LATEST_UDEV_DATABASE_VERSION) < 0)
                return NULL;

        udev_list_entry_foreach(entry, udev_device_get_properties_list_entry(dev)) {
                l[i] = strjoin(udev_list_entry_get_name(entry), "=", udev_list_entry_get_value(entry), NULL);
                if (!l[i])
                        return NULL;
                i++;
        }

        qsort(l, i, sizeof(char *), str_compare);
        return TAKE_PTR(l);
}

/* Returns the owner, group and mode of the device node, and whether they apply. They do not for remove
 * events, see udev_event_execute_rules(). When not set by the rules processed so far,
 * udev_event_execute_rules() will use the values of the device. */
static bool event_get_node_perms(struct udev_event *event, uid_t *ret_uid, gid_t *ret_gid, mode_t *ret_mode) {
        struct udev_device *dev = event->dev;
        uid_t uid;
        gid_t gid;
        mode_t mode;

        if (major(udev_device_get_devnum(dev)) == 0 || streq_ptr(udev_device_get_action(dev), "remove"))
                return false;

        uid = event->owner_set ? event->uid : udev_device_get_devnode_uid(dev);
        gid = event->group_set ? event->gid : udev_device_get_devnode_gid(dev);
        if (event->mode_set)
                mode = event->mode;
        else if (udev_device_get_devnode_mode(dev) > 0)
                mode = udev_device_get_devnode_mode(dev);
        else
                mode = gid > 0 ? 0660 : 0600;

        *ret_uid = uid;
        *ret_gid = gid;
        *ret_mode = mode;
        return true;
}

static int dump_event_json(struct udev_event *event, JsonFormatFlags flags, FILE *f) {
        struct udev_device *dev = event->dev;
        struct udev_list_entry *entry;
        _cleanup_strv_free_ char **properties = NULL;
        char **p;
        const char *subsys, *str;
        unsigned sysnum;
        JsonWriter w;
        uid_t uid;
        gid_t gid;
        mode_t mode;
        int ifindex;

        json_writer_init(&w, f, flags);
        json_writer_object_begin(&w);

        str = udev_device_get_devpath(dev);
        if (str)
                json_writer_field_string(&w, "path", str);

        str = udev_device_get_sysname(dev);
        if (str)
                json_writer_field_string(&w, "name", str);

        str = udev_device_get_sysnum(dev);
        if (str && safe_atou(str, &sysnum) >= 0)
                json_writer_field_unsigned(&w, "number", sysnum);

        str = udev_device_get_id_filename(dev);
        if (str)
                json_writer_field_string(&w, "id", str);

        subsys = udev_device_get_subsystem(dev);
        if (subsys)
                json_writer_field_string(&w, "subsystem", subsys);

        str = udev_device_get_devtype(dev);
        if (str)
                json_writer_field_string(&w, "type", str);

        str = udev_device_get_driver(dev);
        if (str)
                json_writer_field_string(&w, "driver", str);

        str = udev_device_get_devnode(dev);
        if (str) {
                dev_t devnum = udev_device_get_devnum(dev);

                json_writer_key(&w, "node");
                json_writer_object_begin(&w);

                json_writer_field_string(&w, "path", str);
                json_writer_field_string(&w, "type", streq_ptr(subsys, "block") ? "block" : "char");

                json_writer_key(&w, "rdev");
                if (major(devnum) > 0) {
                        json_writer_object_begin(&w);
                        json_writer_field_unsigned(&w, "major", major(devnum));
                        json_writer_field_unsigned(&w, "minor", minor(devnum));
                        json_writer_object_end(&w);
                } else
                        json_writer_null(&w);

                if (event_get_node_perms(event, &uid, &gid, &mode)) {
                        struct passwd *pw = getpwuid(uid);
                        struct group *gr = getgrgid(gid);
                        char buf[DECIMAL_STR_MAX(unsigned)];

                        json_writer_key(&w, "owner");
                        json_writer_object_begin(&w);
                        json_writer_field_unsigned(&w, "uid", uid);
                        if (!pw)
                                snprintf(buf, sizeof(buf), UID_FMT, uid);
                        json_writer_field_string(&w, "userName", pw ? pw->pw_name : buf);
                        json_writer_field_unsigned(&w, "gid", gid);
                        if (!gr)
                                snprintf(buf, sizeof(buf), GID_FMT, gid);
                        json_writer_field_string(&w, "groupName", gr ? gr->gr_name : buf);
                        json_writer_object_end(&w);

                        snprintf(buf, sizeof(buf), "%04o", mode & ~S_IFMT);
                        json_writer_field_string(&w, "mode", buf);
                }

                if (udev_device_get_devlinks_list_entry(dev)) {
                        json_writer_field_integer(&w, "symlinkPriority", udev_device_get_devlink_priority(dev));
                        json_writer_key(&w, "symlinks");
                        json_writer_array_begin(&w);
                        udev_list_entry_foreach(entry, udev_device_get_devlinks_list_entry(dev))
                                json_writer_string(&w, udev_list_entry_get_name(entry));
                        json_writer_array_end(&w);
                }

                if (udev_list_get_entry(&event->seclabel_list)) {
                        json_writer_key(&w, "securityLabels");
                        json_writer_array_begin(&w);
                        udev_list_entry_foreach(entry, udev_list_get_entry(&event->seclabel_list)) {
                                json_writer_object_begin(&w);
                                json_writer_field_string(&w, "name", udev_list_entry_get_name(entry));
                                json_writer_field_string(&w, "label", udev_list_entry_get_value(entry));
                                json_writer_object_end(&w);
                        }
                        json_writer_array_end(&w);
                }

                json_writer_field_boolean(&w, "inotifyWatch", event->inotify_watch);

                json_writer_object_end(&w);
        }

        ifindex = udev_device_get_ifindex(dev);
        if (ifindex > 0) {
                json_writer_key(&w, "networkInterface");
                json_writer_object_begin(&w);
                json_writer_field_integer(&w, "index", ifindex);
                if (!isempty(event->name))
                        json_writer_field_string(&w, "name", event->name);
                /* like systemd, all requested names, sorted, also the name of the interface */
                if (!strv_isempty(event->altnames)) {
                        json_writer_key(&w, "alternativeNames");
                        json_writer_array_begin(&w);
                        STRV_FOREACH(p, strv_sort(event->altnames))
                                json_writer_string(&w, *p);
                        json_writer_array_end(&w);
                }
                json_writer_object_end(&w);
        }

        if (udev_list_get_entry(&event->written_sysattr_list)) {
                json_writer_key(&w, "sysfsAttributes");
                json_writer_array_begin(&w);
                udev_list_entry_foreach(entry, udev_list_get_entry(&event->written_sysattr_list)) {
                        json_writer_object_begin(&w);
                        json_writer_field_string(&w, "path", udev_list_entry_get_name(entry));
                        json_writer_field_string(&w, "value", udev_list_entry_get_value(entry));
                        json_writer_object_end(&w);
                }
                json_writer_array_end(&w);
        }

        if (udev_list_get_entry(&event->written_sysctl_list)) {
                json_writer_key(&w, "sysctl");
                json_writer_array_begin(&w);
                udev_list_entry_foreach(entry, udev_list_get_entry(&event->written_sysctl_list)) {
                        json_writer_object_begin(&w);
                        json_writer_field_string(&w, "path", udev_list_entry_get_name(entry));
                        json_writer_field_string(&w, "value", udev_list_entry_get_value(entry));
                        json_writer_object_end(&w);
                }
                json_writer_array_end(&w);
        }

        if (udev_device_get_tags_list_entry(dev)) {
                json_writer_key(&w, "tags");
                json_writer_array_begin(&w);
                udev_list_entry_foreach(entry, udev_device_get_tags_list_entry(dev))
                        json_writer_string(&w, udev_list_entry_get_name(entry));
                json_writer_array_end(&w);
        }

        if (udev_device_get_current_tags_list_entry(dev)) {
                json_writer_key(&w, "currentTags");
                json_writer_array_begin(&w);
                udev_list_entry_foreach(entry, udev_device_get_current_tags_list_entry(dev))
                        json_writer_string(&w, udev_list_entry_get_name(entry));
                json_writer_array_end(&w);
        }

        properties = dump_properties_strv(dev);
        if (!properties)
                return log_oom();
        json_writer_key(&w, "properties");
        json_writer_array_begin(&w);
        STRV_FOREACH(p, properties)
                json_writer_string(&w, *p);
        json_writer_array_end(&w);

        if (udev_list_get_entry(&event->run_list)) {
                json_writer_key(&w, "queuedCommands");
                json_writer_array_begin(&w);
                udev_list_entry_foreach(entry, udev_list_get_entry(&event->run_list)) {
                        json_writer_object_begin(&w);
                        json_writer_field_string(&w, "type",
                                                 udev_list_entry_get_num(entry) < UDEV_BUILTIN_MAX ? "builtin" : "program");
                        json_writer_field_string(&w, "command", udev_list_entry_get_name(entry));
                        json_writer_object_end(&w);
                }
                json_writer_array_end(&w);
        }

        json_writer_object_end(&w);
        return json_writer_finish(&w);
}

int dump_event(struct udev_event *event, JsonFormatFlags flags, FILE *f) {
        struct udev_device *dev = event->dev;
        struct udev_list_entry *entry;
        _cleanup_strv_free_ char **properties = NULL;
        char **p;
        const char *subsys, *str;
        int ifindex;

        if (!f)
                f = stdout;

        if (json_format_enabled(flags))
                return dump_event_json(event, flags, f);

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
                uid_t uid = 0;
                gid_t gid = 0;
                mode_t mode = 0;
                bool perms = event_get_node_perms(event, &uid, &gid, &mode);

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

                /* like systemd, all requested names, sorted, also the name of the interface */
                if (!strv_isempty(event->altnames)) {
                        fprintf(f, "%sAlternative interface names:%s\n", ansi_highlight(), ansi_normal());
                        STRV_FOREACH(p, strv_sort(event->altnames))
                                fprintf(f, "  %s\n", *p);
                }
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

        if (udev_device_get_current_tags_list_entry(dev)) {
                fprintf(f, "%sCurrent Tags:%s\n", ansi_highlight(), ansi_normal());
                udev_list_entry_foreach(entry, udev_device_get_current_tags_list_entry(dev))
                        fprintf(f, "  %s\n", udev_list_entry_get_name(entry));
        }

        properties = dump_properties_strv(dev);
        if (!properties)
                return log_oom();
        fprintf(f, "%sProperties:%s\n", ansi_highlight(), ansi_normal());
        STRV_FOREACH(p, properties)
                fprintf(f, "  %s\n", *p);

        if (udev_list_get_entry(&event->run_list)) {
                fprintf(f, "%sQueued commands:%s\n", ansi_highlight(), ansi_normal());
                udev_list_entry_foreach(entry, udev_list_get_entry(&event->run_list)) {
                        if (udev_list_entry_get_num(entry) < UDEV_BUILTIN_MAX)
                                fprintf(f, "  RUN{builtin} : %s\n", udev_list_entry_get_name(entry));
                        else
                                fprintf(f, "  RUN{program} : %s\n", udev_list_entry_get_name(entry));
                }
        }

        return 0;
}
