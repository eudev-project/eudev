/*
 * compose persistent device path
 *
 * Copyright (C) 2009-2011 Kay Sievers <kay@vrfy.org>
 *
 * Logic based on Hannes Reinecke's shell script.
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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <getopt.h>
#include <linux/usb/ch11.h>

/* hub protocol values of the USB specification, for older kernel headers */
#ifndef USB_HUB_PR_HS_NO_TT
#define USB_HUB_PR_HS_NO_TT     0 /* Hi-speed hub without TT */
#endif
#ifndef USB_HUB_PR_HS_SINGLE_TT
#define USB_HUB_PR_HS_SINGLE_TT 1 /* Hi-speed hub with single TT */
#endif
#ifndef USB_HUB_PR_HS_MULTI_TT
#define USB_HUB_PR_HS_MULTI_TT  2 /* Hi-speed hub with multiple TT */
#endif
#ifndef USB_HUB_PR_SS
#define USB_HUB_PR_SS           3 /* Super speed hub */
#endif

#include "udev.h"
#include "udev-util.h"
#include "def.h"
#include "path-util.h"

_printf_(2,3)
static int path_prepend(char **path, const char *fmt, ...) {
        va_list va;
        char *pre;
        int err = 0;

        va_start(va, fmt);
        err = vasprintf(&pre, fmt, va);
        va_end(va);
        if (err < 0)
                goto out;

        if (*path != NULL) {
                char *new;

                err = asprintf(&new, "%s-%s", pre, *path);
                free(pre);
                if (err < 0)
                        goto out;
                free(*path);
                *path = new;
        } else {
                *path = pre;
        }
out:
        return err;
}

/*
** The LUN is 64 bits since Linux 3.17: the 1st and 2nd level are in the lower, the 3rd and 4th level in
** the upper 32 bits. See scsilun_to_int() in drivers/scsi/scsi_common.c.
*/
static int format_lun_number(struct udev_device *dev, char **path) {
        const char *sysnum;
        uint64_t lun;
        int r;

        sysnum = udev_device_get_sysnum(dev);
        if (!sysnum)
                return -ENOENT;

        r = safe_atou64_full(sysnum, SAFE_ATO_REFUSE_PLUS_MINUS | SAFE_ATO_REFUSE_LEADING_WHITESPACE | 10, &lun);
        if (r < 0)
                return r;

        /* address method 0, peripheral device addressing with bus id of zero */
        if (lun < 256)
                return path_prepend(path, "lun-%" PRIu64, lun);
        /* all other addressing methods: the 8-byte LUN */
        return path_prepend(path, "lun-0x%04" PRIx64 "%04" PRIx64 "%04" PRIx64 "%04" PRIx64,
                            lun & 0xffff, (lun >> 16) & 0xffff, (lun >> 32) & 0xffff, lun >> 48);
}

static struct udev_device *skip_subsystem(struct udev_device *dev, const char *subsys) {
        struct udev_device *parent = dev;

        while (parent != NULL) {
                const char *subsystem;

                subsystem = udev_device_get_subsystem(parent);
                if (subsystem == NULL || !streq(subsystem, subsys))
                        break;
                dev = parent;
                parent = udev_device_get_parent(parent);
        }
        return dev;
}

static struct udev_device *handle_scsi_fibre_channel(struct udev_device *parent, char **path) {
        struct udev *udev  = udev_device_get_udev(parent);
        struct udev_device *targetdev;
        struct udev_device *fcdev = NULL;
        const char *port;
        char *lun = NULL;

        targetdev = udev_device_get_parent_with_subsystem_devtype(parent, "scsi", "scsi_target");
        if (targetdev == NULL)
                return NULL;

        fcdev = udev_device_new_from_subsystem_sysname(udev, "fc_transport", udev_device_get_sysname(targetdev));
        if (fcdev == NULL)
                return NULL;
        if (device_get_sysattr_safe_string(fcdev, "port_name", &port) < 0) {
                parent = NULL;
                goto out;
        }

        if (format_lun_number(parent, &lun) < 0) {
                parent = NULL;
                goto out;
        }
        path_prepend(path, "fc-%s-%s", port, lun);
        if (lun)
                free(lun);
out:
        udev_device_unref(fcdev);
        return parent;
}

static struct udev_device *handle_scsi_sas_wide_port(struct udev_device *parent, char **path) {
        struct udev *udev  = udev_device_get_udev(parent);
        struct udev_device *targetdev;
        struct udev_device *target_parent;
        struct udev_device *sasdev;
        const char *sas_address;
        char *lun = NULL;

        targetdev = udev_device_get_parent_with_subsystem_devtype(parent, "scsi", "scsi_target");
        if (targetdev == NULL)
                return NULL;

        target_parent = udev_device_get_parent(targetdev);
        if (target_parent == NULL)
                return NULL;

        sasdev = udev_device_new_from_subsystem_sysname(udev, "sas_device",
                                udev_device_get_sysname(target_parent));
        if (sasdev == NULL)
                return NULL;

        if (device_get_sysattr_safe_string(sasdev, "sas_address", &sas_address) < 0) {
                parent = NULL;
                goto out;
        }

        if (format_lun_number(parent, &lun) < 0) {
                parent = NULL;
                goto out;
        }
        path_prepend(path, "sas-%s-%s", sas_address, lun);
        if (lun)
                free(lun);
out:
        udev_device_unref(sasdev);
        return parent;
}

static struct udev_device *handle_scsi_sas(struct udev_device *parent, char **path)
{
        struct udev *udev  = udev_device_get_udev(parent);
        struct udev_device *targetdev;
        struct udev_device *target_parent;
        struct udev_device *port;
        struct udev_device *expander;
        struct udev_device *target_sasdev = NULL;
        struct udev_device *expander_sasdev = NULL;
        struct udev_device *port_sasdev = NULL;
        const char *sas_address = NULL;
        const char *phy_id;
        const char *phy_count;
        unsigned num_phys;
        bool wide_port;
        char *lun = NULL;

        targetdev = udev_device_get_parent_with_subsystem_devtype(parent, "scsi", "scsi_target");
        if (targetdev == NULL)
                return NULL;

        target_parent = udev_device_get_parent(targetdev);
        if (target_parent == NULL)
                return NULL;

        /* Get sas device */
        target_sasdev = udev_device_new_from_subsystem_sysname(udev,
                          "sas_device", udev_device_get_sysname(target_parent));
        if (target_sasdev == NULL)
                return NULL;

        /* The next parent is sas port */
        port = udev_device_get_parent(target_parent);
        if (port == NULL) {
                parent = NULL;
                goto out;
        }

        /* Get port device */
        port_sasdev = udev_device_new_from_subsystem_sysname(udev,
                          "sas_port", udev_device_get_sysname(port));

        phy_count = udev_device_get_sysattr_value(port_sasdev, "num_phys");
        if (phy_count == NULL) {
               parent = NULL;
               goto out;
        }

        if (udev_get_sas_legacy_path(udev))
                /* Previous eudev behaviour (sas_legacy_path=yes in udev.conf): everything but a
                 * single phy, including num_phys=0 and unparsable values, is handled as a wide port. */
                wide_port = !streq(phy_count, "1");
        else {
                if (safe_atou(phy_count, &num_phys) < 0) {
                        parent = NULL;
                        goto out;
                }

                /* Check if this is a wide port (i.e. num_phys is 2 or higher) */
                wide_port = num_phys > 1;
        }

        if (wide_port) {
                 parent = handle_scsi_sas_wide_port(parent, path);
                 goto out;
        }

        /* Get connected phy */
        if (device_get_sysattr_safe_string(target_sasdev, "phy_identifier", &phy_id) < 0) {
                parent = NULL;
                goto out;
        }

        /* The port's parent is either hba or expander */
        expander = udev_device_get_parent(port);
        if (expander == NULL) {
                parent = NULL;
                goto out;
        }

        /* Get expander device */
        expander_sasdev = udev_device_new_from_subsystem_sysname(udev,
                          "sas_device", udev_device_get_sysname(expander));
        if (expander_sasdev != NULL) {
                 /* Get expander's address */
                 if (device_get_sysattr_safe_string(expander_sasdev, "sas_address", &sas_address) < 0) {
                        parent = NULL;
                        goto out;
                 }
        }

        if (format_lun_number(parent, &lun) < 0) {
                parent = NULL;
                goto out;
        }
        if (sas_address)
                 path_prepend(path, "sas-exp%s-phy%s-%s", sas_address, phy_id, lun);
        else
                 path_prepend(path, "sas-phy%s-%s", phy_id, lun);

        if (lun)
                free(lun);
out:
        udev_device_unref(target_sasdev);
        udev_device_unref(expander_sasdev);
        udev_device_unref(port_sasdev);
        return parent;
}

static struct udev_device *handle_scsi_iscsi(struct udev_device *parent, char **path) {
        struct udev *udev  = udev_device_get_udev(parent);
        struct udev_device *transportdev;
        struct udev_device *sessiondev = NULL;
        const char *target;
        const char *sysnum;
        char *connname;
        struct udev_device *conndev = NULL;
        const char *addr;
        const char *port;
        char *lun = NULL;

        /* find iscsi session */
        transportdev = parent;
        for (;;) {
                transportdev = udev_device_get_parent(transportdev);
                if (transportdev == NULL)
                        return NULL;
                if (startswith(udev_device_get_sysname(transportdev), "session"))
                        break;
        }

        /* find iscsi session device */
        sessiondev = udev_device_new_from_subsystem_sysname(udev, "iscsi_session", udev_device_get_sysname(transportdev));
        if (sessiondev == NULL)
                return NULL;
        if (device_get_sysattr_safe_string(sessiondev, "targetname", &target) < 0) {
                parent = NULL;
                goto out;
        }

        sysnum = udev_device_get_sysnum(transportdev);
        if (!sysnum) {
                parent = NULL;
                goto out;
        }
        if (asprintf(&connname, "connection%s:0", sysnum) < 0) {
                parent = NULL;
                goto out;
        }
        conndev = udev_device_new_from_subsystem_sysname(udev, "iscsi_connection", connname);
        free(connname);
        if (conndev == NULL) {
                parent = NULL;
                goto out;
        }
        if (device_get_sysattr_safe_string(conndev, "persistent_address", &addr) < 0 ||
            device_get_sysattr_safe_string(conndev, "persistent_port", &port) < 0) {
                parent = NULL;
                goto out;
        }

        if (format_lun_number(parent, &lun) < 0) {
                parent = NULL;
                goto out;
        }
        path_prepend(path, "ip-%s:%s-iscsi-%s-%s", addr, port, target, lun);
        if (lun)
                free(lun);
out:
        udev_device_unref(sessiondev);
        udev_device_unref(conndev);
        return parent;
}

/* eudev: whether the SCSI host of an ATA port has only one target, i.e. the port has only one device: libata
 * adds a SCSI target for each device it finds on the port, below the host of the port. */
static bool scsi_host_has_one_target(struct udev_device *hostdev) {
        _cleanup_closedir_ DIR *dir = NULL;
        struct dirent *de;
        unsigned n = 0;

        dir = opendir(udev_device_get_syspath(hostdev));
        if (!dir)
                return false;

        while ((de = readdir(dir)))
                if (startswith(de->d_name, "target") && IN_SET(de->d_type, DT_DIR, DT_UNKNOWN))
                        n++;

        return n == 1;
}

static struct udev_device *handle_scsi_ata(struct udev_device *parent, char **path, char **compat_path) {
        struct udev *udev  = udev_device_get_udev(parent);
        struct udev_device *targetdev;
        struct udev_device *target_parent;
        struct udev_device *atadev;
        const char *port_no, *name;
        unsigned host, bus, target, lun;

        assert(parent);
        assert(path);

        name = udev_device_get_sysname(parent);
        if (!name)
                return NULL;
        if (sscanf(name, "%u:%u:%u:%u", &host, &bus, &target, &lun) != 4)
                return NULL;

        targetdev = udev_device_get_parent_with_subsystem_devtype(parent, "scsi", "scsi_host");
        if (!targetdev)
                return NULL;

        target_parent = udev_device_get_parent(targetdev);
        if (!target_parent)
                return NULL;

        atadev = udev_device_new_from_subsystem_sysname(udev, "ata_port", udev_device_get_sysname(target_parent));
        if (!atadev)
                return NULL;

        if (device_get_sysattr_safe_string(atadev, "port_no", &port_no) < 0) {
               parent = NULL;
               goto out;
        }

        if (bus != 0)
                /* Devices behind port multiplier have a bus != 0 */
                path_prepend(path, "ata-%s.%u.0", port_no, bus);
        else
                /* Master/slave are distinguished by target id */
                path_prepend(path, "ata-%s.%u", port_no, target);

        /* old compatible persistent link for ATA devices
         *
         * eudev: the name has neither the bus nor the target, so it is the same for all the devices of the port,
         * e.g. a PATA master and slave, or the disks behind a port multiplier. To keep the link unique, only the
         * device that owns the name alone gets it: the one on bus 0 with target 0 (a single SATA disk, a PATA
         * master, the disk on port 0 of a port multiplier), or the only device of the port (a lone PATA slave
         * or a lone disk behind a port multiplier). systemd gives it to all of them. */
        if (compat_path && ((bus == 0 && target == 0) || scsi_host_has_one_target(targetdev)))
                path_prepend(compat_path, "ata-%s", port_no);
out:
        udev_device_unref(atadev);
        return parent;
}

/* eudev: the device on bus 0 with target 0 owns the old ATA link of its port, see handle_scsi_ata(). When it
 * appears after another device of the port took the link as the only device of the port (a lone PATA slave,
 * or a lone disk behind a port multiplier), that device and its partitions keep the link until their next
 * event, and both claim it. Trigger a "change" uevent for them, after which path_id finds two devices on the
 * port and they drop the link: for every block device below the SCSI host of the port, outside of the
 * target of this device, that has ID_PATH_ATA_COMPAT, or whose event is not finished yet, as it may still
 * get it. The block devices are sorted by their path, so a disk comes before its partitions, whose events
 * then wait for the one of the disk, from which they take ID_PATH_ATA_COMPAT. */
static void trigger_other_ata_compat_owners(struct udev_device *dev, enum udev_event_mode mode) {
        _cleanup_free_ char *lesc1 = NULL;
        _cleanup_udev_enumerate_unref_ struct udev_enumerate *e = NULL;
        _cleanup_strv_free_ char **args = NULL;
        struct udev_device *scsidev, *targetdev, *hostdev;
        struct udev_list_entry *item;
        unsigned host, bus, target, lun;
        int r;

        if (streq_ptr(udev_device_get_action(dev), "remove"))
                return;

        scsidev = udev_device_get_parent_with_subsystem_devtype(dev, "scsi", "scsi_device");
        if (!scsidev)
                return;
        if (sscanf(udev_device_get_sysname(scsidev), "%u:%u:%u:%u", &host, &bus, &target, &lun) != 4 ||
            bus != 0 || target != 0)
                return;

        targetdev = udev_device_get_parent_with_subsystem_devtype(scsidev, "scsi", "scsi_target");
        hostdev = udev_device_get_parent_with_subsystem_devtype(scsidev, "scsi", "scsi_host");
        if (!targetdev || !hostdev)
                return;

        e = udev_enumerate_new(udev_device_get_udev(dev));
        if (!e) {
                log_oom_debug();
                return;
        }
        r = udev_enumerate_add_match_subsystem(e, "block");
        if (r >= 0)
                r = udev_enumerate_add_match_parent(e, hostdev);
        if (r >= 0)
                r = udev_enumerate_scan_devices(e);
        if (r < 0) {
                log_device_debug_errno(dev, r, "Failed to enumerate the block devices of the ATA port, ignoring: %m");
                return;
        }

        udev_list_entry_foreach(item, udev_enumerate_get_list_entry(e)) {
                _cleanup_udev_device_unref_ struct udev_device *d = NULL;
                const char *syspath = udev_list_entry_get_name(item);

                if (path_startswith(syspath, udev_device_get_syspath(targetdev)))
                        continue;

                d = udev_device_new_from_syspath(udev_device_get_udev(dev), syspath);
                if (!d)
                        continue;

                if (udev_device_get_is_initialized(d) > 0 &&
                    !udev_device_get_property_value(d, "ID_PROCESSING") &&
                    !udev_device_get_property_value(d, "ID_PATH_ATA_COMPAT"))
                        continue;

                if (mode != EVENT_UDEV_WORKER) {
                        log_device_debug(dev, "Running in test mode, skipping 'change' uevent for %s, which may have the old ATA link of the port.",
                                         utf8_escape_for_log(udev_device_get_sysname(d), &lesc1));
                        continue;
                }

                /* with the caller arguments, like the uevents udevd triggers, here with the PID of the worker */
                if (!args) {
                        r = device_build_default_trigger_args(/* with_timestamp= */ false, &args);
                        if (r < 0) {
                                log_device_debug_errno(dev, r, "Failed to build the arguments of the 'change' uevents, ignoring: %m");
                                return;
                        }
                }

                log_device_debug(dev, "Triggering 'change' uevent for %s, which may have the old ATA link of the port.",
                                 utf8_escape_for_log(udev_device_get_sysname(d), &lesc1));
                r = device_trigger_with_timestamp(d, "change", args, /* ret_uuid= */ NULL);
                if (r < 0)
                        log_device_debug_errno(dev, r, "Failed to trigger 'change' uevent for %s, ignoring: %m",
                                               utf8_escape_for_log(udev_device_get_sysname(d), &lesc1));
        }
}

/* eudev: the other way round, when a device of an ATA port goes away, e.g. the device on bus 0 with target 0,
 * the owner of the old ATA link of the port, or one of two devices behind a port multiplier, a lone device left
 * on the port gets the link only at its next event, see handle_scsi_ata(). The rules run path_id for the
 * "remove" event of the SCSI target of every device; trigger a "change" uevent for the block devices below the
 * remaining target, if exactly one remains on the port, unless they finished their event with
 * ID_PATH_ATA_COMPAT already, e.g. the owner on bus 0 with target 0. Their events then find one target on the
 * port and give them the link. The SCSI target is used rather than the block device, because the kernel
 * removes the target after it is done with the device (e.g. after the cache of the disk is flushed), so that
 * the target is gone from sysfs when its event runs, while it may still be there during the "remove" event of
 * the disk. The targets are counted like scsi_host_has_one_target() does, without the removed one, in case its
 * directory is still there (or in test mode). */
static void trigger_lone_ata_compat_device(struct udev_device *dev, enum udev_event_mode mode) {
        _cleanup_free_ char *lesc1 = NULL;
        _cleanup_udev_enumerate_unref_ struct udev_enumerate *e = NULL;
        _cleanup_udev_device_unref_ struct udev_device *atadev = NULL, *targetdev = NULL;
        _cleanup_closedir_ DIR *dir = NULL;
        _cleanup_free_ char *target = NULL;
        _cleanup_strv_free_ char **args = NULL;
        struct udev *udev = udev_device_get_udev(dev);
        struct udev_device *hostdev, *portdev;
        struct udev_list_entry *item;
        const char *rest;
        unsigned host, bus, id;
        struct dirent *de;
        int r;

        if (sscanf(udev_device_get_sysname(dev), "target%u:%u:%u", &host, &bus, &id) != 3)
                return;

        /* the target is gone from sysfs, so this is the nearest scsi_host above its path, which must be the
         * parent directory of the target, on an ATA port */
        hostdev = udev_device_get_parent_with_subsystem_devtype(dev, "scsi", "scsi_host");
        if (!hostdev)
                return;
        rest = path_startswith(udev_device_get_syspath(dev), udev_device_get_syspath(hostdev));
        if (!streq_ptr(rest, udev_device_get_sysname(dev)))
                return;
        portdev = udev_device_get_parent(hostdev);
        if (!portdev)
                return;
        atadev = udev_device_new_from_subsystem_sysname(udev, "ata_port", udev_device_get_sysname(portdev));
        if (!atadev)
                return;

        dir = opendir(udev_device_get_syspath(hostdev));
        if (!dir)
                return;
        while ((de = readdir(dir))) {
                if (!startswith(de->d_name, "target") || !IN_SET(de->d_type, DT_DIR, DT_UNKNOWN) ||
                    streq(de->d_name, udev_device_get_sysname(dev)))
                        continue;
                if (target)
                        return; /* more than one target remains, none of them gets the link */
                target = strjoin(udev_device_get_syspath(hostdev), "/", de->d_name, NULL);
                if (!target) {
                        log_oom_debug();
                        return;
                }
        }
        if (!target)
                return;

        targetdev = udev_device_new_from_syspath(udev, target);
        if (!targetdev)
                return;

        e = udev_enumerate_new(udev);
        if (!e) {
                log_oom_debug();
                return;
        }
        r = udev_enumerate_add_match_subsystem(e, "block");
        if (r >= 0)
                r = udev_enumerate_add_match_parent(e, targetdev);
        if (r >= 0)
                r = udev_enumerate_scan_devices(e);
        if (r < 0) {
                log_device_debug_errno(dev, r, "Failed to enumerate the block devices of the ATA port, ignoring: %m");
                return;
        }

        udev_list_entry_foreach(item, udev_enumerate_get_list_entry(e)) {
                _cleanup_udev_device_unref_ struct udev_device *d = NULL;

                d = udev_device_new_from_syspath(udev, udev_list_entry_get_name(item));
                if (!d)
                        continue;

                if (udev_device_get_is_initialized(d) > 0 &&
                    !udev_device_get_property_value(d, "ID_PROCESSING") &&
                    udev_device_get_property_value(d, "ID_PATH_ATA_COMPAT"))
                        continue;

                if (mode != EVENT_UDEV_WORKER) {
                        log_device_debug(dev, "Running in test mode, skipping 'change' uevent for %s, which may get the old ATA link of the port.",
                                         utf8_escape_for_log(udev_device_get_sysname(d), &lesc1));
                        continue;
                }

                /* with the caller arguments, like the uevents udevd triggers, here with the PID of the worker */
                if (!args) {
                        r = device_build_default_trigger_args(/* with_timestamp= */ false, &args);
                        if (r < 0) {
                                log_device_debug_errno(dev, r, "Failed to build the arguments of the 'change' uevents, ignoring: %m");
                                return;
                        }
                }

                log_device_debug(dev, "Triggering 'change' uevent for %s, which may get the old ATA link of the port.",
                                 utf8_escape_for_log(udev_device_get_sysname(d), &lesc1));
                r = device_trigger_with_timestamp(d, "change", args, /* ret_uuid= */ NULL);
                if (r < 0)
                        log_device_debug_errno(dev, r, "Failed to trigger 'change' uevent for %s, ignoring: %m",
                                               utf8_escape_for_log(udev_device_get_sysname(d), &lesc1));
        }
}

static struct udev_device *handle_scsi_default(struct udev_device *parent, char **path) {
        struct udev_device *hostdev;
        int host, bus, target, lun;
        const char *name;
        char *base;
        char *pos;
        DIR *dir;
        struct dirent *dent;
        int basenum;

        hostdev = udev_device_get_parent_with_subsystem_devtype(parent, "scsi", "scsi_host");
        if (hostdev == NULL)
                return NULL;

        name = udev_device_get_sysname(parent);
        if (sscanf(name, "%d:%d:%d:%d", &host, &bus, &target, &lun) != 4)
                return NULL;

        /*
         * Rebase host offset to get the local relative number
         *
         * Note: This is by definition racy, unreliable and too simple.
         * Please do not copy this model anywhere. It's just a left-over
         * from the time we had no idea how things should look like in
         * the end.
         *
         * Making assumptions about a global in-kernel counter and use
         * that to calculate a local offset is a very broken concept. It
         * can only work as long as things are in strict order.
         *
         * The kernel needs to export the instance/port number of a
         * controller directly, without the need for rebase magic like
         * this. Manual driver unbind/bind, parallel hotplug/unplug will
         * get into the way of this "I hope it works" logic.
         */
        basenum = -1;
        base = strdup(udev_device_get_syspath(hostdev));
        if (base == NULL)
                return NULL;
        pos = strrchr(base, '/');
        if (pos == NULL) {
                parent = NULL;
                goto out;
        }
        pos[0] = '\0';
        dir = opendir(base);
        if (dir == NULL) {
                parent = NULL;
                goto out;
        }
        for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
                unsigned i;

                if (dent->d_name[0] == '.')
                        continue;
                if (dent->d_type != DT_DIR && dent->d_type != DT_LNK)
                        continue;
                if (!startswith(dent->d_name, "host"))
                        continue;
                if (safe_atou_full(&dent->d_name[4], 10, &i) < 0)
                        continue;
                /*
                 * find the smallest number; the host really needs to export its
                 * own instance number per parent device; relying on the global host
                 * enumeration and plainly rebasing the numbers sounds unreliable
                 */
                if (basenum == -1 || (int) i < basenum)
                        basenum = i;
        }
        closedir(dir);
        if (basenum == -1) {
                parent = NULL;
                goto out;
        }
        host -= basenum;

        path_prepend(path, "scsi-%i:%i:%i:%i", host, bus, target, lun);
out:
        free(base);
        return hostdev;
}

static struct udev_device *handle_scsi_hyperv(struct udev_device *parent, char **path, size_t guid_str_len) {
        struct udev_device *hostdev;
        struct udev_device *vmbusdev;
        const char *guid_str;
        char *lun = NULL;
        char guid[39];
        size_t i, k;

        assert(parent);
        assert(path);
        assert(guid_str_len < sizeof(guid));

        hostdev = udev_device_get_parent_with_subsystem_devtype(parent, "scsi", "scsi_host");
        if (!hostdev)
                return NULL;

        vmbusdev = udev_device_get_parent(hostdev);
        if (!vmbusdev)
                return NULL;

        if (device_get_sysattr_safe_string(vmbusdev, "device_id", &guid_str) < 0)
                return NULL;

        if (strlen(guid_str) < guid_str_len || guid_str[0] != '{' || guid_str[guid_str_len-1] != '}')
                return NULL;

        for (i = 1, k = 0; i < guid_str_len-1; i++) {
                if (guid_str[i] == '-')
                        continue;
                guid[k++] = guid_str[i];
        }
        guid[k] = '\0';

        if (format_lun_number(parent, &lun) < 0)
                return NULL;
        path_prepend(path, "vmbus-%s-%s", guid, lun);
        free(lun);
        return parent;
}

static struct udev_device *handle_scsi(struct udev_device *parent, char **path, char **compat_path, bool *supported_parent) {
        const char *devtype;
        const char *name;
        const char *id;

        devtype = udev_device_get_devtype(parent);
        if (devtype == NULL || !streq(devtype, "scsi_device"))
                return parent;

        /* firewire */
        if (device_get_sysattr_safe_string(parent, "ieee1394_id", &id) >= 0) {
                parent = skip_subsystem(parent, "scsi");
                path_prepend(path, "ieee1394-0x%s", id);
                *supported_parent = true;
                goto out;
        }

        /* scsi sysfs does not have a "subsystem" for the transport */
        name = udev_device_get_syspath(parent);

        if (strstr(name, "/rport-") != NULL) {
                parent = handle_scsi_fibre_channel(parent, path);
                *supported_parent = true;
                goto out;
        }

        if (strstr(name, "/end_device-") != NULL) {
                parent = handle_scsi_sas(parent, path);
                *supported_parent = true;
                goto out;
        }

        if (strstr(name, "/session") != NULL) {
                parent = handle_scsi_iscsi(parent, path);
                *supported_parent = true;
                goto out;
        }

        if (strstr(name, "/ata") != NULL) {
                parent = handle_scsi_ata(parent, path, compat_path);
                goto out;
        }

        if (strstr(name, "/vmbus_") != NULL) {
                parent = handle_scsi_hyperv(parent, path, 37);
                goto out;
        } else if (strstr(name, "/VMBUS") != NULL) {
                parent = handle_scsi_hyperv(parent, path, 38);
                goto out;
        }

        parent = handle_scsi_default(parent, path);
out:
        return parent;
}

static struct udev_device *handle_cciss(struct udev_device *parent, char **path) {
        const char *str;
        unsigned int controller, disk;

        str = udev_device_get_sysname(parent);
        if (sscanf(str, "c%ud%u%*s", &controller, &disk) != 2)
                return NULL;

        path_prepend(path, "cciss-disk%u", disk);
        parent = skip_subsystem(parent, "cciss");
        return parent;
}

static void handle_scsi_tape(struct udev_device *dev, char **path) {
        const char *name;

        /* must be the last device in the syspath */
        if (*path != NULL)
                return;

        name = udev_device_get_sysname(dev);
        if (startswith(name, "nst") && strchr("lma", name[3]) != NULL)
                path_prepend(path, "nst%c", name[3]);
        else if (startswith(name, "st") && strchr("lma", name[2]) != NULL)
                path_prepend(path, "st%c", name[2]);
}

static int get_usb_revision(struct udev_device *dev) {
        unsigned long protocol;
        const char *s;
        char *end;

        assert(dev);

        /* Returns usb revision 1, 2, or 3. */

        s = udev_device_get_sysattr_value(dev, "bDeviceProtocol");
        if (!s)
                return -ENOENT;

        errno = 0;
        protocol = strtoul(s, &end, 16);
        if (errno != 0 || end == s || *end != '\0' || protocol > UINT8_MAX)
                return -EINVAL;

        switch (protocol) {
        case USB_HUB_PR_HS_NO_TT: /* Full speed hub (USB1) or Hi-speed hub without TT (USB2) */

                /* See speed_show() in drivers/usb/core/sysfs.c of the kernel. */
                s = udev_device_get_sysattr_value(dev, "speed");
                if (!s)
                        return -ENOENT;

                if (streq(s, "480"))
                        return 2;

                return 1;

        case USB_HUB_PR_HS_SINGLE_TT: /* Hi-speed hub with single TT */
        case USB_HUB_PR_HS_MULTI_TT: /* Hi-speed hub with multiple TT */
                return 2;

        case USB_HUB_PR_SS: /* Super speed hub */
                return 3;

        default:
                return -EPROTONOSUPPORT;
        }
}

static struct udev_device *handle_usb(struct udev_device *parent, char **path) {
        const char *devtype;
        const char *str;
        const char *port;
        int r;

        devtype = udev_device_get_devtype(parent);
        if (devtype == NULL)
                return parent;
        if (!streq(devtype, "usb_interface") && !streq(devtype, "usb_device"))
                return parent;

        str = udev_device_get_sysname(parent);
        port = strchr(str, '-');
        if (port == NULL)
                return parent;
        port++;

        parent = skip_subsystem(parent, "usb");

        /* USB host number may change across reboots (and probably even without reboot). The part after USB
         * host number is determined by device topology and so does not change. Hence, drop the host number
         * and always use '0' instead.
         *
         * xHCI host controllers may register two (or more?) USB root hubs for USB 2.0 and USB 3.0, and the
         * sysname, whose host number replaced with 0, of a device under the hubs may conflict with others.
         * To avoid the conflict, let's include the USB revision of the root hub to the PATH_ID.
         * See issue https://github.com/systemd/systemd/issues/19406 for more details. */
        r = get_usb_revision(parent);
        if (r < 0) {
                log_device_debug_errno(parent, r, "Failed to get the USB revision number, ignoring: %m");
                path_prepend(path, "usb-0:%s", port);
        } else {
                assert(r > 0);
                path_prepend(path, "usbv%i-0:%s", r, port);
        }

        return parent;
}

static struct udev_device *handle_bcma(struct udev_device *parent, char **path) {
        const char *sysname;
        unsigned int core;

        sysname = udev_device_get_sysname(parent);
        if (sscanf(sysname, "bcma%*u:%u", &core) != 1)
                return NULL;

        path_prepend(path, "bcma-%u", core);
        return parent;
}

/* Handle devices of AP bus in System z platform. */
static struct udev_device *handle_ap(struct udev_device *parent, char **path) {
        const char *type, *func;

        assert(parent);
        assert(path);

        if (device_get_sysattr_safe_string(parent, "type", &type) >= 0 &&
            device_get_sysattr_safe_string(parent, "ap_functions", &func) >= 0) {
                path_prepend(path, "ap-%s-%s", type, func);
                goto out;
        }
        path_prepend(path, "ap-%s", udev_device_get_sysname(parent));
out:
        parent = skip_subsystem(parent, "ap");
        return parent;
}

static int find_real_nvme_parent(struct udev_device *dev, struct udev_device **ret) {
        _cleanup_udev_device_unref_ struct udev_device *nvme = NULL;
        const char *sysname, *end, *devpath;

        /* If the device belongs to "nvme-subsystem" (not to be confused with "nvme"), which happens when
         * NVMe multipathing is enabled in the kernel (/sys/module/nvme_core/parameters/multipath is Y),
         * then the syspath is something like the following:
         *   /sys/devices/virtual/nvme-subsystem/nvme-subsys0/nvme0n1
         * Hence, we need to find the 'real parent' in "nvme" subsystem, e.g,
         *   /sys/devices/pci0000:00/0000:00:1c.4/0000:3c:00.0/nvme/nvme0 */

        assert(dev);
        assert(ret);

        sysname = udev_device_get_sysname(dev);
        if (!sysname)
                return -ENODEV;

        /* The sysname format of nvme block device is nvme%d[c%d]n%d[p%d], e.g. nvme0n1p2 or nvme0c1n2.
         * (Note, nvme device with 'c' can be ignored, as they are hidden. )
         * The sysname format of nvme subsystem device is nvme%d.
         * See nvme_alloc_ns() and nvme_init_ctrl() in drivers/nvme/host/core.c for more details. */
        end = startswith(sysname, "nvme");
        if (!end)
                return -ENXIO;

        end += strspn(end, DIGITS);
        sysname = strndupa(sysname, end - sysname);

        nvme = udev_device_new_from_subsystem_sysname(udev_device_get_udev(dev), "nvme", sysname);
        if (!nvme)
                return -ENODEV;

        devpath = udev_device_get_devpath(nvme);
        if (!devpath)
                return -ENODEV;

        /* If the 'real parent' is (still) virtual, e.g. for nvmf disks, refuse to set ID_PATH. */
        if (startswith(devpath, "/devices/virtual/"))
                return -ENXIO;

        *ret = nvme;
        nvme = NULL;
        return 0;
}

static int handle_pnp(struct udev_device *parent, char **path) {
        _cleanup_udev_device_unref_ struct udev_device *firmware_node = NULL;
        _cleanup_free_ char *firmware_node_path = NULL;
        const char *syspath, *sysname;

        assert(parent);
        assert(path);

        syspath = udev_device_get_syspath(parent);
        if (!syspath)
                return -ENODEV;

        firmware_node_path = realpath(strjoina(syspath, "/firmware_node"), NULL);
        if (!firmware_node_path)
                return -errno;

        firmware_node = udev_device_new_from_syspath(udev_device_get_udev(parent), firmware_node_path);
        if (!firmware_node)
                return -ENODEV;

        if (!streq_ptr(udev_device_get_subsystem(firmware_node), "acpi"))
                return -ENODEV;

        sysname = udev_device_get_sysname(firmware_node);
        if (!sysname)
                return -ENODEV;

        path_prepend(path, "acpi-%s", sysname);

        return 0;
}

static void add_id_with_usb_revision(struct udev_device *dev, enum udev_event_mode mode, char *path) {
        char *p;

        assert(dev);
        assert(path);

        /* When the path contains the USB revision, let's adds ID_PATH_WITH_USB_REVISION property and
         * drop the version specifier for later use. */

        p = strstr(path, "-usbv");
        if (!p)
                return;
        p += strlen("-usbv");
        if (p[0] < '0' || p[0] > '9')
                return;
        if (p[1] != '-')
                return;

        udev_builtin_add_property(dev, mode, "ID_PATH_WITH_USB_REVISION", path);

        /* Drop the USB revision specifier for backward compatibility. */
        memmove(p - 1, p + 1, strlen(p + 1) + 1);
}

static int builtin_path_id(struct udev_device *dev, int argc __attribute__((unused)), char *argv[] __attribute__((unused)), enum udev_event_mode mode) {
        _cleanup_udev_device_unref_ struct udev_device *dev_other_branch = NULL;
        struct udev_device *parent;
        char *path = NULL;
        _cleanup_free_ char *compat_path = NULL;
        bool supported_transport = false;
        bool supported_parent = false;

        /* eudev: the rules run path_id for the "remove" event of a SCSI target only to pass the old ATA link
         * of its port on, see trigger_lone_ata_compat_device(); the target is gone, there is no path to add */
        if (streq_ptr(udev_device_get_action(dev), "remove") &&
            streq_ptr(udev_device_get_subsystem(dev), "scsi") &&
            streq_ptr(udev_device_get_devtype(dev), "scsi_target")) {
                trigger_lone_ata_compat_device(dev, mode);
                return EXIT_SUCCESS;
        }

        /* walk up the chain of devices and compose path */
        parent = dev;
        while (parent != NULL) {
                const char *subsys;

                subsys = udev_device_get_subsystem(parent);
                if (subsys == NULL) {
                        ;
                } else if (streq(subsys, "scsi_tape")) {
                        handle_scsi_tape(parent, &path);
                } else if (streq(subsys, "scsi")) {
                        parent = handle_scsi(parent, &path, &compat_path, &supported_parent);
                        supported_transport = true;
                } else if (streq(subsys, "cciss")) {
                        parent = handle_cciss(parent, &path);
                        supported_transport = true;
                } else if (streq(subsys, "usb")) {
                        parent = handle_usb(parent, &path);
                        supported_transport = true;
                } else if (streq(subsys, "bcma")) {
                        parent = handle_bcma(parent, &path);
                        supported_transport = true;
                } else if (streq(subsys, "serio")) {
                        const char *sysnum;

                        sysnum = udev_device_get_sysnum(parent);
                        if (sysnum) {
                                path_prepend(&path, "serio-%s", sysnum);
                                parent = skip_subsystem(parent, "serio");
                        }
                } else if (streq(subsys, "auxiliary")) {
                        const char *sfnum;
                        unsigned n;

                        /* sfnum is the user-defined sub-function number (devlink port add ...
                         * sfnum N). Prepend it so an SF leaf device gets an ID_PATH distinct
                         * from its parent PF/VF; aux devices without 'sfnum' emit no token to
                         * preserve pre-patch ID_PATH values. */
                        sfnum = udev_device_get_sysattr_value(parent, "sfnum");
                        if (sfnum && safe_atou(sfnum, &n) >= 0) {
                                path_prepend(&path, "sf-%u", n);
                                if (compat_path)
                                        path_prepend(&compat_path, "sf-%u", n);
                        }
                } else if (streq(subsys, "pci")) {
                        path_prepend(&path, "pci-%s", udev_device_get_sysname(parent));
                        if (compat_path)
                                path_prepend(&compat_path, "pci-%s", udev_device_get_sysname(parent));
                        parent = skip_subsystem(parent, "pci");
                        supported_parent = true;
                } else if (streq(subsys, "platform")) {
                        path_prepend(&path, "platform-%s", udev_device_get_sysname(parent));
                        if (compat_path)
                                path_prepend(&compat_path, "platform-%s", udev_device_get_sysname(parent));
                        parent = skip_subsystem(parent, "platform");
                        supported_transport = true;
                        supported_parent = true;
                } else if (streq(subsys, "amba")) {
                        path_prepend(&path, "amba-%s", udev_device_get_sysname(parent));
                        if (compat_path)
                                path_prepend(&compat_path, "amba-%s", udev_device_get_sysname(parent));
                        parent = skip_subsystem(parent, "amba");
                        supported_transport = true;
                        supported_parent = true;
                } else if (streq(subsys, "acpi")) {
                        path_prepend(&path, "acpi-%s", udev_device_get_sysname(parent));
                        if (compat_path)
                                path_prepend(&compat_path, "acpi-%s", udev_device_get_sysname(parent));
                        parent = skip_subsystem(parent, "acpi");
                        supported_parent = true;
                } else if (streq(subsys, "pnp")) {
                        if (handle_pnp(parent, &path) >= 0)
                                supported_parent = true;
                        parent = skip_subsystem(parent, "pnp");
                } else if (streq(subsys, "xen")) {
                        path_prepend(&path, "xen-%s", udev_device_get_sysname(parent));
                        if (compat_path)
                                path_prepend(&compat_path, "xen-%s", udev_device_get_sysname(parent));
                        parent = skip_subsystem(parent, "xen");
                        supported_parent = true;
                } else if (streq(subsys, "virtio")) {
                        parent = skip_subsystem(parent, "virtio");
                        supported_transport = true;
                } else if (streq(subsys, "scm")) {
                        path_prepend(&path, "scm-%s", udev_device_get_sysname(parent));
                        if (compat_path)
                                path_prepend(&compat_path, "scm-%s", udev_device_get_sysname(parent));
                        parent = skip_subsystem(parent, "scm");
                        supported_transport = true;
                        supported_parent = true;
                } else if (streq(subsys, "ccw")) {
                        path_prepend(&path, "ccw-%s", udev_device_get_sysname(parent));
                        if (compat_path)
                                path_prepend(&compat_path, "ccw-%s", udev_device_get_sysname(parent));
                        parent = skip_subsystem(parent, "ccw");
                        supported_transport = true;
                        supported_parent = true;
                } else if (streq(subsys, "ccwgroup")) {
                        path_prepend(&path, "ccwgroup-%s", udev_device_get_sysname(parent));
                        if (compat_path)
                                path_prepend(&compat_path, "ccwgroup-%s", udev_device_get_sysname(parent));
                        parent = skip_subsystem(parent, "ccwgroup");
                        supported_transport = true;
                        supported_parent = true;
                } else if (streq(subsys, "ap")) {
                        parent = handle_ap(parent, &path);
                        supported_transport = true;
                        supported_parent = true;
                } else if (streq(subsys, "iucv")) {
                        path_prepend(&path, "iucv-%s", udev_device_get_sysname(parent));
                        if (compat_path)
                                path_prepend(&compat_path, "iucv-%s", udev_device_get_sysname(parent));
                        parent = skip_subsystem(parent, "iucv");
                        supported_transport = true;
                        supported_parent = true;
                } else if (streq(subsys, "nvme") || streq(subsys, "nvme-subsystem")) {
                        const char *nsid;

                        if (device_get_sysattr_safe_string(dev, "nsid", &nsid) >= 0) {
                                path_prepend(&path, "nvme-%s", nsid);
                                if (compat_path)
                                        path_prepend(&compat_path, "nvme-%s", nsid);

                                if (streq(subsys, "nvme-subsystem")) {
                                        int r;

                                        r = find_real_nvme_parent(dev, &dev_other_branch);
                                        if (r < 0) {
                                                free(path);
                                                return r;
                                        }

                                        parent = dev_other_branch;
                                }

                                parent = skip_subsystem(parent, "nvme");
                                supported_parent = true;
                                supported_transport = true;
                        }
                } else if (streq(subsys, "spi")) {
                        const char *sysnum;

                        sysnum = udev_device_get_sysnum(parent);
                        if (sysnum) {
                                path_prepend(&path, "cs-%s", sysnum);
                                parent = skip_subsystem(parent, "spi");
                        }
                }

                parent = udev_device_get_parent(parent);
        }

        /*
         * Do not return devices with an unknown parent device type. They
         * might produce conflicting IDs if the parent does not provide a
         * unique and predictable name.
         */
        if (!supported_parent) {
                free(path);
                path = NULL;
        }

        /*
         * Do not return block devices without a well-known transport. Some
         * devices do not expose their buses and do not provide a unique
         * and predictable name that way.
         */
        if (streq_ptr(udev_device_get_subsystem(dev), "block") && !supported_transport) {
                free(path);
                path = NULL;
        }

        if (path != NULL) {
                char tag[UTIL_NAME_SIZE];
                size_t i;
                const char *p;

                add_id_with_usb_revision(dev, mode, path);

                /* compose valid udev tag name */
                for (p = path, i = 0; *p && i < sizeof(tag) - 1; p++) {
                        if ((*p >= '0' && *p <= '9') ||
                            (*p >= 'A' && *p <= 'Z') ||
                            (*p >= 'a' && *p <= 'z') ||
                            *p == '-') {
                                tag[i++] = *p;
                                continue;
                        }

                        /* skip all leading '_' */
                        if (i == 0)
                                continue;

                        /* avoid second '_' */
                        if (tag[i-1] == '_')
                                continue;

                        tag[i++] = '_';
                }
                /* strip trailing '_' */
                while (i > 0 && tag[i-1] == '_')
                        i--;
                tag[i] = '\0';

                udev_builtin_add_property(dev, mode, "ID_PATH", path);
                udev_builtin_add_property(dev, mode, "ID_PATH_TAG", tag);

                /*
                 * Compatible link generation for ATA devices
                 * we assign compat_link to the env variable
                 * ID_PATH_ATA_COMPAT
                 */
                if (compat_path) {
                        udev_builtin_add_property(dev, mode, "ID_PATH_ATA_COMPAT", compat_path);
                        trigger_other_ata_compat_owners(dev, mode);
                }

                free(path);
                return EXIT_SUCCESS;
        }

        /* Like systemd, without a path the error is ENOENT. */
        return -ENOENT;
}

const struct udev_builtin udev_builtin_path_id = {
        .name = "path_id",
        .cmd = builtin_path_id,
        .help = "Compose persistent device path",
        .run_once = true,
};
