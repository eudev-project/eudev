/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Predictable network interface device names based on:
 *  - firmware/bios-provided index numbers for on-board devices
 *  - firmware-provided pci-express hotplug slot index number
 *  - physical/geographical location of the hardware
 *  - the interface's MAC address
 *
 * https://systemd.io/PREDICTABLE_INTERFACE_NAMES
 *
 * This implements the naming schemes of systemd (net.naming_scheme=v238 and later), following
 * systemd's net_id. The names are described in udev(7); when the code here is changed,
 * man/udev.xml must be updated too.
 *
 * The "eudev" scheme is implemented separately in udev-builtin-net_id-eudev.c.
 *
 * eudev: unlike systemd, which also uses longer names as alternative interface names, only
 * names that fit into IFNAMSIZ are exported in the ID_NET_NAME_* properties, as the rules
 * assign them with NAME=.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/pci_regs.h>

#include "udev.h"
#include "def.h"
#include "netif-naming-scheme.h"
#include "path-util.h"
#include "udev-util.h"

#ifndef ALTIFNAMSIZ
#define ALTIFNAMSIZ 128
#endif

#ifndef ARPHRD_MCTP
#define ARPHRD_MCTP 290
#endif

#ifndef NET_ADDR_PERM
#define NET_ADDR_PERM 0
#endif

#ifndef HEXDIGITS
#define HEXDIGITS DIGITS "abcdefABCDEF"
#endif

#define ONBOARD_14BIT_INDEX_MAX ((1U << 14) - 1)
#define ONBOARD_16BIT_INDEX_MAX ((1U << 16) - 1)

#define log_device_debug(dev, fmt, ...) \
        log_debug("%s: " fmt, udev_device_get_sysname(dev), ##__VA_ARGS__)
#define log_device_debug_errno(dev, error, fmt, ...) \
        log_debug_errno(error, "%s: " fmt, udev_device_get_sysname(dev), ##__VA_ARGS__)

static inline const char *strempty(const char *s) {
        return s ?: "";
}

static bool device_in_subsystem(struct udev_device *dev, const char *subsystem) {
        return streq_ptr(udev_device_get_subsystem(dev), subsystem);
}

/* Like sd_device_new_child(): returns the device the path below the device points to. */
static struct udev_device *device_new_child(struct udev_device *dev, const char *suffix) {
        _cleanup_free_ char *path = NULL, *resolved = NULL;

        path = strjoin(udev_device_get_syspath(dev), "/", suffix, NULL);
        if (!path)
                return NULL;

        resolved = realpath(path, NULL);
        if (!resolved || !path_startswith(resolved, "/sys"))
                return NULL;

        return udev_device_new_from_syspath(udev_device_get_udev(dev), resolved);
}

static int get_matching_parent(
                struct udev_device *dev,
                const char * const *parent_subsystems,
                bool skip_virtio,
                struct udev_device **ret) {

        struct udev_device *parent;

        assert(dev);

        parent = udev_device_get_parent(dev);

        /* This provides the parent device, but skips intermediate virtio devices. There can only ever be one
         * virtio bus per parent device, so we can safely ignore any virtio buses. See
         * https://lore.kernel.org/virtualization/CAPXgP137A=CdmggtVPUZXbnpTbU9Tewq-sOjg9T8ohYktct1kQ@mail.gmail.com/ */
        while (skip_virtio && parent && device_in_subsystem(parent, "virtio"))
                parent = udev_device_get_parent(parent);

        if (!parent)
                return -ENOENT;

        /* check if our direct parent is in an expected subsystem. */
        for (; *parent_subsystems; parent_subsystems++)
                if (device_in_subsystem(parent, *parent_subsystems)) {
                        if (ret)
                                *ret = parent;
                        return 0;
                }

        return -ENODEV;
}

static int get_first_syspath_component(struct udev_device *dev, const char *prefix, char **ret) {
        const char *p;
        size_t n;
        char *buf;

        assert(dev);
        assert(prefix);
        assert(ret);

        p = path_startswith(udev_device_get_syspath(dev), prefix);
        if (!p)
                return -EINVAL;

        n = strcspn(p, "/");
        if (n == 0 || n > NAME_MAX)
                return -EINVAL;

        buf = strndup(p, n);
        if (!buf)
                return -ENOMEM;

        *ret = buf;
        return (int) n; /* return the length of the string */
}

static int get_virtfn_info(struct udev_device *pcidev, struct udev_device **ret_physfn_pcidev, char **ret_suffix) {
        _cleanup_udev_device_unref_ struct udev_device *physfn_pcidev = NULL;
        _cleanup_closedir_ DIR *dir = NULL;
        struct dirent *de;
        const char *syspath;

        assert(pcidev);
        assert(ret_physfn_pcidev);
        assert(ret_suffix);

        syspath = udev_device_get_syspath(pcidev);

        /* Get physical function's pci device. */
        physfn_pcidev = device_new_child(pcidev, "physfn");
        if (!physfn_pcidev)
                return -ENOENT;

        dir = opendir(udev_device_get_syspath(physfn_pcidev));
        if (!dir)
                return -errno;

        /* Find the virtual function number by finding the right virtfn link. */
        while ((de = readdir(dir))) {
                _cleanup_udev_device_unref_ struct udev_device *child = NULL;
                const char *n;

                /* Only accepts e.g. virtfn0, virtfn1, and so on. */
                n = startswith(de->d_name, "virtfn");
                if (isempty(n) || !in_charset(n, DIGITS))
                        continue;

                child = device_new_child(physfn_pcidev, de->d_name);
                if (!child)
                        continue;

                if (streq(udev_device_get_syspath(child), syspath)) {
                        char *suffix;

                        suffix = strjoin("v", n, NULL);
                        if (!suffix)
                                return -ENOMEM;

                        *ret_physfn_pcidev = TAKE_PTR(physfn_pcidev);
                        *ret_suffix = suffix;
                        return 0;
                }
        }

        return -ENOENT;
}

static int get_subfunc_info(struct udev_device *aux_dev, struct udev_device **ret_parent_pcidev, char **ret_suffix) {
        struct udev_device *parent;
        unsigned sfnum;
        char *suffix;
        int r;

        assert(aux_dev);
        assert(ret_parent_pcidev);
        assert(ret_suffix);

        /* The auxiliary device must expose an 'sfnum' attribute. This is currently used by the
         * mlx5_core driver for sub-function (SF) auxiliary devices. The sfnum is the user-defined
         * stable identifier passed to "devlink port add ... sfnum N". */
        r = device_get_sysattr_unsigned_filtered(aux_dev, "sfnum", &sfnum);
        if (r < 0)
                return r;

        /* Walk one hop up: the auxiliary device's parent must be a PCI function. It can be either
         * the PF directly, or an SR-IOV VF — mlx5 also supports SFs hosted on VFs (VF-SF), see
         * Documentation/networking/representors.rst in the kernel tree. The VF case is handled by
         * the existing virtfn logic in names_pci(), so here we just return the immediate PCI
         * parent and a single "S<sfnum>" suffix piece. */
        parent = udev_device_get_parent(aux_dev);
        if (!parent)
                return -ENOENT;

        if (!device_in_subsystem(parent, "pci"))
                return -ENODEV;

        if (asprintf(&suffix, "S%u", sfnum) < 0)
                return -ENOMEM;

        *ret_parent_pcidev = udev_device_ref(parent);
        *ret_suffix = suffix;
        return 0;
}

static int get_port_specifier(struct udev_device *dev, char **ret) {
        const char *phys_port_name;
        unsigned dev_port;
        char *buf;
        int r;

        assert(dev);
        assert(ret);

        /* First, try to use the kernel provided front panel port name for multiple port PCI device. */
        r = device_get_sysattr_safe_string_filtered(dev, "phys_port_name", &phys_port_name);
        if (r >= 0 && !isempty(phys_port_name)) {
                if (naming_scheme_has(NAMING_SR_IOV_R)) {
                        int vf_id = -1;

                        /* Check if phys_port_name indicates virtual device representor. */
                        (void) sscanf(phys_port_name, "pf%*uvf%d", &vf_id);

                        if (vf_id >= 0) {
                                /* For VF representor append 'r<VF_NUM>'. */
                                if (asprintf(&buf, "r%d", vf_id) < 0)
                                        return -ENOMEM;

                                *ret = buf;
                                return 1;
                        }
                }

                /* Otherwise, use phys_port_name as is. */
                buf = strjoin("n", phys_port_name, NULL);
                if (!buf)
                        return -ENOMEM;

                *ret = buf;
                return 1;
        }

        /* Then, try to use the kernel provided port index for the case when multiple ports on a single PCI
         * function. */
        r = device_get_sysattr_unsigned_filtered(dev, "dev_port", &dev_port);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get device port index: %m");
        if (r > 0) {
                assert(dev_port > 0);
                if (asprintf(&buf, "d%u", dev_port) < 0)
                        return -ENOMEM;

                *ret = buf;
                return 1;
        }

        *ret = NULL;
        return 0;
}

static bool is_valid_onboard_index(unsigned idx) {
        /* Some BIOSes report rubbish indexes that are excessively high (2^24-1 is an index VMware likes to
         * report for example). Let's define a cut-off where we don't consider the index reliable anymore. We
         * pick some arbitrary cut-off, which is somewhere beyond the realistic number of physical network
         * interface a system might have. Ideally the kernel would already filter this crap for us, but it
         * doesn't currently. The initial cut-off value (2^14-1) was too conservative for s390 PCI which
         * allows for index values up 2^16-1 which is now enabled with the NAMING_16BIT_INDEX naming flag. */
        return idx <= (naming_scheme_has(NAMING_16BIT_INDEX) ? ONBOARD_16BIT_INDEX_MAX : ONBOARD_14BIT_INDEX_MAX);
}

static int pci_get_onboard_index(struct udev_device *dev, unsigned *ret) {
        unsigned idx;
        int r;

        assert(dev);
        assert(ret);

        /* ACPI _DSM — device specific method for naming a PCI or PCI Express device */
        r = device_get_sysattr_unsigned_filtered(dev, "acpi_index", &idx);
        if (r < 0)
                /* SMBIOS type 41 — Onboard Devices Extended Information */
                r = device_get_sysattr_unsigned_filtered(dev, "index", &idx);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Could not obtain onboard index: %m");

        if (idx == 0 && !naming_scheme_has(NAMING_ZERO_ACPI_INDEX))
                return log_device_debug_errno(dev, EINVAL, "Naming scheme does not allow onboard index==0.");
        if (!is_valid_onboard_index(idx))
                return log_device_debug_errno(dev, EINVAL, "Not a valid onboard index: %u", idx);

        *ret = idx;
        return 0;
}

static int names_pci_onboard(struct udev_device *dev, struct udev_device *pci_dev, const char *prefix, const char *suffix, enum udev_event_mode mode) {
        _cleanup_free_ char *port = NULL;
        unsigned idx = 0;  /* avoid false maybe-uninitialized warning */
        char str[IFNAMSIZ];
        int r;

        assert(dev);
        assert(pci_dev);
        assert(prefix);

        /* retrieve on-board index number from firmware */
        r = pci_get_onboard_index(pci_dev, &idx);
        if (r < 0)
                return r;

        r = get_port_specifier(dev, &port);
        if (r < 0)
                return r;

        if (snprintf_ok(str, sizeof str, "%so%u%s%s", prefix, idx, strempty(port), strempty(suffix)))
                udev_builtin_add_property(dev, mode, "ID_NET_NAME_ONBOARD", str);
        else
                str[0] = '\0';

        log_device_debug(dev, "PCI onboard index identifier: index=%u port=%s -> %s",
                         idx, strna(port), isempty(str) ? "n/a" : str);

        return 0;
}

static int names_pci_onboard_label(struct udev_device *dev, struct udev_device *pci_dev, const char *prefix, enum udev_event_mode mode) {
        const char *label;
        char str[ALTIFNAMSIZ];
        int r;

        assert(dev);
        assert(pci_dev);
        assert(prefix);

        /* retrieve on-board label from firmware */
        r = device_get_sysattr_safe_string_filtered(pci_dev, "label", &label);
        if (r < 0)
                return log_device_debug_errno(pci_dev, r, "Failed to get PCI onboard label: %m");

        if (snprintf_ok(str, sizeof str, "%s%s",
                        naming_scheme_has(NAMING_LABEL_NOPREFIX) ? "" : prefix,
                        label))
                udev_builtin_add_property(dev, mode, "ID_NET_LABEL_ONBOARD", str);

        log_device_debug(dev, "Onboard label from PCI device: %s", label);
        return 0;
}

/* read the 256 bytes PCI configuration space to check the multi-function bit */
static int is_pci_multifunction(struct udev_device *dev) {
        _cleanup_close_ int fd = -1;
        const char *filename;
        uint8_t config[PCI_HEADER_TYPE + 1];
        ssize_t n;

        assert(dev);

        filename = strjoina(udev_device_get_syspath(dev), "/config");
        fd = open(filename, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
                return -errno;

        n = loop_read(fd, config, sizeof config, false);
        if (n < 0)
                return (int) n;
        if ((size_t) n < sizeof config)
                return -EINVAL;

#ifndef PCI_HEADER_TYPE_MULTIFUNC
#define PCI_HEADER_TYPE_MULTIFUNC 0x80
#endif

        /* bit 0-6 header type, bit 7 multi/single function device */
        return config[PCI_HEADER_TYPE] & PCI_HEADER_TYPE_MULTIFUNC;
}

static bool is_pci_ari_enabled(struct udev_device *dev) {
        assert(dev);

        return device_get_sysattr_bool_filtered(dev, "ari_enabled") > 0;
}

static bool is_pci_bridge(struct udev_device *dev) {
        const char *v, *p;
        bool b;

        assert(dev);

        if (device_get_sysattr_safe_string_filtered(dev, "modalias", &v) < 0)
                return false;

        if (!startswith(v, "pci:"))
                return false;

        p = strrchr(v, 's');
        if (!p)
                return false;
        if (p[1] != 'c')
                return false;

        /* PCI device subclass 04 corresponds to PCI bridge */
        b = strneq(p + 2, "04", 2);
        if (b)
                log_device_debug(dev, "Device is a PCI bridge.");
        return b;
}

static int parse_hotplug_slot_from_function_id(struct udev_device *dev, int slots_dirfd, uint32_t *ret) {
        uint64_t function_id;
        char filename[NAME_MAX+1];
        const char *attr;
        int r;

        /* The <sysname>/function_id attribute is unique to the s390 PCI driver. If present, we know that the
         * slot's directory name for this device is /sys/bus/pci/slots/XXXXXXXX/ where XXXXXXXX is the fixed
         * length 8 hexadecimal character string representation of function_id. Therefore we can short cut
         * here and just check for the existence of the slot directory. As this directory has to exist, we're
         * emitting a debug message for the unlikely case it's not found. Note that the domain part doesn't
         * belong to the slot name here because there's a 1-to-1 relationship between PCI function and its
         * hotplug slot. See https://docs.kernel.org/arch/s390/pci.html for more details. */

        assert(dev);
        assert(slots_dirfd >= 0);
        assert(ret);

        if (!naming_scheme_has(NAMING_SLOT_FUNCTION_ID)) {
                *ret = 0;
                return 0;
        }

        if (device_get_sysattr_safe_string_filtered(dev, "function_id", &attr) < 0) {
                *ret = 0;
                return 0;
        }

        r = safe_atou64(attr, &function_id);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to parse function_id, ignoring: '%s'", attr);

        if (function_id <= 0 || function_id > UINT32_MAX)
                return log_device_debug_errno(dev, EINVAL, "Invalid function id (0x%" PRIx64 "), ignoring.",
                                              function_id);

        if (!snprintf_ok(filename, sizeof(filename), "%08" PRIx64, function_id))
                return log_device_debug_errno(dev, ENAMETOOLONG, "PCI slot path is too long, ignoring.");

        if (faccessat(slots_dirfd, filename, F_OK, 0) < 0)
                return log_device_debug_errno(dev, errno, "Cannot access '%s' under pci slots, ignoring: %m", filename);

        *ret = (uint32_t) function_id;
        return 1; /* Found. We should ignore domain part. */
}

static int pci_get_hotplug_slot_from_address(
                struct udev_device *dev,
                struct udev_device *pci,
                DIR *dir,
                uint32_t *ret) {

        struct dirent *de;
        const char *sysname;

        assert(dev);
        assert(pci);
        assert(dir);
        assert(ret);

        sysname = udev_device_get_sysname(dev);

        rewinddir(dir);
        while ((de = readdir(dir))) {
                _cleanup_free_ char *path = NULL;
                const char *address;
                unsigned slot;
                int r;

                if (streq(de->d_name, ".") || streq(de->d_name, ".."))
                        continue;

                if (de->d_type != DT_DIR)
                        continue;

                r = safe_atou_full(de->d_name, 0, &slot);
                if (r < 0 || slot <= 0)
                        continue;

                path = strjoin("slots/", de->d_name, "/address", NULL);
                if (!path)
                        return -ENOMEM;

                if (device_get_sysattr_safe_string_filtered(pci, path, &address) < 0)
                        continue;

                /* match slot address with device by stripping the function */
                if (!startswith(sysname, address))
                        continue;

                *ret = slot;
                return 1; /* found */
        }

        *ret = 0;
        return 0; /* not found */
}

static int pci_get_hotplug_slot(struct udev_device *dev, uint32_t *ret) {
        _cleanup_udev_device_unref_ struct udev_device *pci = NULL;
        _cleanup_closedir_ DIR *dir = NULL;
        struct udev_device *slot_dev;
        const char *slots;
        int r;

        assert(dev);
        assert(ret);

        /* ACPI _SUN — slot user number */
        pci = udev_device_new_from_subsystem_sysname(udev_device_get_udev(dev), "subsystem", "pci");
        if (!pci)
                return log_debug_errno(errno > 0 ? errno : ENOENT,
                                       "Failed to create udev_device object for pci subsystem: %m");

        slots = strjoina(udev_device_get_syspath(pci), "/slots");
        dir = opendir(slots);
        if (!dir)
                return log_device_debug_errno(dev, errno, "Cannot open 'slots' subdirectory: %m");

        for (slot_dev = dev; slot_dev; ) {
                uint32_t slot = 0;  /* avoid false maybe-uninitialized warning */

                r = parse_hotplug_slot_from_function_id(slot_dev, dirfd(dir), &slot);
                if (r < 0)
                        return r;
                if (r > 0) {
                        *ret = slot;
                        return 1; /* domain should be ignored. */
                }

                r = pci_get_hotplug_slot_from_address(slot_dev, pci, dir, &slot);
                if (r < 0)
                        return r;
                if (r > 0) {
                        /* We found the match between PCI device and slot. However, we won't use the slot
                         * index if the device is a PCI bridge, because it can have other child devices that
                         * will try to claim the same index and that would create name collision. */
                        if (naming_scheme_has(NAMING_BRIDGE_NO_SLOT) && is_pci_bridge(slot_dev)) {
                                if (naming_scheme_has(NAMING_BRIDGE_MULTIFUNCTION_SLOT) && is_pci_multifunction(dev) <= 0)
                                        return log_device_debug_errno(dev, ESTALE,
                                                                      "Not using slot information because the PCI device associated with "
                                                                      "the hotplug slot is a bridge and the PCI device has a single function.");

                                if (!naming_scheme_has(NAMING_BRIDGE_MULTIFUNCTION_SLOT))
                                        return log_device_debug_errno(dev, ESTALE,
                                                                      "Not using slot information because the PCI device is a bridge.");
                        }

                        *ret = slot;
                        return 0; /* domain can be still used. */
                }

                slot_dev = udev_device_get_parent_with_subsystem_devtype(slot_dev, "pci", NULL);
        }

        return -ENOENT;
}

static int get_device_firmware_node_sun(struct udev_device *dev, uint32_t *ret) {
        const char *attr;
        unsigned sun;
        int r;

        assert(dev);
        assert(ret);

        r = device_get_sysattr_safe_string_filtered(dev, "firmware_node/sun", &attr);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to read firmware_node/sun, ignoring: %m");

        r = safe_atou_full(attr, 0, &sun);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to parse firmware_node/sun '%s', ignoring: %m", attr);
        if (sun == 0)
                return log_device_debug_errno(dev, EINVAL, "firmware_node/sun == 0, ignoring.");

        *ret = sun;
        return 0;
}

static int pci_get_slot_from_firmware_node_sun(struct udev_device *dev, uint32_t *ret) {
        struct udev_device *slot_dev;

        assert(dev);
        assert(ret);

        if (!naming_scheme_has(NAMING_FIRMWARE_NODE_SUN))
                return -EOPNOTSUPP;

        /* Try getting the ACPI _SUN for the device */
        if (get_device_firmware_node_sun(dev, ret) >= 0)
                return 0;

        slot_dev = udev_device_get_parent_with_subsystem_devtype(dev, "pci", NULL);
        if (!slot_dev)
                return log_device_debug_errno(dev, ENOENT, "Failed to find parent PCI device, ignoring.");

        if (is_pci_bridge(slot_dev) && is_pci_multifunction(dev) <= 0)
                return log_device_debug_errno(dev, ESTALE,
                                              "Not using slot information because the parent PCI slot is a bridge and the PCI device is not multifunction.");

        /* Try getting the ACPI _SUN from the parent pcieport */
        if (get_device_firmware_node_sun(slot_dev, ret) >= 0)
                return 0;

        return -ENOENT;
}

static int get_pci_slot_specifiers(
                struct udev_device *dev,
                char **ret_domain,
                char **ret_bus_and_slot,
                char **ret_func) {

        _cleanup_free_ char *domain_spec = NULL, *bus_and_slot_spec = NULL, *func_spec = NULL;
        unsigned domain, bus, slot, func;
        const char *sysname;
        int r;

        assert(dev);
        assert(ret_domain);
        assert(ret_bus_and_slot);
        assert(ret_func);

        sysname = udev_device_get_sysname(dev);

        r = sscanf(sysname, "%x:%x:%x.%u", &domain, &bus, &slot, &func);
        if (r != 4)
                return log_device_debug_errno(dev, EINVAL, "Failed to parse slot information from PCI device sysname.");

        if (naming_scheme_has(NAMING_NPAR_ARI) &&
            is_pci_ari_enabled(dev))
                /* ARI devices support up to 256 functions on a single device ("slot"), and interpret the
                 * traditional 5-bit slot and 3-bit function number as a single 8-bit function number,
                 * where the slot makes up the upper 5 bits. */
                func += slot * 8;

        /* Include the PCI domain in the name if the ID_NET_NAME_INCLUDE_DOMAIN property says so, if it is
         * set. If it is not set, include it if the domain is non-zero. */
        r = device_get_property_bool(dev, "ID_NET_NAME_INCLUDE_DOMAIN");
        if (r < 0) {
                if (r != -ENOENT)
                        log_warning_errno(r, "%s: Failed to read property \"ID_NET_NAME_INCLUDE_DOMAIN\", ignoring: %m",
                                          sysname);

                r = domain > 0;
        }
        if (r > 0 && asprintf(&domain_spec, "P%u", domain) < 0)
                return -ENOMEM;

        if (asprintf(&bus_and_slot_spec, "p%us%u", bus, slot) < 0)
                return -ENOMEM;

        if ((func > 0 || is_pci_multifunction(dev) > 0) &&
            asprintf(&func_spec, "f%u", func) < 0)
                return -ENOMEM;

        *ret_domain = TAKE_PTR(domain_spec);
        *ret_bus_and_slot = TAKE_PTR(bus_and_slot_spec);
        *ret_func = TAKE_PTR(func_spec);
        return 0;
}

static int names_pci_slot(struct udev_device *dev, struct udev_device *pci_dev, const char *prefix, const char *suffix, enum udev_event_mode mode) {
        _cleanup_free_ char *domain = NULL, *bus_and_slot = NULL, *func = NULL, *port = NULL;
        uint32_t slot = 0;  /* avoid false maybe-uninitialized warning */
        char str[IFNAMSIZ];
        int r;

        assert(dev);
        assert(pci_dev);
        assert(prefix);

        r = get_pci_slot_specifiers(pci_dev, &domain, &bus_and_slot, &func);
        if (r < 0)
                return r;

        r = get_port_specifier(dev, &port);
        if (r < 0)
                return r;

        /* compose a name based on the raw kernel's PCI bus, slot numbers */
        if (snprintf_ok(str, sizeof str, "%s%s%s%s%s%s",
                        prefix, strempty(domain), bus_and_slot, strempty(func), strempty(port), strempty(suffix)))
                udev_builtin_add_property(dev, mode, "ID_NET_NAME_PATH", str);
        else
                str[0] = '\0';

        log_device_debug(dev, "PCI path identifier: domain=%s bus_and_slot=%s func=%s port=%s -> %s",
                         strna(domain), bus_and_slot, strna(func), strna(port), isempty(str) ? "n/a" : str);

        if (pci_get_slot_from_firmware_node_sun(pci_dev, &slot) < 0) {
                /* If we don't find a slot using firmware_node/sun, fallback to hotplug_slot */
                r = pci_get_hotplug_slot(pci_dev, &slot);
                if (r < 0)
                        return r;
                if (r > 0) {
                        /* If the hotplug slot is found through the function ID, then drop the domain from the name.
                         * See comments in parse_hotplug_slot_from_function_id(). */
                        free(domain);
                        domain = NULL;
                }
        }

        if (snprintf_ok(str, sizeof str, "%s%ss%" PRIu32 "%s%s%s",
                        prefix, strempty(domain), slot, strempty(func), strempty(port), strempty(suffix)))
                udev_builtin_add_property(dev, mode, "ID_NET_NAME_SLOT", str);
        else
                str[0] = '\0';

        log_device_debug(dev, "PCI slot identifier: domain=%s slot=%" PRIu32 " func=%s port=%s -> %s",
                         strna(domain), slot, strna(func), strna(port), isempty(str) ? "n/a" : str);

        return 0;
}

static int names_vio(struct udev_device *dev, const char *prefix, enum udev_event_mode mode) {
        _cleanup_free_ char *s = NULL;
        unsigned slotid;
        char str[IFNAMSIZ];
        int r;

        assert(dev);
        assert(prefix);

        /* get ibmveth/ibmvnic slot-based names. */

        /* check if our direct parent is a VIO device with no other bus in-between */
        if (get_matching_parent(dev, (const char *[]) { "vio", NULL }, /* skip_virtio= */ false, NULL) < 0)
                return 0;

        log_device_debug(dev, "Parent device is in the vio subsystem.");

        /* The devices' $DEVPATH number is tied to (virtual) hardware (slot id
         * selected in the HMC), thus this provides a reliable naming (e.g.
         * "/devices/vio/30000002/net/eth1"); we ignore the bus number, as
         * there should only ever be one bus, and then remove leading zeros. */
        r = get_first_syspath_component(dev, "/sys/devices/vio/", &s);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get VIO bus ID and slot ID: %m");

        if (r != 8)
                return log_device_debug_errno(dev, EINVAL, "VIO bus ID and slot ID have invalid length: '%s'", s);

        if (!in_charset(s, HEXDIGITS))
                return log_device_debug_errno(dev, EINVAL, "VIO bus ID and slot ID contain invalid characters: '%s'", s);

        /* Parse only slot ID (the last 4 hexdigits). */
        r = safe_atou_full(s + 4, 16, &slotid);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to parse VIO slot from '%s': %m", s);

        if (snprintf_ok(str, sizeof str, "%sv%u", prefix, slotid))
                udev_builtin_add_property(dev, mode, "ID_NET_NAME_SLOT", str);
        log_device_debug(dev, "Vio slot identifier: slotid=%u", slotid);
        return 0;
}

static int names_platform(struct udev_device *dev, const char *prefix, enum udev_event_mode mode) {
        _cleanup_free_ char *p = NULL;
        const char *validchars;
        char vendor[5], model_str[5], instance_str[3];
        unsigned model, instance;
        char str[IFNAMSIZ];
        char *c;
        int r;

        assert(dev);
        assert(prefix);

        /* get ACPI path names for ARM64 platform devices */

        /* check if our direct parent is a platform device with no other bus in-between */
        if (get_matching_parent(dev, (const char *[]) { "platform", NULL }, /* skip_virtio= */ false, NULL) < 0)
                return 0;

        log_device_debug(dev, "Parent device is in the platform subsystem.");

        r = get_first_syspath_component(dev, "/sys/devices/platform/", &p);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get platform ID: %m");

        /* Platform devices are named after ACPI table match, and instance id
         * eg. "/sys/devices/platform/HISI00C2:00"
         * The Vendor (3 or 4 char), followed by hexadecimal model number : instance id. */
        if (r == 10 && p[7] == ':') {
                /* 3 char vendor string */
                strscpy(vendor, 4, p);
                strscpy(model_str, sizeof model_str, p + 3);
                strscpy(instance_str, sizeof instance_str, p + 8);
                validchars = UPPERCASE_LETTERS;
        } else if (r == 11 && p[8] == ':') {
                /* 4 char vendor string */
                strscpy(vendor, sizeof vendor, p);
                strscpy(model_str, sizeof model_str, p + 4);
                strscpy(instance_str, sizeof instance_str, p + 9);
                validchars = UPPERCASE_LETTERS DIGITS;
        } else
                return -EOPNOTSUPP;

        if (!in_charset(vendor, validchars))
                return log_device_debug_errno(dev, EINVAL, "Platform vendor contains invalid characters: '%s'", vendor);

        for (c = vendor; *c; c++)
                *c = tolower(*c);

        r = safe_atou_full(model_str, 16, &model);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to parse model number \"%s\": %m", model_str);

        r = safe_atou_full(instance_str, 16, &instance);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to parse instance id \"%s\": %m", instance_str);

        if (snprintf_ok(str, sizeof str, "%sa%s%xi%u", prefix, vendor, model, instance))
                udev_builtin_add_property(dev, mode, "ID_NET_NAME_PATH", str);
        log_device_debug(dev, "Platform identifier: vendor=%s model=%x instance=%u", vendor, model, instance);
        return 0;
}

static int names_devicetree_alias_prefix(struct udev_device *dev, const char *prefix, const char *alias_prefix, enum udev_event_mode mode) {
        _cleanup_udev_device_unref_ struct udev_device *aliases_dev = NULL, *ofnode_dev = NULL, *devicetree_dev = NULL;
        _cleanup_free_ char *alias_prefix_0 = NULL, *devicetree_path = NULL;
        _cleanup_closedir_ DIR *dir = NULL;
        const char *ofnode_path, *ofnode_syspath, *devicetree_syspath;
        struct dirent *de;
        int r;

        assert(dev);
        assert(prefix);
        assert(alias_prefix);

        /* Returns 1 if found, 0 if not found, negative if error */

        alias_prefix_0 = strjoin(alias_prefix, "0", NULL);
        if (!alias_prefix_0)
                return -ENOMEM;

        /* check if the device itself has an of_node */
        if (naming_scheme_has(NAMING_DEVICETREE_PORT_ALIASES)) {
                ofnode_dev = device_new_child(dev, "of_node");
                if (!ofnode_dev)
                        log_device_debug(dev, "Failed to get device of_node, ignoring.");
        }
        if (!ofnode_dev) {
                struct udev_device *parent;

                /* check if our direct parent has an of_node as a fallback */
                parent = udev_device_get_parent(dev);
                if (!parent)
                        return log_device_debug_errno(dev, ENOENT, "Failed to get parent device.");

                ofnode_dev = device_new_child(parent, "of_node");
                if (!ofnode_dev)
                        return log_device_debug_errno(parent, ENOENT, "Failed to get device of_node.");
        }

        ofnode_syspath = udev_device_get_syspath(ofnode_dev);

        /* /proc/device-tree should be a symlink to /sys/firmware/devicetree/base. */
        devicetree_path = realpath("/proc/device-tree", NULL);
        if (devicetree_path && path_startswith(devicetree_path, "/sys"))
                devicetree_dev = udev_device_new_from_syspath(udev_device_get_udev(dev), devicetree_path);
        if (!devicetree_dev)
                return log_debug_errno(ENOENT, "Failed to create udev_device object from '/proc/device-tree'.");

        devicetree_syspath = udev_device_get_syspath(devicetree_dev);

        /*
         * Example paths:
         * devicetree_syspath = /sys/firmware/devicetree/base
         * ofnode_syspath = /sys/firmware/devicetree/base/soc/ethernet@deadbeef
         * ofnode_path = soc/ethernet@deadbeef
         */
        ofnode_path = path_startswith(ofnode_syspath, devicetree_syspath);
        if (!ofnode_path)
                return log_device_debug_errno(ofnode_dev, EINVAL,
                                              "The device '%s' is not a child device of '%s'.",
                                              ofnode_syspath, devicetree_syspath);

        /* Get back our leading / to match the contents of the aliases */
        ofnode_path = strjoina("/", ofnode_path);

        aliases_dev = device_new_child(devicetree_dev, "aliases");
        if (!aliases_dev)
                return log_device_debug_errno(devicetree_dev, ENOENT, "Failed to get 'aliases' child device.");

        dir = opendir(udev_device_get_syspath(aliases_dev));
        if (!dir)
                return log_device_debug_errno(aliases_dev, errno, "Failed to open directory: %m");

        while ((de = readdir(dir))) {
                const char *alias = de->d_name, *alias_path, *alias_index, *conflict;
                char str[IFNAMSIZ];
                unsigned i;

                if (!IN_SET(de->d_type, DT_REG, DT_LNK))
                        continue;

                alias_index = startswith(alias, alias_prefix);
                if (!alias_index)
                        continue;

                if (device_get_sysattr_safe_string_filtered(aliases_dev, alias, &alias_path) < 0)
                        continue;

                if (!path_equal(ofnode_path, alias_path))
                        continue;

                /* If there's no index, we default to 0... */
                if (isempty(alias_index)) {
                        i = 0;
                        conflict = alias_prefix_0;
                } else {
                        r = safe_atou_full(alias_index, 0, &i);
                        if (r < 0)
                                return log_device_debug_errno(dev, r, "Could not get index of alias '%s': %m", alias);
                        conflict = alias_prefix;
                }

                /* ...but make sure we don't have an alias conflict */
                if (i == 0 && device_get_sysattr_safe_string_filtered(aliases_dev, conflict, NULL) >= 0)
                        return log_device_debug_errno(dev, EEXIST,
                                                      "DeviceTree alias conflict: '%s' and '%s' both exist.",
                                                      alias_prefix, alias_prefix_0);

                if (snprintf_ok(str, sizeof str, "%sd%u", prefix, i))
                        udev_builtin_add_property(dev, mode, "ID_NET_NAME_ONBOARD", str);
                log_device_debug(dev, "DeviceTree identifier: alias_index=%u", i);
                return 1;
        }

        return 0;
}

static int names_devicetree(struct udev_device *dev, const char *prefix, enum udev_event_mode mode) {
        int r;

        assert(dev);
        assert(prefix);

        if (!naming_scheme_has(NAMING_DEVICETREE_ALIASES))
                return 0;

        if (streq(prefix, "en"))
                r = names_devicetree_alias_prefix(dev, prefix, "ethernet", mode);
        else if (naming_scheme_has(NAMING_DEVICETREE_ALIASES_WLAN) &&
                 streq(prefix, "wl")) {
                r = names_devicetree_alias_prefix(dev, prefix, "wifi", mode);
                /* Sometimes DeviceTrees have WLAN devices with alias ethernetN, fall back to those */
                if (r == 0)
                        r = names_devicetree_alias_prefix(dev, prefix, "ethernet", mode);
        } else
                return -EOPNOTSUPP; /* Unsupported interface type */
        if (r < 0)
                return r;
        if (r == 0) /* Not found */
                return -ENOENT;

        return 0; /* Found */
}

static int names_pci(struct udev_device *dev, const char *prefix, enum udev_event_mode mode) {
        _cleanup_udev_device_unref_ struct udev_device *physfn_pcidev = NULL, *parent_pcidev = NULL;
        _cleanup_free_ char *virtfn_suffix = NULL, *subfunc_suffix = NULL, *combined_suffix = NULL;
        struct udev_device *parent;
        const char *suffix = NULL;
        bool is_child_function;

        assert(dev);
        assert(prefix);

        /* If the network device's direct parent is an auxiliary device that exposes a stable
         * 'sfnum' attribute (currently mlx5_core sub-functions), peel off the SF identity into
         * a 'S<sfnum>' suffix piece and pick up the aux device's underlying PCI function as
         * 'parent'. The aux device is just a bump on the path; everything below — PF/VF
         * resolution, slot/onboard lookup — proceeds the same way as for any PCI-rooted
         * network device. */
        if (naming_scheme_has(NAMING_SUBFUNC)) {
                struct udev_device *aux;

                if (get_matching_parent(dev, (const char *[]) { "auxiliary", NULL },
                                        /* skip_virtio= */ false, &aux) >= 0)
                        (void) get_subfunc_info(aux, &parent_pcidev, &subfunc_suffix);
        }

        /* SF: parent is the aux device's PCI function. Otherwise the network device's direct
         * parent must itself be a PCI device. */
        if (subfunc_suffix)
                parent = parent_pcidev;
        else if (get_matching_parent(dev, (const char *[]) { "pci", NULL }, /* skip_virtio= */ true, &parent) < 0)
                return 0;

        /* If parent is an SR-IOV VF, walk to the parent PF and add a 'v<N>' suffix piece. The
         * onboard BIOS label is intentionally not exposed for any "child function" (VF, SF, or
         * VF-SF), since the label refers to the parent's physical port, not to a logical child. */
        is_child_function = !!subfunc_suffix;
        if (naming_scheme_has(NAMING_SR_IOV_V) &&
            get_virtfn_info(parent, &physfn_pcidev, &virtfn_suffix) >= 0) {
                parent = physfn_pcidev;
                is_child_function = true;
        }
        if (!is_child_function)
                (void) names_pci_onboard_label(dev, parent, prefix, mode);

        /* Compose the final suffix in PF -> [VF ->] SF order, e.g. "v0", "S88", or "v0S88". */
        if (virtfn_suffix && subfunc_suffix) {
                combined_suffix = strjoin(virtfn_suffix, subfunc_suffix, NULL);
                if (!combined_suffix)
                        return -ENOMEM;
                suffix = combined_suffix;
        } else
                suffix = virtfn_suffix ?: subfunc_suffix;

        (void) names_pci_onboard(dev, parent, prefix, suffix, mode);
        (void) names_pci_slot(dev, parent, prefix, suffix, mode);
        return 0;
}

static int get_usb_specifier(struct udev_device *dev, char **ret) {
        _cleanup_free_ char *ports = NULL;
        char *config, *interf, *buf, *t;
        const char *sysname, *s;

        assert(dev);
        assert(ret);

        sysname = udev_device_get_sysname(dev);

        /* get USB port number chain, configuration, interface */
        s = strchr(sysname, '-');
        if (!s)
                return log_device_debug_errno(dev, EINVAL, "sysname \"%s\" does not have '-' in the expected place.", sysname);

        ports = strdup(s + 1);
        if (!ports)
                return -ENOMEM;

        t = strchr(ports, ':');
        if (!t)
                return log_device_debug_errno(dev, EINVAL, "sysname \"%s\" does not have ':' in the expected place.", sysname);

        *t = '\0';
        config = t + 1;
        t = strchr(config, '.');
        if (!t)
                return log_device_debug_errno(dev, EINVAL, "sysname \"%s\" does not have '.' in the expected place.", sysname);

        *t = '\0';
        interf = t + 1;

        /* prefix every port number in the chain with "u" */
        for (t = ports; (t = strchr(t, '.')); )
                *t = 'u';

        /* suppress the common config == 1 */
        if (streq(config, "1"))
                config = NULL;

        /* suppress the interface == 0 */
        if (streq(interf, "0"))
                interf = NULL;

        buf = strjoin("u", ports,
                      config ? "c" : "", strempty(config),
                      interf ? "i" : "", strempty(interf), NULL);
        if (!buf)
                return -ENOMEM;

        log_device_debug(dev, "USB name identifier: ports=%s config=%s interface=%s -> %s",
                         ports, strna(config), strna(interf), buf);

        *ret = buf;
        return 0;
}

static int names_usb(struct udev_device *dev, const char *prefix, enum udev_event_mode mode) {
        struct udev_device *usbdev, *pcidev;
        _cleanup_free_ char *suffix = NULL;
        char str[IFNAMSIZ];
        int r;

        assert(dev);
        assert(prefix);

        /* USB device */

        usbdev = udev_device_get_parent_with_subsystem_devtype(dev, "usb", "usb_interface");
        if (!usbdev)
                return log_device_debug_errno(dev, ENOENT, "Could not find USB parent device.");

        r = get_usb_specifier(usbdev, &suffix);
        if (r < 0)
                return r;

        /* If the USB bus is on PCI bus, then suffix the USB specifier to the name based on the PCI bus. */
        pcidev = udev_device_get_parent_with_subsystem_devtype(usbdev, "pci", NULL);
        if (pcidev)
                return names_pci_slot(dev, pcidev, prefix, suffix, mode);

        if (!naming_scheme_has(NAMING_USB_HOST))
                return log_device_debug_errno(usbdev, ENOENT, "Failed to get parent PCI bus.");

        /* Otherwise, e.g. on-chip asics that have USB ports, use the USB specifier as is. */
        if (snprintf_ok(str, sizeof str, "%s%s", prefix, suffix))
                udev_builtin_add_property(dev, mode, "ID_NET_NAME_PATH", str);

        return 0;
}

static int get_bcma_specifier(struct udev_device *dev, char **ret) {
        const char *sysname;
        char *buf = NULL;
        unsigned core;

        assert(dev);
        assert(ret);

        sysname = udev_device_get_sysname(dev);

        /* bus num:core num */
        if (sscanf(sysname, "bcma%*u:%u", &core) != 1)
                return log_device_debug_errno(dev, EINVAL, "Failed to parse BCMA device information.");

        /* suppress the common core == 0 */
        if (core > 0 && asprintf(&buf, "b%u", core) < 0)
                return -ENOMEM;

        log_device_debug(dev, "BCMA core identifier: core=%u -> \"%s\"", core, strna(buf));

        *ret = buf;
        return 0;
}

static int names_bcma(struct udev_device *dev, const char *prefix, enum udev_event_mode mode) {
        struct udev_device *bcmadev, *pcidev;
        _cleanup_free_ char *suffix = NULL;
        int r;

        assert(dev);
        assert(prefix);

        bcmadev = udev_device_get_parent_with_subsystem_devtype(dev, "bcma", NULL);
        if (!bcmadev)
                return log_device_debug_errno(dev, ENOENT, "Could not get BCMA parent device.");

        pcidev = udev_device_get_parent_with_subsystem_devtype(bcmadev, "pci", NULL);
        if (!pcidev)
                return log_device_debug_errno(dev, ENOENT, "Could not get PCI parent device.");

        r = get_bcma_specifier(bcmadev, &suffix);
        if (r < 0)
                return r;

        return names_pci_slot(dev, pcidev, prefix, suffix, mode);
}

static int names_ccw(struct udev_device *dev, const char *prefix, enum udev_event_mode mode) {
        struct udev_device *cdev;
        const char *bus_id;
        size_t bus_id_start, bus_id_len;
        char str[IFNAMSIZ];

        assert(dev);
        assert(prefix);

        /* get path names for Linux on System z network devices */

        if (get_matching_parent(dev, (const char *[]) { "ccwgroup", "ccw", NULL }, /* skip_virtio= */ true, &cdev) < 0)
                return 0;

        log_device_debug(dev, "Device is CCW.");

        /* Retrieve bus-ID of the CCW device.  The bus-ID uniquely
         * identifies the network device on the Linux on System z channel
         * subsystem.  Note that the bus-ID contains lowercase characters.
         */
        bus_id = udev_device_get_sysname(cdev);

        /* Check the length of the bus-ID. Rely on the fact that the kernel provides a correct bus-ID;
         * alternatively, improve this check and parse and verify each bus-ID part...
         */
        bus_id_len = strlen(bus_id);
        if (!IN_SET(bus_id_len, 8, 9))
                return log_device_debug_errno(cdev, EINVAL, "Invalid bus_id: '%s'", bus_id);

        /* Strip leading zeros from the bus id for aesthetic purposes. This
         * keeps the ccw names stable, yet much shorter in general case of
         * bus_id 0.0.0600 -> 600. This is similar to e.g. how PCI domain is
         * not prepended when it is zero. Preserve the last 0 for 0.0.0000.
         */
        bus_id_start = strspn(bus_id, ".0");
        bus_id += bus_id_start < bus_id_len ? bus_id_start : bus_id_len - 1;

        /* Use the CCW bus-ID as network device name */
        if (snprintf_ok(str, sizeof str, "%sc%s", prefix, bus_id))
                udev_builtin_add_property(dev, mode, "ID_NET_NAME_PATH", str);
        log_device_debug(dev, "CCW identifier: ccw_busid=%s", bus_id);
        return 0;
}

/* IEEE Organizationally Unique Identifier vendor string */
static int ieee_oui(struct udev_device *dev, const uint8_t mac[6], enum udev_event_mode mode) {
        char str[32];

        assert(dev);
        assert(mac);

        /* skip commonly misused 00:00:00 (Xerox) prefix */
        if (mac[0] == 0 && mac[1] == 0 && mac[2] == 0)
                return -EINVAL;

        xsprintf(str, "OUI:%02X%02X%02X%02X%02X%02X",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

        return udev_builtin_hwdb_lookup(dev, NULL, str, NULL, mode);
}

/* Parse a hardware address like systemd's parse_hw_addr(), but only accept addresses of 6 bytes. */
static int parse_ether_addr(const char *s, uint8_t ret[6]) {
        size_t field_size, len = 0;
        char sep;

        assert(s);
        assert(ret);

        /* This accepts the following formats:
         *
         * Dot separated 2 bytes format: xxyy.zzaa.bbcc
         * Colon separated 1 bytes format: xx:yy:zz:aa:bb:cc
         * Hyphen separated 1 bytes format: xx-yy-zz-aa-bb-cc
         */

        sep = s[strspn(s, HEXDIGITS)];
        if (sep == '.')
                field_size = 2;
        else if (IN_SET(sep, ':', '-'))
                field_size = 1;
        else
                return -EINVAL;

        for (;;) {
                unsigned data = 0;
                size_t i;

                for (i = 0; i < field_size * 2; i++) {
                        int x;

                        if (*s == '\0' || *s == sep) {
                                if (i == 0)
                                        return -EINVAL;
                                break;
                        }

                        x = unhexchar(*s);
                        if (x < 0)
                                return -EINVAL;

                        data = (data << 4) | (unsigned) x;
                        s++;
                }

                if (*s != '\0' && *s != sep)
                        return -EINVAL;

                if (len + field_size > 6)
                        return -EINVAL;

                if (field_size == 2) {
                        ret[len++] = (data & 0xff00) >> 8;
                        ret[len++] = data & 0xff;
                } else
                        ret[len++] = data;

                if (*s == '\0')
                        break;
                s++;
        }

        if (len != 6)
                return -EINVAL;

        return 0;
}

static int names_mac(struct udev_device *dev, const char *prefix, enum udev_event_mode mode) {
        unsigned iftype, assign_type;
        uint8_t mac[6];
        const char *s;
        char str[IFNAMSIZ];
        int r;

        assert(dev);
        assert(prefix);

        r = device_get_sysattr_unsigned_filtered(dev, "type", &iftype);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to read 'type' attribute: %m");

        /* The persistent part of a hardware address of an InfiniBand NIC is 8 bytes long. We cannot
         * fit this much in an iface name.
         * TODO: but it can be used as alternative names?? */
        if (iftype == ARPHRD_INFINIBAND)
                return log_device_debug_errno(dev, EOPNOTSUPP, "Not generating MAC name for infiniband device.");

        /* check for NET_ADDR_PERM, skip random MAC addresses */
        r = device_get_sysattr_unsigned_filtered(dev, "addr_assign_type", &assign_type);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to read/parse addr_assign_type: %m");

        if (assign_type != NET_ADDR_PERM)
                return log_device_debug_errno(dev, EINVAL, "addr_assign_type=%u, MAC address is not permanent.", assign_type);

        r = device_get_sysattr_safe_string_filtered(dev, "address", &s);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to read 'address' attribute: %m");

        r = parse_ether_addr(s, mac);
        if (r < 0)
                return log_device_debug_errno(dev, EOPNOTSUPP, "Not generating MAC name for device with MAC address '%s'.", s);

        /* Skip empty MAC addresses. eudev: systemd generates e.g. enx000000000000 since v250, as a side
         * effect of taking the address from the netlink information (eaba9bb3e6), and does not use MAC
         * based names unless configured to. Keep skipping them, as 80-net-name-slot.rules uses
         * ID_NET_NAME_MAC as the interface name when no other name is available. */
        if (mac[0] == 0 && mac[1] == 0 && mac[2] == 0 && mac[3] == 0 && mac[4] == 0 && mac[5] == 0)
                return log_device_debug_errno(dev, EINVAL, "Not generating MAC name for empty MAC address.");

        xsprintf(str, "%sx%02x%02x%02x%02x%02x%02x", prefix,
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        udev_builtin_add_property(dev, mode, "ID_NET_NAME_MAC", str);
        log_device_debug(dev, "MAC address identifier: hw_addr=%s -> %s", s, str + strlen(prefix));

        (void) ieee_oui(dev, mac, mode);
        return 0;
}

static int names_netdevsim(struct udev_device *dev, const char *prefix, enum udev_event_mode mode) {
        struct udev_device *netdevsimdev;
        const char *phys_port_name;
        unsigned addr;
        char str[IFNAMSIZ];
        int r;

        assert(dev);
        assert(prefix);

        /* get netdevsim path names */

        if (!naming_scheme_has(NAMING_NETDEVSIM))
                return 0;

        netdevsimdev = udev_device_get_parent_with_subsystem_devtype(dev, "netdevsim", NULL);
        if (!netdevsimdev)
                return -ENOENT;

        r = device_get_sysnum_unsigned(netdevsimdev, &addr);
        if (r < 0)
                return log_device_debug_errno(netdevsimdev, r, "Failed to get device sysnum: %m");

        r = device_get_sysattr_safe_string_filtered(dev, "phys_port_name", &phys_port_name);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get 'phys_port_name' attribute: %m");
        if (isempty(phys_port_name))
                return log_device_debug_errno(dev, EOPNOTSUPP, "The 'phys_port_name' attribute is empty.");

        if (snprintf_ok(str, sizeof str, "%si%un%s", prefix, addr, phys_port_name))
                udev_builtin_add_property(dev, mode, "ID_NET_NAME_PATH", str);
        log_device_debug(dev, "Netdevsim identifier: address=%u, port_name=%s", addr, phys_port_name);
        return 0;
}

static int names_xen(struct udev_device *dev, const char *prefix, enum udev_event_mode mode) {
        _cleanup_free_ char *vif = NULL;
        const char *p;
        unsigned id;
        char str[IFNAMSIZ];
        int r;

        assert(dev);
        assert(prefix);

        /* get xen vif "slot" based names. */

        if (!naming_scheme_has(NAMING_XEN_VIF))
                return 0;

        /* check if our direct parent is a Xen VIF device with no other bus in-between */
        if (get_matching_parent(dev, (const char *[]) { "xen", NULL }, /* skip_virtio= */ false, NULL) < 0)
                return 0;

        /* Use the vif-n name to extract "n" */
        r = get_first_syspath_component(dev, "/sys/devices/", &vif);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get Xen VIF name: %m");

        p = startswith(vif, "vif-");
        if (!p)
                return log_device_debug_errno(dev, EINVAL, "Invalid vif name: '%s'.", vif);

        r = safe_atou_full(p, SAFE_ATO_REFUSE_PLUS_MINUS | SAFE_ATO_REFUSE_LEADING_ZERO |
                           SAFE_ATO_REFUSE_LEADING_WHITESPACE | 10, &id);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to parse vif index from '%s': %m", p);

        if (snprintf_ok(str, sizeof str, "%sX%u", prefix, id))
                udev_builtin_add_property(dev, mode, "ID_NET_NAME_SLOT", str);
        log_device_debug(dev, "Xen identifier: id=%u", id);
        return 0;
}

static int get_ifname_prefix(struct udev_device *dev, const char **ret) {
        unsigned iftype;
        int r;

        assert(dev);
        assert(ret);

        r = device_get_sysattr_unsigned_filtered(dev, "type", &iftype);
        if (r < 0)
                return r;

        /* handle only ARPHRD_ETHER, ARPHRD_SLIP, ARPHRD_INFINIBAND, and ARPHRD_MCTP devices */
        switch (iftype) {
        case ARPHRD_ETHER: {
                const char *devtype = udev_device_get_devtype(dev);

                if (streq_ptr(devtype, "wlan"))
                        *ret = "wl";
                else if (streq_ptr(devtype, "wwan"))
                        *ret = "ww";
                else
                        *ret = "en";
                return 0;
        }
        case ARPHRD_INFINIBAND:
                if (!naming_scheme_has(NAMING_INFINIBAND))
                        return -EOPNOTSUPP;

                *ret = "ib";
                return 0;

        case ARPHRD_SLIP:
                *ret = "sl";
                return 0;

        case ARPHRD_MCTP:
                if (!naming_scheme_has(NAMING_MCTP))
                        return -EOPNOTSUPP;

                *ret = "mc";
                return 0;

        default:
                return -EOPNOTSUPP;
        }
}

static int device_is_stacked(struct udev_device *dev) {
        int ifindex, iflink, r;

        assert(dev);

        ifindex = udev_device_get_ifindex(dev);
        if (ifindex <= 0)
                return -ENOENT;

        r = device_get_sysattr_int_filtered(dev, "iflink", &iflink);
        if (r < 0)
                return r;

        return ifindex != iflink;
}

static int builtin_net_id(struct udev_device *dev, int argc __attribute__((unused)), char *argv[] __attribute__((unused)), enum udev_event_mode mode) {
        const char *prefix;
        int r;

        /* Normally already done by the init hook, but read udev.conf also when that did not run */
        naming_scheme_init(udev_device_get_udev(dev));

        if (!naming_scheme_has(NAMING_SYSTEMD))
                return udev_builtin_net_id_eudev(dev, mode);

        /* skip stacked devices, like VLANs, ... */
        r = device_is_stacked(dev);
        if (r < 0) {
                log_device_debug_errno(dev, r, "Failed to check if the device is stacked: %m");
                return EXIT_FAILURE;
        }
        if (r > 0)
                return EXIT_SUCCESS;

        r = get_ifname_prefix(dev, &prefix);
        if (r < 0) {
                log_device_debug_errno(dev, r, "Failed to determine prefix for network interface naming, ignoring: %m");
                return EXIT_SUCCESS;
        }

        udev_builtin_add_property(dev, mode, "ID_NET_NAMING_SCHEME", naming_scheme()->name);

        (void) names_mac(dev, prefix, mode);
        (void) names_devicetree(dev, prefix, mode);
        (void) names_ccw(dev, prefix, mode);
        (void) names_vio(dev, prefix, mode);
        (void) names_platform(dev, prefix, mode);
        (void) names_netdevsim(dev, prefix, mode);
        (void) names_xen(dev, prefix, mode);
        (void) names_pci(dev, prefix, mode);
        (void) names_usb(dev, prefix, mode);
        (void) names_bcma(dev, prefix, mode);

        return EXIT_SUCCESS;
}

static int builtin_net_id_init(struct udev *udev) {
        /* Load naming scheme here to suppress log messages in workers. */
        naming_scheme_init(udev);
        return 0;
}

const struct udev_builtin udev_builtin_net_id = {
        .name = "net_id",
        .cmd = builtin_net_id,
        .init = builtin_net_id_init,
        .help = "Network device properties",
};
