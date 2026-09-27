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
#include "udev-util.h"

#ifndef ALTIFNAMSIZ
#define ALTIFNAMSIZ 128
#endif

#ifndef NET_ADDR_PERM
#define NET_ADDR_PERM 0
#endif

#ifndef HEXDIGITS
#define HEXDIGITS DIGITS "abcdefABCDEF"
#endif

#define ONBOARD_14BIT_INDEX_MAX ((1U << 14) - 1)

#define log_device_debug(dev, fmt, ...) \
        log_debug("%s: " fmt, udev_device_get_sysname(dev), ##__VA_ARGS__)
#define log_device_debug_errno(dev, error, fmt, ...) \
        log_debug_errno(error, "%s: " fmt, udev_device_get_sysname(dev), ##__VA_ARGS__)

static inline const char *strempty(const char *s) {
        return s ?: "";
}

static inline const char *strna(const char *s) {
        return s ?: "n/a";
}

static bool device_in_subsystem(struct udev_device *dev, const char *subsystem) {
        return streq_ptr(udev_device_get_subsystem(dev), subsystem);
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

static int get_port_specifier(struct udev_device *dev, char **ret) {
        unsigned dev_port;
        char *buf;
        int r;

        assert(dev);
        assert(ret);

        /* Try to use the kernel provided port index for the case when multiple ports on a single PCI
         * function. */
        r = device_get_sysattr_unsigned(dev, "dev_port", &dev_port);
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
         * doesn't currently. */
        return idx <= ONBOARD_14BIT_INDEX_MAX;
}

static int pci_get_onboard_index(struct udev_device *dev, unsigned *ret) {
        unsigned idx;
        int r;

        assert(dev);
        assert(ret);

        /* ACPI _DSM — device specific method for naming a PCI or PCI Express device */
        r = device_get_sysattr_unsigned(dev, "acpi_index", &idx);
        if (r < 0)
                /* SMBIOS type 41 — Onboard Devices Extended Information */
                r = device_get_sysattr_unsigned(dev, "index", &idx);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Could not obtain onboard index: %m");

        if (idx == 0)
                return log_device_debug_errno(dev, EINVAL, "Onboard index 0 is not used.");
        if (!is_valid_onboard_index(idx))
                return log_device_debug_errno(dev, EINVAL, "Not a valid onboard index: %u", idx);

        *ret = idx;
        return 0;
}

static int names_pci_onboard(struct udev_device *dev, struct udev_device *pci_dev, const char *prefix, const char *suffix, bool test) {
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
                udev_builtin_add_property(dev, test, "ID_NET_NAME_ONBOARD", str);
        else
                str[0] = '\0';

        log_device_debug(dev, "PCI onboard index identifier: index=%u port=%s -> %s",
                         idx, strna(port), isempty(str) ? "n/a" : str);

        return 0;
}

static int names_pci_onboard_label(struct udev_device *dev, struct udev_device *pci_dev, const char *prefix, bool test) {
        const char *label;
        char str[ALTIFNAMSIZ];
        int r;

        assert(dev);
        assert(pci_dev);
        assert(prefix);

        /* retrieve on-board label from firmware */
        r = device_get_sysattr_safe_string(pci_dev, "label", &label);
        if (r < 0)
                return log_device_debug_errno(pci_dev, r, "Failed to get PCI onboard label: %m");

        if (snprintf_ok(str, sizeof str, "%s%s", prefix, label))
                udev_builtin_add_property(dev, test, "ID_NET_LABEL_ONBOARD", str);

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

                if (device_get_sysattr_safe_string(pci, path, &address) < 0)
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
        const char *slots;
        uint32_t slot = 0;  /* avoid false maybe-uninitialized warning */
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

        r = pci_get_hotplug_slot_from_address(dev, pci, dir, &slot);
        if (r < 0)
                return r;
        if (r == 0)
                return -ENOENT;

        *ret = slot;
        return 0;
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

        /* The PCI domain is only prepended when it is not 0. */
        if (domain > 0 && asprintf(&domain_spec, "P%u", domain) < 0)
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

static int names_pci_slot(struct udev_device *dev, struct udev_device *pci_dev, const char *prefix, const char *suffix, bool test) {
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
                udev_builtin_add_property(dev, test, "ID_NET_NAME_PATH", str);
        else
                str[0] = '\0';

        log_device_debug(dev, "PCI path identifier: domain=%s bus_and_slot=%s func=%s port=%s -> %s",
                         strna(domain), bus_and_slot, strna(func), strna(port), isempty(str) ? "n/a" : str);

        r = pci_get_hotplug_slot(pci_dev, &slot);
        if (r < 0)
                return r;

        if (snprintf_ok(str, sizeof str, "%s%ss%" PRIu32 "%s%s%s",
                        prefix, strempty(domain), slot, strempty(func), strempty(port), strempty(suffix)))
                udev_builtin_add_property(dev, test, "ID_NET_NAME_SLOT", str);
        else
                str[0] = '\0';

        log_device_debug(dev, "PCI slot identifier: domain=%s slot=%" PRIu32 " func=%s port=%s -> %s",
                         strna(domain), slot, strna(func), strna(port), isempty(str) ? "n/a" : str);

        return 0;
}

static int names_pci(struct udev_device *dev, const char *prefix, bool test) {
        struct udev_device *parent;

        assert(dev);
        assert(prefix);

        /* check if our direct parent is a PCI device with no other bus in-between */
        if (get_matching_parent(dev, (const char *[]) { "pci", NULL }, /* skip_virtio= */ true, &parent) < 0)
                return 0;

        (void) names_pci_onboard_label(dev, parent, prefix, test);
        (void) names_pci_onboard(dev, parent, prefix, NULL, test);
        (void) names_pci_slot(dev, parent, prefix, NULL, test);
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

static int names_usb(struct udev_device *dev, const char *prefix, bool test) {
        struct udev_device *usbdev, *pcidev;
        _cleanup_free_ char *suffix = NULL;
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
                return names_pci_slot(dev, pcidev, prefix, suffix, test);

        return log_device_debug_errno(usbdev, ENOENT, "Failed to get parent PCI bus.");
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

static int names_bcma(struct udev_device *dev, const char *prefix, bool test) {
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

        return names_pci_slot(dev, pcidev, prefix, suffix, test);
}

static int names_ccw(struct udev_device *dev, const char *prefix, bool test) {
        struct udev_device *cdev;
        const char *bus_id;
        size_t bus_id_len;
        char str[IFNAMSIZ];

        assert(dev);
        assert(prefix);

        /* get path names for Linux on System z network devices */

        /* Network devices are always grouped CCW devices */
        if (get_matching_parent(dev, (const char *[]) { "ccwgroup", NULL }, /* skip_virtio= */ false, &cdev) < 0)
                return 0;

        log_device_debug(dev, "Device is CCW.");

        /* Retrieve bus-ID of the grouped CCW device.  The bus-ID uniquely
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

        /* Use the CCW bus-ID as network device name */
        if (snprintf_ok(str, sizeof str, "%sccw%s", prefix, bus_id))
                udev_builtin_add_property(dev, test, "ID_NET_NAME_PATH", str);
        log_device_debug(dev, "CCW identifier: ccw_busid=%s", bus_id);
        return 0;
}

/* IEEE Organizationally Unique Identifier vendor string */
static int ieee_oui(struct udev_device *dev, const uint8_t mac[6], bool test) {
        char str[32];

        assert(dev);
        assert(mac);

        /* skip commonly misused 00:00:00 (Xerox) prefix */
        if (mac[0] == 0 && mac[1] == 0 && mac[2] == 0)
                return -EINVAL;

        xsprintf(str, "OUI:%02X%02X%02X%02X%02X%02X",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

        return udev_builtin_hwdb_lookup(dev, NULL, str, NULL, test);
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

static int names_mac(struct udev_device *dev, const char *prefix, bool test) {
        unsigned assign_type;
        uint8_t mac[6];
        const char *s;
        char str[IFNAMSIZ];
        int r;

        assert(dev);
        assert(prefix);

        /* check for NET_ADDR_PERM, skip random MAC addresses */
        r = device_get_sysattr_unsigned(dev, "addr_assign_type", &assign_type);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to read/parse addr_assign_type: %m");

        if (assign_type != NET_ADDR_PERM)
                return log_device_debug_errno(dev, EINVAL, "addr_assign_type=%u, MAC address is not permanent.", assign_type);

        r = device_get_sysattr_safe_string(dev, "address", &s);
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
        udev_builtin_add_property(dev, test, "ID_NET_NAME_MAC", str);
        log_device_debug(dev, "MAC address identifier: hw_addr=%s -> %s", s, str + strlen(prefix));

        (void) ieee_oui(dev, mac, test);
        return 0;
}

static int get_ifname_prefix(struct udev_device *dev, const char **ret) {
        unsigned iftype;
        int r;

        assert(dev);
        assert(ret);

        r = device_get_sysattr_unsigned(dev, "type", &iftype);
        if (r < 0)
                return r;

        /* handle only ARPHRD_ETHER and ARPHRD_SLIP devices */
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
        case ARPHRD_SLIP:
                *ret = "sl";
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

        r = device_get_sysattr_int(dev, "iflink", &iflink);
        if (r < 0)
                return r;

        return ifindex != iflink;
}

static int builtin_net_id(struct udev_device *dev, int argc __attribute__((unused)), char *argv[] __attribute__((unused)), bool test) {
        const char *prefix;
        int r;

        if (!naming_scheme_has(NAMING_SYSTEMD))
                return udev_builtin_net_id_eudev(dev, test);

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

        udev_builtin_add_property(dev, test, "ID_NET_NAMING_SCHEME", naming_scheme()->name);

        (void) names_mac(dev, prefix, test);
        (void) names_ccw(dev, prefix, test);
        (void) names_pci(dev, prefix, test);
        (void) names_usb(dev, prefix, test);
        (void) names_bcma(dev, prefix, test);

        return EXIT_SUCCESS;
}

static int builtin_net_id_init(struct udev *udev __attribute__((unused))) {
        /* Load naming scheme here to suppress log messages in workers. */
        naming_scheme();
        return 0;
}

const struct udev_builtin udev_builtin_net_id = {
        .name = "net_id",
        .cmd = builtin_net_id,
        .init = builtin_net_id_init,
        .help = "Network device properties",
};
