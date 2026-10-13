/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/ethtool.h>
#include <linux/netlink.h>
#include <linux/sockios.h>

#include "udev.h"

static int ethtool_get_driver(const char *ifname, char **ret) {
        struct ethtool_drvinfo ecmd = {
                .cmd = ETHTOOL_GDRVINFO,
        };
        struct ifreq ifr = {
                .ifr_data = (void*) &ecmd,
        };
        _cleanup_close_ int fd = -1;
        char *d;

        assert(ifname);
        assert(ret);

        /* Traditionally only AF_INET was good for the network interface ioctl()s. Since kernel 4.6
         * AF_NETLINK works for this too, hence fall back to it if AF_INET is not available. */
        fd = socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, 0);
        if (fd < 0)
                fd = socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_GENERIC);
        if (fd < 0)
                return -errno;

        strscpy(ifr.ifr_name, sizeof(ifr.ifr_name), ifname);

        if (ioctl(fd, SIOCETHTOOL, &ifr) < 0)
                return -errno;

        if (isempty(ecmd.driver))
                return -ENODATA;

        d = strdup(ecmd.driver);
        if (!d)
                return -ENOMEM;

        *ret = d;
        return 0;
}

static int builtin_net_driver_set_driver(struct udev_device *dev, int argc __attribute__((unused)), char *argv[] __attribute__((unused)), enum udev_event_mode mode) {
        _cleanup_free_ char *lesc1 = NULL;
        _cleanup_free_ char *driver = NULL;
        const char *ifname;
        int r;

        /* Prefer the INTERFACE property, as '!' in the sysname is replaced by '/'. */
        ifname = udev_device_get_property_value(dev, "INTERFACE");
        if (!ifname)
                ifname = udev_device_get_sysname(dev);
        /* Like systemd, the errors are returned as negative error codes, with the reason. */
        if (!ifname)
                return log_device_warning_errno(dev, ENOENT, "Failed to get network interface name: %m");

        r = ethtool_get_driver(ifname, &driver);
        if (IN_SET(r, -EOPNOTSUPP, -ENOTTY, -ENOSYS, -EAFNOSUPPORT, -EPFNOSUPPORT,
                      -EPROTONOSUPPORT, -ESOCKTNOSUPPORT, -ENOPROTOOPT)) {
                log_device_debug_errno(dev, r,
                                       "Querying driver name via ethtool API is not supported by device '%s', ignoring: %m",
                                       utf8_escape_for_log(ifname, &lesc1));
                return EXIT_SUCCESS;
        }
        if (r == -ENODEV) {
                log_device_debug_errno(dev, r, "Device already vanished, ignoring.");
                return EXIT_SUCCESS;
        }
        if (r < 0)
                return log_device_warning_errno(dev, r, "Failed to get driver for '%s': %m",
                                                utf8_escape_for_log(ifname, &lesc1));

        return udev_builtin_add_property(dev, mode, "ID_NET_DRIVER", driver);
}

const struct udev_builtin udev_builtin_net_driver = {
        .name = "net_driver",
        .cmd = builtin_net_driver_set_driver,
        .help = "Set driver for network device",
        .run_once = true,
};
