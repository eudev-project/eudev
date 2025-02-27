/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <stdlib.h>

#include "factory-reset.h"
#include "udev.h"

/* Sometimes it is relevant in udev rules to know whether factory reset is currently in effect or not. Report
 * the current state at moment of probing as a udev property. This can be used to create certain device node
 * symlinks only once factory reset is complete, or even mark whole devices as SYSTEMD_READY=0 as long as
 * factory reset is still ongoing. */

static int builtin_factory_reset(struct udev_device *dev, int argc, char *argv[], enum udev_event_mode mode) {
        FactoryResetMode f;

        if (argc != 2 || !streq(argv[1], "status")) {
                log_warning("%s: expected: status", argv[0]);
                return EXIT_FAILURE;
        }

        /* Report factory reset mode at the moment of probing a device. */
        f = factory_reset_mode();
        if (f < 0) {
                log_debug_errno(f, "%s: Unable to detect factory reset mode, ignoring: %m",
                                udev_device_get_sysname(dev));
                return EXIT_SUCCESS;
        }

        udev_builtin_add_property(dev, mode, "ID_FACTORY_RESET", factory_reset_mode_to_string(f));
        return EXIT_SUCCESS;
}

const struct udev_builtin udev_builtin_factory_reset = {
        .name = "factory_reset",
        .cmd = builtin_factory_reset,
        .help = "Factory Reset Mode",
        .run_once = true,
};
