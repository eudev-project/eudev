/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

#include "efivars.h"
#include "factory-reset.h"
#include "id128-util.h"
#include "json-util.h"
#include "log.h"
#include "os-util.h"
#include "util.h"

static bool factory_reset_supported(void) {
        int r;

        r = secure_getenv_bool("SYSTEMD_FACTORY_RESET_SUPPORTED");
        if (r >= 0)
                return r;
        if (r != -ENXIO)
                log_debug_errno(r, "Unable to parse $SYSTEMD_FACTORY_RESET_SUPPORTED, ignoring: %m");

        return true;
}

static FactoryResetMode factory_reset_mode_efi_variable(void) {
        static const char *const fields[] = { "osReleaseId", "osReleaseImageId", "bootId" };
        static const char *const os_release_fields[] = { "ID", "IMAGE_ID" };
        _cleanup_free_ char *req_str = NULL, *req_id = NULL, *req_image_id = NULL, *req_boot_id = NULL;
        _cleanup_free_ char *id = NULL, *image_id = NULL;
        char *values[3], *os_release_values[2];
        id128_t req_boot, boot_id;
        int r;

        if (!is_efi_boot()) {
                log_debug("Not booted in EFI mode, not checking FactoryResetRequest variable.");
                return FACTORY_RESET_UNSPECIFIED;
        }

        r = efi_get_variable_string(EFI_SYSTEMD_VARIABLE_STR("FactoryResetRequest"), &req_str);
        if (r == -ENOENT) {
                log_debug_errno(r, "EFI variable FactoryResetRequest is not set, skipping.");
                return FACTORY_RESET_UNSPECIFIED;
        }
        if (r < 0)
                return log_debug_errno(r, "Failed to get EFI variable FactoryResetRequest: %m");

        /* The variable contains a JSON object with the string members osReleaseId (mandatory),
         * osReleaseImageId (optional) and bootId (mandatory); other members are ignored. */
        r = json_object_get_strings(req_str, fields, values, ELEMENTSOF(fields));
        if (r == -EBADMSG) {
                log_debug_errno(r, "EFI variable FactoryResetRequest set to invalid JSON, ignoring: %m");
                return FACTORY_RESET_UNSPECIFIED;
        }
        if (r < 0) {
                log_debug_errno(r, "Unable to dispatch EFI variable FactoryResetRequest, ignoring: %m");
                return FACTORY_RESET_UNSPECIFIED;
        }
        req_id = values[0];
        req_image_id = values[1];
        req_boot_id = values[2];

        if (!req_id || !req_boot_id) {
                log_debug("EFI variable FactoryResetRequest lacks a mandatory field, ignoring.");
                return FACTORY_RESET_UNSPECIFIED;
        }

        r = id128_from_string(req_boot_id, &req_boot);
        if (r < 0) {
                log_debug_errno(r, "Unable to dispatch EFI variable FactoryResetRequest, bootId is not a valid ID, ignoring: %m");
                return FACTORY_RESET_UNSPECIFIED;
        }

        r = parse_os_release(os_release_fields, os_release_values, ELEMENTSOF(os_release_fields));
        if (r < 0)
                return log_debug_errno(r, "Failed to parse os-release: %m");
        id = os_release_values[0];
        image_id = os_release_values[1];

        if (!streq_ptr(req_id, id) || !streq_ptr(req_image_id, image_id)) {
                log_debug("FactoryResetRequest EFI variable set, but not for us, ignoring.");
                return FACTORY_RESET_UNSPECIFIED;
        }

        r = id128_get_boot(&boot_id);
        if (r < 0)
                return log_debug_errno(r, "Failed to query boot ID: %m");

        if (id128_equal(req_boot, boot_id)) {
                /* NB: if the boot ID in the EFI variable matches our *current* one, then the request is not
                 * intended for us, but for the *next* boot. */
                log_debug("EFI variable FactoryResetRequest set for next boot.");
                return FACTORY_RESET_PENDING;
        }

        return FACTORY_RESET_ON;
}

FactoryResetMode factory_reset_mode(void) {
        bool b;
        int r;

        if (!factory_reset_supported())
                return FACTORY_RESET_UNSUPPORTED;

        /* First check if we already completed a factory reset in this boot */
        if (access("/run/systemd/factory-reset-complete", F_OK) >= 0)
                return FACTORY_RESET_COMPLETE;
        if (errno != ENOENT)
                return log_debug_errno(errno, "Can't determine if /run/systemd/factory-reset-complete exists: %m");

        r = proc_cmdline_get_bool("systemd.factory_reset", &b);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse systemd.factory_reset kernel command line argument: %m");
        if (r == 0)  /* Check EFI variable in case kernel cmdline switch is not specified */
                return factory_reset_mode_efi_variable();

        return b ? FACTORY_RESET_ON : FACTORY_RESET_OFF; /* Honour if explicitly turned off or on via kernel cmdline */
}

static const char* const factory_reset_mode_table[_FACTORY_RESET_MODE_MAX] = {
        [FACTORY_RESET_UNSUPPORTED] = "unsupported",
        [FACTORY_RESET_UNSPECIFIED] = "unspecified",
        [FACTORY_RESET_OFF]         = "off",
        [FACTORY_RESET_ON]          = "on",
        [FACTORY_RESET_COMPLETE]    = "complete",
        [FACTORY_RESET_PENDING]     = "pending",
};

DEFINE_STRING_TABLE_LOOKUP(factory_reset_mode, FactoryResetMode);
