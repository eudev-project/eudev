/*
 * load kernel modules
 *
 * Copyright (C) 2011-2012 Kay Sievers <kay@vrfy.org>
 * Copyright (C) 2011 ProFUSION embedded systems
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
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <libkmod.h>

#include "udev.h"
#include "strv.h"

static struct kmod_ctx *ctx = NULL;

/* the modules of the module_blacklist= options of the kernel command line, which the kernel refuses to
 * load with EPERM */
static char **cmdline_denylist = NULL;

static int parse_proc_cmdline_item(const char *key, const char *value) {
        if (proc_cmdline_key_streq(key, "module_blacklist")) {
                if (proc_cmdline_value_missing(key, value))
                        return 0;

                return strv_split_and_extend(&cmdline_denylist, value, ",", /* filter_duplicates= */ true);
        }

        return 0;
}

/* Like module_load_and_warn() of systemd, which the kmod builtin calls with verbose=false, so that
 * everything is logged at debug level. */
static int load_module(const char *module) {
        /* the name as given, which may come from a substitution, escaped like the values in the messages of
         * the rules */
        _cleanup_free_ char *escaped = log_escape(LOG_DEBUG, module);
        struct kmod_list *list = NULL;
        struct kmod_list *l;
        bool denylist_parsed = false;
        int r;

        log_debug("Loading module: %s", escaped ?: module);

        r = kmod_module_new_from_lookup(ctx, module, &list);
        if (r < 0)
                return log_debug_errno(r, "Failed to look up module alias '%s': %m", escaped ?: module);

        if (!list)
                return log_debug_errno(ENOENT, "Failed to find module '%s'", escaped ?: module);

        kmod_list_foreach(l, list) {
                struct kmod_module *mod = kmod_module_get_module(l);
                /* the name of the module, which may be the name as given, escaped like it */
                _cleanup_free_ char *escaped_name = log_escape(LOG_DEBUG, kmod_module_get_name(mod));
                const char *name = escaped_name ?: kmod_module_get_name(mod);
                int err;

                switch (kmod_module_get_initstate(mod)) {

                case KMOD_MODULE_BUILTIN:
                        log_debug("Module '%s' is built in", name);
                        break;

                case KMOD_MODULE_LIVE:
                        log_debug("Module '%s' is already loaded", name);
                        break;

                default:
                        err = kmod_module_probe_insert_module(mod, KMOD_PROBE_APPLY_BLACKLIST, NULL, NULL, NULL, NULL);
                        if (err == 0)
                                log_debug("Inserted module '%s'", name);
                        else if (err == KMOD_PROBE_APPLY_BLACKLIST)
                                log_debug("Module '%s' is deny-listed (by kmod)", name);
                        else {
                                if (err == -EPERM) {
                                        if (!denylist_parsed) {
                                                cmdline_denylist = strv_free(cmdline_denylist);
                                                r = parse_proc_cmdline(parse_proc_cmdline_item);
                                                if (r < 0)
                                                        log_debug_errno(r, "Failed to parse kernel command line, ignoring: %m");

                                                denylist_parsed = true;
                                        }
                                }

                                if (err == -EPERM && strv_contains(cmdline_denylist, kmod_module_get_name(mod)))
                                        log_debug("Module '%s' is deny-listed (by kernel)", name);
                                else {
                                        log_debug_errno(err, "Failed to insert module '%s': %m", name);
                                        if (!IN_SET(err, -ENODEV, -ENOENT))
                                                r = err;
                                }
                        }
                }

                kmod_module_unref(mod);
        }

        kmod_module_unref_list(list);
        cmdline_denylist = strv_free(cmdline_denylist);
        return r;
}

/* The messages of libkmod, which may contain e.g. the module alias given to "kmod load", escaped like the values
 * in the messages of the rules, without the line break they end with. */
_printf_(6,0) static void udev_kmod_log(void *data __attribute__((unused)), int priority, const char *file, int line, const char *fn, const char *format, va_list args) {
        _cleanup_free_ char *message = NULL, *escaped = NULL;
        size_t len;

        if (log_get_max_level() < LOG_PRI(priority))
                return;

        if (vasprintf(&message, format, args) < 0) {
                log_oom();
                return;
        }

        len = strlen(message);
        while (len > 0 && message[len - 1] == '\n')
                message[--len] = '\0';

        escaped = utf8_escape_non_printable(message);
        log_internal(priority, 0, file, line, fn, "%s", escaped ?: message);
}

static int builtin_kmod(struct udev_device *dev, int argc, char *argv[], enum udev_event_mode mode) {
        int i;

        if (mode != EVENT_UDEV_WORKER) {
                log_device_debug(dev, "Running in test mode, skipping execution of 'kmod' builtin command.");
                return EXIT_SUCCESS;
        }

        if (!ctx)
                return 0;

        /* Like systemd, the errors are returned as negative error codes, with the reason. */
        if (argc < 2 || !streq(argv[1], "load"))
                return log_device_warning_errno(dev, EINVAL, "%s: expected: load [module…]", argv[0]);

        if (!argv[2]) {
                const char *modalias;

                modalias = udev_device_get_property_value(dev, "MODALIAS");
                if (!modalias)
                        return log_device_warning_errno(dev, ENOENT, "Failed to read property \"MODALIAS\": %m");

                (void) load_module(modalias);
        } else
                for (i = 2; argv[i]; i++)
                        (void) load_module(argv[i]);

        return EXIT_SUCCESS;
}

/* called at udev startup and reload */
static int builtin_kmod_init(struct udev *udev) {
        if (ctx)
                return 0;

        ctx = kmod_new(NULL, NULL);
        if (!ctx)
                return log_error_errno(ENOMEM, "Failed to initialize libkmod context: %m");

        (void) kmod_load_resources(ctx);
        kmod_set_log_fn(ctx, udev_kmod_log, udev);
        log_debug("Loaded kernel module index.");
        return 0;
}

/* called on udev shutdown and reload request */
static void builtin_kmod_exit(struct udev *udev __attribute__((unused))) {
        if (!ctx)
                return;

        ctx = kmod_unref(ctx);
        log_debug("Unloaded kernel module index.");
}

/* called every couple of seconds during event activity; 'true' if config has changed */
static bool builtin_kmod_validate(struct udev *udev __attribute__((unused))) {
        if (!ctx)
                return false;

        if (kmod_validate_resources(ctx) != KMOD_RESOURCES_OK) {
                log_debug("Kernel module index needs reloading.");
                return true;
        }

        return false;
}

const struct udev_builtin udev_builtin_kmod = {
        .name = "kmod",
        .cmd = builtin_kmod,
        .init = builtin_kmod_init,
        .exit = builtin_kmod_exit,
        .validate = builtin_kmod_validate,
        .help = "Kernel module loader",
        .run_once = false,
};
