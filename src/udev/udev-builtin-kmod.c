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

#ifdef HAVE_LIBKMOD
#include <libkmod.h>
#endif

#include "udev.h"

static struct kmod_ctx *ctx;

static int load_module(struct udev *udev, const char *alias)
{
        int err;
#ifdef HAVE_LIBKMOD
        struct kmod_list *list = NULL;
        struct kmod_list *l;

        err = kmod_module_new_from_lookup(ctx, alias, &list);
        if (err < 0)
                return err;

        if (list == NULL)
                log_debug("no module matches '%s'", alias);

        kmod_list_foreach(l, list) {
                struct kmod_module *mod = kmod_module_get_module(l);

                err = kmod_module_probe_insert_module(mod, KMOD_PROBE_APPLY_BLACKLIST, NULL, NULL, NULL, NULL);
                if (err == KMOD_PROBE_APPLY_BLACKLIST)
                        log_debug("module '%s' is blacklisted", kmod_module_get_name(mod));
                else if (err == 0)
                        log_debug("inserted '%s'", kmod_module_get_name(mod));
                else
                        log_debug("failed to insert '%s'", kmod_module_get_name(mod));

                kmod_module_unref(mod);
        }

        kmod_module_unref_list(list);
#else

        /* 
           These 3 temporaries are needed because argv (below) is a const pointer, not pointer to const
        */
        char *tmp_alias = strdup(alias);
        char *tmp_modprobe = strdup(MODPROBE);
        char *tmp_bq = strdup("-bq");
        char *const argv[] = { tmp_modprobe, tmp_bq, tmp_alias, 0 };

        err = execute_command(MODPROBE, argv);

        free(tmp_alias);
        free(tmp_modprobe);
        free(tmp_bq);
#endif
        /*  both 'kmod_module_new_from_lookup' and 'execute_command' return <0 on error
		    so it is ok to assign both to 'err' */
        return err;
}

_printf_(6,0)
static void udev_kmod_log(void *data, int priority, const char *file, int line,
                          const char *fn, const char *format, va_list args)
{
        udev_main_log(data, priority, file, line, fn, format, args);
}

static int builtin_kmod(struct udev_device *dev, int argc, char *argv[], bool test)
{
        struct udev *udev = udev_device_get_udev(dev);
        int i;

#ifdef HAVE_LIBKMOD
        if (!ctx)
                return 0;
#endif

        if (argc < 3 || !streq(argv[1], "load")) {
                log_error("expect: %s load <module>", argv[0]);
                return EXIT_FAILURE;
        }

        for (i = 2; argv[i]; i++) {
                log_debug("execute '%s' '%s'", argv[1], argv[i]);
                load_module(udev, argv[i]);
        }

        return EXIT_SUCCESS;
}

/* called at udev startup and reload */
static int builtin_kmod_init(struct udev *udev)
{
#ifdef HAVE_LIBKMOD
        if (ctx)
                return 0;

        ctx = kmod_new(NULL, NULL);
        if (!ctx)
                return -ENOMEM;

        log_debug("load module index");
        kmod_set_log_fn(ctx, udev_kmod_log, udev);
        kmod_load_resources(ctx);
#endif
        return 0;
}

/* called on udev shutdown and reload request */
static void builtin_kmod_exit(struct udev *udev)
{
#ifdef HAVE_LIBKMOD
        log_debug("unload module index");
        ctx = kmod_unref(ctx);
#endif
}

#ifdef HAVE_LIBKMOD
/* called every couple of seconds during event activity; 'true' if config has changed */
static bool builtin_kmod_validate(struct udev *udev)
{
        log_debug("validate module index");
        if (!ctx)
                return false;
        return (kmod_validate_resources(ctx) != KMOD_RESOURCES_OK);
}
#endif

const struct udev_builtin udev_builtin_kmod = {
        .name = "kmod",
        .cmd = builtin_kmod,
        .init = builtin_kmod_init,
        .exit = builtin_kmod_exit,
#ifdef HAVE_LIBKMOD
        .validate = builtin_kmod_validate,
#endif
        .help = "kernel module loader",
        .run_once = false,
};
