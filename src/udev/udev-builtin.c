/***
  This file is part of systemd.

  Copyright 2007-2012 Kay Sievers <kay@vrfy.org>

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include "udev.h"

static bool initialized;

static const struct udev_builtin *builtins[] = {
#ifdef HAVE_BLKID
        [UDEV_BUILTIN_BLKID] = &udev_builtin_blkid,
#endif
        [UDEV_BUILTIN_BTRFS] = &udev_builtin_btrfs,
        [UDEV_BUILTIN_FACTORY_RESET] = &udev_builtin_factory_reset,
        [UDEV_BUILTIN_HWDB] = &udev_builtin_hwdb,
        [UDEV_BUILTIN_INPUT_ID] = &udev_builtin_input_id,
        [UDEV_BUILTIN_KEYBOARD] = &udev_builtin_keyboard,
#ifdef HAVE_KMOD
        [UDEV_BUILTIN_KMOD] = &udev_builtin_kmod,
#endif
        [UDEV_BUILTIN_NET_DRIVER] = &udev_builtin_net_driver,
        [UDEV_BUILTIN_NET_ID] = &udev_builtin_net_id,
        [UDEV_BUILTIN_PATH_ID] = &udev_builtin_path_id,
        [UDEV_BUILTIN_TPM2_ID] = &udev_builtin_tpm2_id,
        [UDEV_BUILTIN_USB_ID] = &udev_builtin_usb_id,
};

void udev_builtin_init(struct udev *udev) {
        unsigned int i;

        if (initialized)
                return;

        for (i = 0; i < ELEMENTSOF(builtins); i++)
                if (builtins[i]->init)
                        builtins[i]->init(udev);

        initialized = true;
}

void udev_builtin_exit(struct udev *udev) {
        unsigned int i;

        if (!initialized)
                return;

        for (i = 0; i < ELEMENTSOF(builtins); i++)
                if (builtins[i]->exit)
                        builtins[i]->exit(udev);

        initialized = false;
}

bool udev_builtin_validate(struct udev *udev) {
        unsigned int i;

        for (i = 0; i < ELEMENTSOF(builtins); i++)
                if (builtins[i]->validate && builtins[i]->validate(udev))
                        return true;
        return false;
}

void udev_builtin_list(struct udev *udev __attribute__((unused))) {
        unsigned int i;

        for (i = 0; i < ELEMENTSOF(builtins); i++)
                fprintf(stderr, "  %-14s  %s\n", builtins[i]->name, builtins[i]->help);
}

const char *udev_builtin_name(enum udev_builtin_cmd cmd) {
        return builtins[cmd]->name;
}

bool udev_builtin_run_once(enum udev_builtin_cmd cmd) {
        return builtins[cmd]->run_once;
}

enum udev_builtin_cmd udev_builtin_lookup(const char *command) {
        enum udev_builtin_cmd i;
        size_t n;

        assert(command);

        command += strspn(command, WHITESPACE);
        n = strcspn(command, WHITESPACE);
        for (i = 0; i < ELEMENTSOF(builtins); i++)
                if (strlen(builtins[i]->name) == n &&
                    strneq(builtins[i]->name, command, n))
                        return i;
        return UDEV_BUILTIN_MAX;
}

/* Splits cmd in place into words, like systemd's strv_split_full() with
 * EXTRACT_UNQUOTE|EXTRACT_RELAX|EXTRACT_RETAIN_ESCAPE: words are separated by any whitespace; single and
 * double quotes, also in the middle of a word, group characters including whitespace and are removed;
 * a missing closing quote is accepted; backslashes have no special meaning. A word is never longer than
 * its source, hence the words can be written over cmd. */
static void split_command(char *cmd, int *ret_argc, char *argv[]) {
        char *r = cmd, *w = cmd;
        int argc = 0;

        for (;;) {
                char quote = 0;
                bool end;

                r += strspn(r, WHITESPACE);
                if (*r == '\0')
                        break;

                /* callers provide an array of UDEV_ARGV_MAX entries, leave room for the terminating NULL */
                if (argc >= UDEV_ARGV_MAX - 1) {
                        log_error("too many arguments in command, ignoring the rest: '%s'", r);
                        break;
                }

                argv[argc++] = w;
                for (; *r != '\0'; r++) {
                        if (quote != 0) {
                                if (*r == quote)
                                        quote = 0;
                                else
                                        *w++ = *r;
                        } else if (IN_SET(*r, '\'', '"'))
                                quote = *r;
                        else if (strchr(WHITESPACE, *r))
                                break;
                        else
                                *w++ = *r;
                }

                /* Skip the separator before terminating the word, which may overwrite it. */
                end = *r == '\0';
                if (!end)
                        r++;
                *w++ = '\0';
                if (end)
                        break;
        }

        argv[argc] = NULL;
        *ret_argc = argc;
}

int udev_builtin_run(struct udev_device *dev, enum udev_builtin_cmd cmd, const char *command, enum udev_event_mode mode) {
        char arg[UTIL_PATH_SIZE];
        int argc;
        char *argv[UDEV_ARGV_MAX];

        /* we need '0' here to reset the internal state */
        optind = 0;
        strscpy(arg, sizeof(arg), command);
        split_command(arg, &argc, argv);
        return builtins[cmd]->cmd(dev, argc, argv, mode);
}

int udev_builtin_add_property(struct udev_device *dev, enum udev_event_mode mode, const char *key, const char *val) {
        int r;

        assert(key);

        if (isempty(val))
                val = NULL;

        r = udev_device_add_property(dev, key, val);
        if (r < 0)
                return log_debug_errno(r, "%s: Failed to %s property '%s%s%s': %m",
                                       udev_device_get_sysname(dev), val ? "add" : "remove",
                                       key, val ? "=" : "", val ?: "");

        if (mode == EVENT_UDEVADM_TEST_BUILTIN) {
                if (val)
                        printf("%s=%s\n", key, val);
                else
                        printf("%s (removed)\n", key);
        }

        return 0;
}
