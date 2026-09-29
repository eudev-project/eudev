/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * systemd-hwdb: the hardware database tool of systemd, for the scripts and packages that call
 * it. It shares the code with 'udevadm hwdb', and like that, it writes hwdb.bin in the format
 * configured with hwdb_format= in udev.conf.
 */

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include "hwdb-util.h"
#include "udev.h"
#include "udevadm-util.h"

static const char *arg_hwdb_bin_dir = NULL;
static char *arg_root = NULL;
static bool arg_strict = false;

static void help(void) {
        _cleanup_free_ char *link = NULL;

        if (terminal_urlify_man("systemd-hwdb", "8", &link) < 0)
                link = NULL;


        printf("%s [OPTIONS...] COMMAND ...\n\n"
               "%sUpdate or query the hardware database.%s\n"
               "\nCommands:\n"
               "  update          Update the hwdb database\n"
               "  query MODALIAS  Query database and print result\n"
               "\nOptions:\n"
               "  -h --help       Show this help\n"
               "     --version    Show package version\n"
               "  -s --strict     When updating, return non-zero exit value on any parsing error\n"
               "     --usr        Generate in " UDEV_LIBEXEC_DIR " instead of /etc/udev\n"
               "  -r --root=PATH  Alternative root path in the filesystem\n"
               "\nSee the %s man page for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link ?: "systemd-hwdb(8)");
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_USR,
        };

        static const struct option options[] = {
                { "help",     no_argument,       NULL, 'h'         },
                { "version",  no_argument,       NULL, ARG_VERSION },
                { "usr",      no_argument,       NULL, ARG_USR     },
                { "strict",   no_argument,       NULL, 's'         },
                { "root",     required_argument, NULL, 'r'         },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "sr:h", options, NULL)) >= 0)
                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        printf("%s\n", UDEV_VERSION);
                        return 0;

                case ARG_USR:
                        arg_hwdb_bin_dir = UDEV_LIBEXEC_DIR;
                        break;

                case 's':
                        arg_strict = true;
                        break;

                case 'r':
                        /* like systemd, the root directory is made absolute, and "/" is no root */
                        r = parse_root_argument(optarg, &arg_root);
                        if (r < 0)
                                return r;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unknown option");
                }

        return 1;
}

/* Like hwdb_bypass() of systemd. */
static bool hwdb_bypass(void) {
        const char *e;
        int r;

        e = getenv("SYSTEMD_HWDB_UPDATE_BYPASS");
        if (!e)
                return false;

        r = parse_boolean(e);
        if (r < 0)
                log_debug_errno(r, "Failed to parse $SYSTEMD_HWDB_UPDATE_BYPASS, assuming no: %m");
        if (r <= 0)
                return false;

        log_debug("$SYSTEMD_HWDB_UPDATE_BYPASS is enabled, skipping execution.");
        return true;
}

static int verb_update(struct udev *udev) {
        _cleanup_free_ char *hwdb_bin = NULL;

        if (hwdb_bypass())
                return 0;

        hwdb_bin = strjoin(arg_hwdb_bin_dir ?: "/etc/udev", "/hwdb.bin", NULL);
        if (!hwdb_bin)
                return log_oom();

        return hwdb_update(udev, arg_root, hwdb_bin, arg_strict);
}

/* Like the dispatch_verb() of systemd for the verbs "update" and "query MODALIAS". */
static int dispatch_verb(struct udev *udev, int argc, char *argv[]) {
        char **args = argv + optind;
        int left = argc - optind;

        if (left <= 0) {
                log_error("Command verb required (one of update, query).");
                return -EINVAL;
        }

        if (streq(args[0], "update")) {
                if (left > 1) {
                        log_error("Too many arguments.");
                        return -EINVAL;
                }

                return verb_update(udev);
        }

        if (streq(args[0], "query")) {
                if (left < 2) {
                        log_error("Too few arguments.");
                        return -EINVAL;
                }
                if (left > 2) {
                        log_error("Too many arguments.");
                        return -EINVAL;
                }

                return hwdb_query(udev, args[1], arg_root);
        }

        log_error("Unknown command verb '%s'.", args[0]);
        return -EINVAL;
}

int main(int argc, char *argv[]) {
        struct udev *udev;
        int r;

        log_open();

        udev = udev_new();
        if (!udev) {
                r = log_oom();
                goto finish;
        }

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        /* The full SELinux database, to label hwdb.bin, which fails in enforcing mode, like
         * systemd's mac_init(). */
        r = mac_selinux_init(NULL);
        if (r < 0)
                goto finish;

        r = dispatch_verb(udev, argc, argv);

finish:
        mac_selinux_finish();
        free(arg_root);
        udev_unref(udev);
        log_close();
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
