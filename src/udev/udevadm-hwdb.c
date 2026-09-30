/***
  This file is part of systemd.

  Copyright 2012 Kay Sievers <kay@vrfy.org>

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

#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <ctype.h>

#include "pager.h"
#include "util.h"

#include "udev.h"
#include "udevadm-util.h"
#include "hwdb-util.h"

static void help(void) {
        pager_open(0);

        printf("Usage: udevadm hwdb OPTIONS\n"
               "  -u,--update          update the hardware database\n"
               "  -s,--strict          when updating, return non-zero exit value on any parsing error\n"
               "  -o,--output=.../hwdb.bin generate in .../hwdb.bin instead of /etc/udev/hwdb.bin\n"
               "  --usr                generate in " UDEV_LIBEXEC_DIR " instead of /etc/udev\n"
               "  -t,--test=MODALIAS   query database and print result\n"
               "  -r,--root=PATH       alternative root path in the filesystem\n"
               "  -h,--help\n"
               "\n"
               "The HWDB is searched in "
               UDEV_HWDB_DIR ", " UDEV_LIBEXEC_DIR "/hwdb.d, "
               "and the UDEV_HWDB_PATH search path.\n"
               "The format of hwdb.bin is configured with hwdb_format= in udev.conf.\n");
        print_man_page_link();
}

static int adm_hwdb(struct udev *udev, int argc, char *argv[]) {
        enum {
                ARG_USR = 0x100,
        };

        static const struct option options[] = {
                { "update", no_argument,       NULL, 'u' },
                { "strict", no_argument,       NULL, 's' },
                { "usr",    no_argument,       NULL, ARG_USR },
                { "output", required_argument, NULL, 'o' },
                { "test",   required_argument, NULL, 't' },
                { "root",   required_argument, NULL, 'r' },
                { "help",   no_argument,       NULL, 'h' },
                {}
        };
        const char *test = NULL;
        const char *root = "";
        bool update = false;
        bool strict = false;
        int c;
        int rc = EXIT_SUCCESS;

        _cleanup_free_ char *hwdb_bin = strdup("/etc/udev/hwdb.bin");
        if (hwdb_bin == NULL) {
                rc = EXIT_FAILURE;
                goto out;
        }

        while ((c = getopt_long(argc, argv, "uso:t:r:h", options, NULL)) >= 0)
                switch(c) {
                case 'u':
                        update = true;
                        break;
                case 's':
                        strict = true;
                        break;
                case ARG_USR:
                        free(hwdb_bin);
                        hwdb_bin = strdup(UDEV_LIBEXEC_DIR "/hwdb.bin");
                        if (hwdb_bin == NULL) {
                                rc = EXIT_FAILURE;
                                goto out;
                        }
                        break;
                case 'o':
                        free(hwdb_bin);
                        hwdb_bin = strdup(optarg);
                        if (hwdb_bin == NULL) {
                                rc = EXIT_FAILURE;
                                goto out;
                        }
                        break;
                case 't':
                        test = optarg;
                        break;
                case 'r':
                        root = optarg;
                        break;
                case 'h':
                        help();
                        return EXIT_SUCCESS;
                case '?':
                        return EXIT_FAILURE;
                default:
                        assert_not_reached("Unknown option");
                }

        if (!update && !test) {
                log_error("Either --update or --test must be used");
                return EXIT_FAILURE;
        }

        if (update) {
                if (!hwdb_bin) {
                        rc = EXIT_FAILURE;
                        goto out;
                }

                /* udevadm loads the SELinux database only for /dev, load all of it to label
                 * hwdb.bin, like systemd-hwdb. */
                mac_selinux_finish();
                if (mac_selinux_init(NULL) < 0) {
                        rc = EXIT_FAILURE;
                        goto out;
                }

                if (hwdb_update(udev, root, hwdb_bin, strict) < 0)
                        rc = EXIT_FAILURE;
        }

        if (test && hwdb_query(udev, test, root) < 0)
                rc = EXIT_FAILURE;
out:
        return rc;
}

const struct udevadm_cmd udevadm_hwdb = {
        .name = "hwdb",
        .cmd = adm_hwdb,
        .help = "maintain the hardware database index",
};
