/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include "pager.h"
#include "strv.h"
#include "udev.h"
#include "udev-rules-check.h"
#include "udevadm-util.h"

static int arg_resolve_names = 1;
static char *arg_root = NULL;
static bool arg_summary = true;
static bool arg_style = true;

static void help(void) {
        pager_open(0);

        printf("%s verify [OPTIONS] [FILE...]\n"
               "\n%sVerify udev rules files.%s\n\n"
               "  -h --help                            Show this help\n"
               "  -V --version                         Show package version\n"
               "  -N --resolve-names=early|late|never  When to resolve names\n"
               "     --root=PATH                       Operate on an alternate filesystem root\n"
               "     --no-summary                      Do not show summary\n"
               "     --no-style                        Ignore style issues\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal());
        print_man_page_link();
}

/* Like systemd's parse_resolve_name_timing(): returns 1 if parsed, 0 for "help", and a
 * negative error otherwise. */
static int parse_resolve_names(const char *s, int *ret) {
        if (streq(s, "help")) {
                puts("never\n"
                     "late\n"
                     "early");
                return 0;
        }

        if (udev_parse_resolve_names(s, ret) < 0) {
                log_error("--resolve-names= must be 'early', 'late', or 'never'.");
                return -EINVAL;
        }

        return 1;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_ROOT = 0x100,
                ARG_NO_SUMMARY,
                ARG_NO_STYLE,
        };
        static const struct option options[] = {
                { "help",          no_argument,       NULL, 'h'             },
                { "version",       no_argument,       NULL, 'V'             },
                { "resolve-names", required_argument, NULL, 'N'             },
                { "root",          required_argument, NULL, ARG_ROOT        },
                { "no-summary",    no_argument,       NULL, ARG_NO_SUMMARY  },
                { "no-style",      no_argument,       NULL, ARG_NO_STYLE    },
                {}
        };

        int r, c;

        while ((c = getopt_long(argc, argv, "hVN:", options, NULL)) >= 0)
                switch (c) {
                case 'h':
                        help();
                        return 0;
                case 'V':
                        printf("%s\n", UDEV_VERSION);
                        return 0;
                case 'N':
                        r = parse_resolve_names(optarg, &arg_resolve_names);
                        if (r <= 0)
                                return r;
                        break;
                case ARG_ROOT:
                        r = parse_root_argument(optarg, &arg_root);
                        if (r < 0)
                                return r;
                        break;
                case ARG_NO_SUMMARY:
                        arg_summary = false;
                        break;
                case ARG_NO_STYLE:
                        arg_style = false;
                        break;
                case '?':
                        return -EINVAL;
                default:
                        assert_not_reached("Unknown option");
                }

        return 1;
}

static int verify_rules_file(struct udev *udev, struct udev_rules_check *check, const char *name, const char *path) {
        unsigned issues, mask;
        int r;

        r = udev_rules_check_file(udev, check, name, path);
        if (r < 0)
                return log_error_errno(r, "Failed to parse rules file %s: %m", name);

        issues = udev_rules_check_get_issues(check);
        mask = (1U << LOG_ERR) | (1U << LOG_WARNING);
        if (issues & mask) {
                log_error("%s: udev rules check failed.", name);
                return -EINVAL;
        }

        if (arg_style && (issues & (1U << LOG_NOTICE))) {
                log_warning("%s: udev rules have style issues.", name);
                return -EINVAL;
        }

        return 0;
}

static int verify_rules(struct udev *udev, struct udev_rules_check *check, char **names, char **paths) {
        size_t fail_count = 0, success_count = 0, i;
        int r, ret = 0;

        for (i = 0; names && names[i]; i++) {
                r = verify_rules_file(udev, check, names[i], paths[i]);
                if (r < 0) {
                        ++fail_count;
                        if (ret == 0)
                                ret = r;
                } else
                        ++success_count;
        }

        if (arg_summary)
                printf("\n%s%zu udev rules files have been checked.%s\n"
                       "  Success: %zu\n"
                       "%s  Fail:    %zu%s\n",
                       ansi_highlight(),
                       fail_count + success_count,
                       ansi_normal(),
                       success_count,
                       fail_count > 0 ? ansi_highlight_red() : "",
                       fail_count,
                       fail_count > 0 ? ansi_normal() : "");

        return ret;
}

static int adm_verify(struct udev *udev, int argc, char *argv[]) {
        _cleanup_strv_free_ char **names = NULL, **paths = NULL;
        struct udev_rules_check *check;
        int r;

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        r = search_rules_files(argv + optind, arg_root, &names, &paths);
        if (r < 0)
                goto finish;

        check = udev_rules_check_new(arg_resolve_names);
        if (!check) {
                r = log_oom();
                goto finish;
        }

        r = verify_rules(udev, check, names, paths);
        udev_rules_check_free(check);

finish:
        free(arg_root);
        arg_root = NULL;
        return r < 0 ? 1 : 0;
}

const struct udevadm_cmd udevadm_verify = {
        .name = "verify",
        .cmd = adm_verify,
        .help = "Verify udev rules files",
};
