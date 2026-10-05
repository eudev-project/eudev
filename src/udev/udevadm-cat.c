/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "conf-files.h"
#include "pager.h"
#include "path-util.h"
#include "strv.h"
#include "udev.h"
#include "udevadm-util.h"

static char *arg_root = NULL;
static bool arg_tldr = false;
static bool arg_config = false;

static void help(void) {
        pager_open(0);

        printf("%s cat [OPTIONS] [FILE...]\n"
               "\n%sShow udev rules files.%s\n\n"
               "  -h --help            Show this help\n"
               "  -V --version         Show package version\n"
               "     --root=PATH       Operate on an alternate filesystem root\n"
               "     --tldr            Skip comments and empty lines\n"
               "     --config          Show udev.conf rather than udev rules files\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal());
        print_man_page_link();
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_ROOT = 0x100,
                ARG_TLDR,
                ARG_CONFIG,
        };
        static const struct option options[] = {
                { "help",          no_argument,       NULL, 'h'             },
                { "version",       no_argument,       NULL, 'V'             },
                { "root",          required_argument, NULL, ARG_ROOT        },
                { "tldr",          no_argument,       NULL, ARG_TLDR        },
                { "config",        no_argument,       NULL, ARG_CONFIG      },
                {}
        };

        int r, c;

        while ((c = getopt_long(argc, argv, "hV", options, NULL)) >= 0)
                switch (c) {
                case 'h':
                        help();
                        return 0;
                case 'V':
                        printf("%s\n", UDEV_VERSION);
                        return 0;
                case ARG_ROOT:
                        r = parse_root_argument(optarg, &arg_root);
                        if (r < 0)
                                return r;
                        break;
                case ARG_TLDR:
                        arg_tldr = true;
                        break;
                case ARG_CONFIG:
                        arg_config = true;
                        break;
                case '?':
                        return -EINVAL;
                default:
                        assert_not_reached("Unknown option");
                }

        if (arg_config && optind < argc) {
                log_error("Combination of --config and FILEs is not supported.");
                return -EINVAL;
        }

        return 1;
}

/* Like cat_file() of systemd's pretty-print.c, for files without sections. */
static int cat_file(const char *name, const char *path, bool *newline) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *line = NULL, *urlified = NULL;
        size_t size = 0;
        ssize_t n;
        int r;

        if (*newline)
                putc('\n', stdout);
        *newline = true;

        r = terminal_urlify_path(path, NULL, &urlified);
        if (r < 0)
                return log_error_errno(r, "Failed to urlify path \"%s\": %m", path);

        printf("%s# %s%s%s%s\n",
               ansi_highlight_blue(),
               path_equal(name, path) ? "" : name,
               path_equal(name, path) ? "" : " -> ",
               urlified,
               ansi_normal());

        f = fopen(path, "re");
        if (!f)
                return log_error_errno(errno, "Failed to open \"%s\": %m", path);

        while ((n = getline(&line, &size, f)) >= 0) {
                const char *l;
                bool escaped = false;
                char *e;

                if (n > 0 && line[n - 1] == '\n')
                        line[n - 1] = '\0';

                l = line + strspn(line, WHITESPACE);

                /* comment */
                if (*l != '\0' && strchr(COMMENTS, *l)) {
                        if (!arg_tldr)
                                printf("%s%s%s\n", ansi_highlight_grey(), line, ansi_normal());
                        continue;
                }

                /* empty line */
                if (arg_tldr && (isempty(l) || streq(l, "\\")))
                        continue;

                /* Check if the line ends with a backslash. */
                for (e = line; *e != '\0'; e++) {
                        if (escaped)
                                escaped = false;
                        else if (*e == '\\')
                                escaped = true;
                }

                /* Highlight the trailing backslash. */
                if (escaped) {
                        *(e - 1) = '\0';
                        printf("%s%s\\%s\n", line, ansi_highlight_red(), ansi_normal());
                } else
                        printf("%s\n", line);
        }

        if (ferror(f))
                return log_error_errno(EIO, "Failed to read \"%s\": %m", path);

        return 0;
}

/* Like conf_files_cat() of systemd for "udev/udev.conf": shows the main configuration file and the drop-ins, as
 * libudev reads them, see udev_conf_files(). Like systemd, a file that is not a regular file counts as not found.
 * Unlike systemd, which says that the main file is not found also when it is masked, i.e. an empty file or a
 * symlink to /dev/null, which hides the ones in the later directories, the mask is named. */
static int cat_config(bool *newline) {
        ConfFile *c = NULL, **dropins = NULL;
        _cleanup_free_ char *mask = NULL;
        size_t n_dropins = 0, i;
        int r, ret = 0;

        udev_conf_log_search_dirs(arg_root);

        r = udev_conf_files(arg_root, CONF_FILES_WARN, &c, &mask, &dropins, &n_dropins);
        if (r < 0)
                return log_error_errno(r, "Failed to query file list: %m");

        if (c)
                ret = cat_file(c->original_path, c->resolved_path, newline);
        else if (mask)
                printf("%s# Main configuration file udev/udev.conf is masked by %s%s\n",
                       ansi_highlight_magenta(),
                       mask,
                       ansi_normal());
        else
                printf("%s# Main configuration file udev/udev.conf not found%s\n",
                       ansi_highlight_magenta(),
                       ansi_normal());

        for (i = 0; i < n_dropins; i++) {
                r = cat_file(dropins[i]->original_path, dropins[i]->resolved_path, newline);
                if (r < 0 && ret == 0)
                        ret = r;
        }

        conf_file_free(c);
        conf_file_free_array(dropins, n_dropins);
        return ret;
}

static int adm_cat(struct udev *udev __attribute__((unused)), int argc, char *argv[]) {
        _cleanup_strv_free_ char **names = NULL, **paths = NULL;
        bool newline = false;
        size_t i;
        int r, ret = 0;

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        if (arg_config) {
                r = cat_config(&newline);
                goto finish;
        }

        r = search_rules_files(argv + optind, arg_root, &names, &paths);
        if (r < 0)
                goto finish;

        for (i = 0; names && names[i]; i++) {
                r = cat_file(names[i], paths[i], &newline);
                if (r < 0 && ret == 0)
                        ret = r;
        }
        r = ret;

finish:
        free(arg_root);
        arg_root = NULL;
        return r < 0 ? 1 : 0;
}

const struct udevadm_cmd udevadm_cat = {
        .name = "cat",
        .cmd = adm_cat,
        .help = "Show udev rules files",
};
