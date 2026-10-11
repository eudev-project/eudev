/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <limits.h>
#include <string.h>

#include "log.h"
#include "options.h"
#include "terminal-util.h"
#include "utf8.h"
#include "util.h"

/* The first len characters of an argument for the messages about it, escaped like the values in the
 * messages of the rules of udev, see utf8_escape_non_printable(), as it may be e.g. an argument of a builtin
 * that was substituted into its command. NULL without memory. */
static char *option_escape(const char *arg, size_t len) {
        _cleanup_free_ char *s = strndup(arg, len);

        return s ? utf8_escape_non_printable(s) : NULL;
}

/* Like the option parser of systemd: the index of the long option named by the len characters of name,
 * of the one with this name, or of the only one whose name begins with them, -1 if there is none, or
 * if name is empty, and -2 if the names of several begin with them. */
static int find_long_option(const struct option *longopts, const char *name, size_t len) {
        int i, found = -1;
        unsigned n = 0;

        if (len == 0)
                return -1;

        for (i = 0; longopts[i].name; i++) {
                if (!strneq(longopts[i].name, name, len))
                        continue;

                if (longopts[i].name[len] == '\0')
                        return i;

                found = i;
                n++;
        }

        return n > 1 ? -2 : found;
}

/* "udevadm: option '--na' is ambiguous; possibilities: --name, --name-match", the long options in the
 * order of longopts, like systemd. arg is the argument as given, len the length of the name in it. */
static void log_ambiguous_option(const struct option *longopts, const char *arg, size_t len) {
        _cleanup_free_ char *list = NULL, *escaped = NULL;
        size_t n = 0;
        char *p;
        int i;

        for (i = 0; longopts[i].name; i++)
                if (strneq(longopts[i].name, arg + 2, len))
                        n += strlen(", --") + strlen(longopts[i].name);

        list = new(char, n + 1);
        if (!list) {
                log_oom();
                return;
        }

        p = list;
        for (i = 0; longopts[i].name; i++)
                if (strneq(longopts[i].name, arg + 2, len))
                        p = stpcpy(stpcpy(p, p == list ? "--" : ", --"), longopts[i].name);
        *p = '\0';

        escaped = option_escape(arg, len + 2);
        log_error("%s: option '%s' is ambiguous; possibilities: %s",
                  program_invocation_short_name, escaped ?: arg, list);
}

int getopt_long_log(int argc, char * const argv[], const char *optstring, const struct option *longopts) {
        const char *arg, *p;
        size_t len;
        int c, i = -1, j;

        assert(argv);
        assert(optstring);
        assert(longopts);

        /* the messages about invalid options are logged below */
        opterr = 0;

        c = getopt_long(argc, argv, optstring, longopts, &i);
        if (c < 0)
                return c;

        if (c != '?') {
                /* a short option */
                if (i < 0)
                        return c;

                /* A long option: getopt_long() moved past it, and past its argument if that is a separate
                 * one. Like systemd, an abbreviation is ambiguous if the names of several long options
                 * begin with it, also if they are aliases, which getopt_long() of glibc accepts. */
                arg = argv[optind - (optarg && optarg == argv[optind - 1] ? 2 : 1)];
                if (!startswith(arg, "--"))
                        return c;

                len = strcspn(arg + 2, "=");
                if (longopts[i].name[len] != '\0' && find_long_option(longopts, arg + 2, len) == -2) {
                        log_ambiguous_option(longopts, arg, len);
                        return '?';
                }

                return c;
        }

        /* An invalid option. getopt_long() moved past a long option, and sets optopt to 0 if it is unknown or
         * ambiguous, and to its value if its argument is missing or not allowed. For a short option, optopt is
         * its character; the argument before is not that option if more characters follow it, and musl moves
         * optind past the end if the argument of the last one is missing. The value of a long option that
         * is a character is always one of a short option too, so it is not the character of an unknown one. */
        arg = optind <= argc ? argv[optind - 1] : NULL;
        if (arg && startswith(arg, "--")) {
                bool long_option = optopt == 0;

                len = strcspn(arg + 2, "=");
                j = find_long_option(longopts, arg + 2, len);

                /* the value of the option, or of one of the options the name is an abbreviation of */
                for (i = 0; !long_option && longopts[i].name; i++)
                        if (strneq(longopts[i].name, arg + 2, len) && longopts[i].val == optopt)
                                long_option = true;

                if (long_option) {
                        _cleanup_free_ char *escaped = NULL;

                        /* the texts of systemd, with the name as given, without the argument */
                        if (j == -2)
                                log_ambiguous_option(longopts, arg, len);
                        else if (j < 0) {
                                escaped = option_escape(arg, len + 2);
                                log_error("%s: unrecognized option '%s'",
                                          program_invocation_short_name, escaped ?: arg);
                        } else if (arg[2 + len] == '=') {
                                escaped = option_escape(arg, len + 2);
                                log_error("%s: option '%s' doesn't allow an argument",
                                          program_invocation_short_name, escaped ?: arg);
                        } else {
                                escaped = option_escape(arg, strlen(arg));
                                log_error("%s: option '%s' requires an argument",
                                          program_invocation_short_name, escaped ?: arg);
                        }
                        return '?';
                }
        }

        /* a short option: unknown, or its argument is missing; the character escaped, see option_escape() */
        p = optstring + (optstring[0] == '+' || optstring[0] == '-');
        p = optopt > 0 && optopt <= UCHAR_MAX && optopt != ':' ? strchr(p, optopt) : NULL;
        {
                char c_str[2] = { (char) optopt, '\0' };
                _cleanup_free_ char *escaped = option_escape(c_str, 1);

                if (p && p[1] == ':')
                        log_error("%s: option '-%s' requires an argument", program_invocation_short_name, escaped ?: c_str);
                else
                        log_error("%s: unrecognized option '-%s'", program_invocation_short_name, escaped ?: c_str);
        }

        return '?';
}

int help_print(const char *argspec, const char *abstract, const char *options) {
        assert(abstract);
        assert(options);

        printf("%s>%s %s [OPTION…]%s%s\n"
               "\n"
               "%s%s%s%s\n"
               "\n"
               "%sOptions:%s\n"
               "%s",
               ansi_grey(), ansi_normal(), program_invocation_short_name, argspec ? " " : "", argspec ?: "",
               ansi_highlight(), ansi_add_italics(), abstract, ansi_normal(),
               ansi_underline(), ansi_normal(),
               options);

        return 0;
}
