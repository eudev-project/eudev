/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

struct option;

/* getopt_long() with the messages of systemd's option parser instead of the ones of the C library,
 * e.g. "udevadm: unrecognized option '-Z'", "udevadm: option '--name' requires an argument" or
 * "udevadm: option '--exp' is ambiguous; possibilities: --export, --export-prefix, --export-db",
 * logged at error level with the name of the program. Like that parser, an abbreviated long option
 * is ambiguous whenever the names of several long options begin with it, also if they are aliases.
 * Returns '?' after logging an invalid option. */
int getopt_long_log(int argc, char * const argv[], const char *optstring, const struct option *longopts);

/* Prints the help of a program in the layout of systemd's command_print_help(): the command line
 * "> ata_id [OPTION…] DEVICE" ("[OPTION…]" alone if argspec is NULL), the abstract, and the table of
 * options under "Options:", one line per option, ending in a newline, with systemd's colors if they are
 * enabled. Returns 0. */
int help_print(const char *argspec, const char *abstract, const char *options);
