/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

/*
 * Checks of udev rules files for 'udevadm verify'.
 *
 * udev-rules.c parses a rules file with udev_rules_check_file(). The levels of all
 * messages about the file are collected, and the rules are checked for the issues that
 * systemd's rules parser reports but eudev's does not: operators that are taken as another
 * one, invalid substitutions, empty values, conflicting and duplicate expressions, lines
 * without effect, unused labels, and the style of the delimiters between the keys. Invalid
 * keys, attributes, operators and modes of TEST are reported by the parser.
 */

#include <stdbool.h>

struct udev;

typedef enum UdevRulesCheckOp {
        CHECK_OP_MATCH,
        CHECK_OP_NOMATCH,
        CHECK_OP_ADD,
        CHECK_OP_REMOVE,
        CHECK_OP_ASSIGN,
        CHECK_OP_ASSIGN_FINAL,
} UdevRulesCheckOp;

struct udev_rules_check;

/* resolve_names is the same as for udev_rules_new(): 1 early, 0 late, -1 never. */
struct udev_rules_check *udev_rules_check_new(int resolve_names);
struct udev_rules_check *udev_rules_check_free(struct udev_rules_check *c);

/* Parses the file and checks its rules. Returns a negative error if the file cannot be read. */
int udev_rules_check_file(struct udev *udev, struct udev_rules_check *c, const char *filename);

/* The levels of the messages about the last checked file, as a mask of (1 << level). */
unsigned udev_rules_check_get_issues(struct udev_rules_check *c);

/* The directories of the rules files, in the order of precedence. */
const char* const* udev_rules_get_dirs(void);

/* In udev-rules.c: whether a single value of OPTIONS= is one that the parser knows. */
bool udev_rules_option_is_known(const char *value);

/* In udev-rules.c: parses a single rules file, calling the functions below while doing so. */
int udev_rules_parse_file_for_check(struct udev *udev, int resolve_names, const char *filename,
                                    struct udev_rules_check *c);

/* Called by udev-rules.c while it parses a file for udev_rules_check_file(). */
void udev_rules_check_note_level(struct udev_rules_check *c, int level);
void udev_rules_check_file_begin(struct udev_rules_check *c, const char *filename);
void udev_rules_check_line_begin(struct udev_rules_check *c, unsigned line_nr, const char *line);
void udev_rules_check_delimiters(struct udev_rules_check *c, const char *pos);
void udev_rules_check_token(struct udev_rules_check *c, const char *key, const char *attr, UdevRulesCheckOp op,
                            const char *value, bool is_case_insensitive);
void udev_rules_check_line_end(struct udev_rules_check *c, bool valid);
void udev_rules_check_goto_unresolved(struct udev_rules_check *c, unsigned line_nr);
void udev_rules_check_file_end(struct udev_rules_check *c);
