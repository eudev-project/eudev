/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Checks of udev rules files for 'udevadm verify', see udev-rules-check.h.
 *
 * The checks and their messages follow systemd's src/udev/udev-rules.c (parse_token(),
 * check_token_delimiters(), check_tokens_order(), rule_resolve_goto() and
 * udev_check_rule_line()) and src/udev/udev-format.c (udev_check_format()), for the rules
 * as eudev's parser accepts them. Issues that eudev's parser already reports as errors are
 * not reported again.
 */

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "def.h"
#include "strv.h"
#include "udev.h"
#include "udev-rules-check.h"
#include "util.h"

typedef enum MatchType {
        MATCH_TYPE_EMPTY,               /* empty string */
        MATCH_TYPE_PLAIN,               /* no special characters */
        MATCH_TYPE_PLAIN_WITH_EMPTY,    /* no special characters with empty string, e.g., "|foo" */
        MATCH_TYPE_GLOB,                /* shell globs ?,*,[] */
        MATCH_TYPE_GLOB_WITH_EMPTY,     /* shell globs ?,*,[] with empty string, e.g., "|foo*" */
        MATCH_TYPE_SUBSYSTEM,           /* "subsystem", "bus", or "class" */

        MATCH_REMOVE_TRAILING_WHITESPACE = 1 << 4,
        MATCH_CASE_INSENSITIVE           = 1 << 5,

        MATCH_TYPE_INVALID = -1,        /* not a match */
} MatchType;

typedef enum SubstType {
        SUBST_TYPE_PLAIN,
        SUBST_TYPE_FORMAT,
        SUBST_TYPE_SUBSYS,
        SUBST_TYPE_INVALID = -1,        /* not an attribute match */
} SubstType;

typedef struct CheckToken {
        char *type;             /* the key, and for IMPORT and RUN also the type, e.g. "IMPORT{db}" */
        bool is_match;
        UdevRulesCheckOp op;
        MatchType match_type;
        SubstType attr_subst_type;
        char *data;             /* the attribute of ENV, ATTR, ATTRS, SYSCTL and SECLABEL, the mode of TEST */
        char *value;
        char **values;          /* the alternatives of the value of matches that take them, "a|b" */
} CheckToken;

typedef struct CheckLine {
        unsigned line_nr;
        char *label;
        char *goto_label;
        bool referenced;        /* the label is the target of a GOTO */
        bool has_other;         /* the line does something else than GOTO and LABEL */
        bool dropped;           /* the GOTO has no label, and the line has no effect any more */
        bool names_ignored;     /* OWNER or GROUP names were ignored with --resolve-names=never */
        CheckToken *tokens;
        size_t n_tokens;
} CheckLine;

struct udev_rules_check {
        int resolve_names;
        unsigned issues;
        char *filename;

        /* the line being parsed */
        unsigned line_nr;
        const char *line;
        bool line_failed;       /* a token of the line is invalid, like systemd, drop the rest */
        bool has_result;
        bool order_checked;
        CheckLine current;
        size_t n_tokens_allocated;
        /* the state of the line before the last key, see udev_rules_check_key_dropped() */
        size_t key_first_token;
        bool key_had_other;

        /* the lines of the file that are kept */
        CheckLine *lines;
        size_t n_lines, n_lines_allocated;
};

static void check_token_done(CheckToken *t) {
        free(t->type);
        free(t->data);
        free(t->value);
        strv_free(t->values);
}

static void check_line_done(CheckLine *l) {
        size_t i;

        free(l->label);
        free(l->goto_label);
        for (i = 0; i < l->n_tokens; i++)
                check_token_done(&l->tokens[i]);
        free(l->tokens);
        memzero(l, sizeof(CheckLine));
}

static void check_lines_clear(struct udev_rules_check *c) {
        size_t i;

        for (i = 0; i < c->n_lines; i++)
                check_line_done(&c->lines[i]);
        c->n_lines = 0;
        check_line_done(&c->current);
        c->n_tokens_allocated = 0;
}

struct udev_rules_check *udev_rules_check_new(int resolve_names) {
        struct udev_rules_check *c;

        c = new0(struct udev_rules_check, 1);
        if (!c)
                return NULL;

        c->resolve_names = resolve_names;
        return c;
}

struct udev_rules_check *udev_rules_check_free(struct udev_rules_check *c) {
        if (!c)
                return NULL;

        check_lines_clear(c);
        free(c->lines);
        free(c->filename);
        free(c);
        return NULL;
}

int udev_rules_check_file(struct udev *udev, struct udev_rules_check *c, const char *filename) {
        assert(c);
        assert(filename);

        return udev_rules_parse_file_for_check(udev, c->resolve_names, filename, c);
}

unsigned udev_rules_check_get_issues(struct udev_rules_check *c) {
        assert(c);

        return c->issues;
}

void udev_rules_check_note_level(struct udev_rules_check *c, int level) {
        assert(c);

        c->issues |= 1U << LOG_PRI(level);
}

/* The message may contain a whole value, so it is not cut to LINE_MAX here, see log_internalv(). */
_printf_(3,4)
static void log_line(struct udev_rules_check *c, int level, const char *format, ...) {
        _cleanup_free_ char *buf = NULL;
        va_list ap;
        int r;

        va_start(ap, format);
        r = vasprintf(&buf, format, ap);
        va_end(ap);
        if (r < 0)
                buf = NULL;

        udev_rules_check_note_level(c, level);
        log_full(level, "%s:%u %s", c->filename, c->line_nr, buf ?: "Out of memory.");
}

#define log_line_error(c, ...)   log_line(c, LOG_ERR, __VA_ARGS__)
#define log_line_warning(c, ...) log_line(c, LOG_WARNING, __VA_ARGS__)
#define log_line_notice(c, ...)  log_line(c, LOG_NOTICE, __VA_ARGS__)

/* Like systemd, a token with an error makes the rest of the line ignored. */
_printf_(2,3)
static void log_line_error_fail(struct udev_rules_check *c, const char *format, ...) {
        _cleanup_free_ char *buf = NULL;
        va_list ap;
        int r;

        va_start(ap, format);
        r = vasprintf(&buf, format, ap);
        va_end(ap);
        if (r < 0)
                buf = NULL;

        log_line_error(c, "%s", buf ?: "Out of memory.");
        c->line_failed = true;
}


void udev_rules_check_file_begin(struct udev_rules_check *c, const char *filename) {
        assert(c);
        assert(filename);

        check_lines_clear(c);
        c->issues = 0;
        free(c->filename);
        c->filename = strdup(filename);
        if (!c->filename)
                log_oom();
}

void udev_rules_check_line_begin(struct udev_rules_check *c, unsigned line_nr, const char *line) {
        assert(c);

        check_line_done(&c->current);
        c->n_tokens_allocated = 0;
        c->current.line_nr = line_nr;
        c->line_nr = line_nr;
        c->line = line;
        c->line_failed = false;
        c->has_result = false;
        c->order_checked = false;
}

void udev_rules_check_delimiters(struct udev_rules_check *c, const char *pos) {
        size_t n_comma = 0;
        bool ws_before_comma = false, ws_after_comma = false;
        const char *p;

        assert(c);
        assert(pos);

        if (c->line_failed)
                return;

        for (p = pos; !isempty(p); ++p) {
                if (*p == ',')
                        ++n_comma;
                else if (strchr(WHITESPACE, *p)) {
                        if (n_comma > 0)
                                ws_after_comma = true;
                        else
                                ws_before_comma = true;
                } else
                        break;
        }

        if (pos == c->line) {
                /* this is the first token of the rule */
                if (n_comma > 0)
                        log_line_notice(c, "style: stray leading comma.");
        } else if (isempty(p)) {
                /* there are no more tokens in the rule */
                if (n_comma > 0)
                        log_line_notice(c, "style: stray trailing comma.");
        } else {
                /* single comma is expected */
                if (n_comma == 0)
                        log_line_notice(c, "style: a comma between tokens is expected.");
                else if (n_comma > 1)
                        log_line_notice(c, "style: more than one comma between tokens.");

                /* whitespace after comma is expected */
                if (n_comma > 0) {
                        if (ws_before_comma)
                                log_line_notice(c, "style: stray whitespace before comma.");
                        if (!ws_after_comma)
                                log_line_notice(c, "style: whitespace after comma is expected.");
                } else if (!ws_before_comma && !ws_after_comma)
                        log_line_notice(c, "style: whitespace between tokens is expected.");
        }
}

/* The substitutions of udev_event_apply_format(), like udev_check_format() of systemd. */
static const struct {
        const char *name;
        char fmt;
} subst_map[] = {
        { "devnode",  'N' },
        { "tempnode", 'N' },
        { "attr",     's' },
        { "sysfs",    's' },
        { "env",      'E' },
        { "kernel",   'k' },
        { "number",   'n' },
        { "driver",   'd' },
        { "devpath",  'p' },
        { "id",       'b' },
        { "major",    'M' },
        { "minor",    'm' },
        { "result",   'c' },
        { "parent",   'P' },
        { "name",     'D' },
        { "links",    'L' },
        { "root",     'r' },
        { "sys",      'S' },
};

/* Returns 0 if *str does not start a substitution, 1 if it does, and a negative error for an
 * invalid one. On success, *str is moved past the substitution, and the index into subst_map
 * and the attribute (or "" if there is none) are returned. */
static int get_subst_type(const char **str, size_t *ret_index, char *ret_attr, size_t attr_size) {
        const char *p = *str, *q = NULL;
        size_t i = 0;

        if (*p == '$') {
                p++;
                if (*p == '$') {
                        *str = p;
                        return 0;
                }
                for (i = 0; i < ELEMENTSOF(subst_map); i++)
                        if ((q = startswith(p, subst_map[i].name)))
                                break;
        } else if (*p == '%') {
                p++;
                if (*p == '%') {
                        *str = p;
                        return 0;
                }

                for (i = 0; i < ELEMENTSOF(subst_map); i++)
                        if (*p == subst_map[i].fmt) {
                                q = p + 1;
                                break;
                        }
        } else
                return 0;
        if (!q)
                /* '$' and '%' must be escaped. */
                return -EINVAL;

        if (*q == '{') {
                const char *start, *end;
                size_t len;

                start = q + 1;
                end = strchr(start, '}');
                if (!end)
                        return -EINVAL;

                len = end - start;
                if (len == 0 || len >= attr_size)
                        return -EINVAL;

                memcpy(ret_attr, start, len);
                ret_attr[len] = '\0';
                q = end + 1;
        } else
                ret_attr[0] = '\0';

        *str = q;
        *ret_index = i;
        return 1;
}

static int check_format(const char *value, size_t *ret_offset, const char **ret_hint) {
        const char *s = value;
        char attr[UTIL_PATH_SIZE];
        size_t i;
        int r;

        while (*s) {
                r = get_subst_type(&s, &i, attr, sizeof(attr));
                if (r < 0) {
                        *ret_offset = s - value;
                        *ret_hint = "invalid substitution type";
                        return r;
                } else if (r == 0) {
                        s++;
                        continue;
                }

                if (IN_SET(subst_map[i].fmt, 's', 'E') && isempty(attr)) {
                        *ret_offset = s - value;
                        *ret_hint = "attribute value missing";
                        return -EINVAL;
                }

                if (subst_map[i].fmt == 'c' && !isempty(attr)) {
                        unsigned u;

                        /* a number, optionally followed by '+', like the substitution takes it */
                        r = safe_atou_optional_plus(attr, &u);
                        if (r < 0) {
                                *ret_offset = s - value;
                                *ret_hint = "attribute value not a valid number";
                                return r;
                        }
                }
        }

        return 0;
}

static void check_value_format(struct udev_rules_check *c, const char *key, const char *value, bool nonempty) {
        size_t offset;
        const char *hint;

        if (nonempty && isempty(value))
                log_line_error_fail(c, "Invalid value \"%s\" for %s (char %zu: %s), ignoring.",
                                    value, key, (size_t) 0, "empty value");
        else if (check_format(value, &offset, &hint) < 0)
                log_line_error_fail(c, "Invalid value \"%s\" for %s (char %zu: %s), ignoring.",
                                    value, key, offset + 1, hint);
}

/* A missing or empty attribute is reported by the parser. */
static void check_attr_format(struct udev_rules_check *c, const char *key, const char *attr) {
        size_t offset;
        const char *hint;

        if (check_format(attr, &offset, &hint) < 0)
                log_line_error_fail(c, "Invalid attribute \"%s\" for %s (char %zu: %s), ignoring.",
                                    attr, key, offset + 1, hint);
}

static SubstType get_substitution_type(const char *str) {
        if (str[0] == '[')
                return SUBST_TYPE_SUBSYS;
        if (strchr(str, '%') || strchr(str, '$'))
                return SUBST_TYPE_FORMAT;
        return SUBST_TYPE_PLAIN;
}

/* Remembers a token of the current line, for the checks of conflicting and duplicate expressions. */
static void add_token(struct udev_rules_check *c, const char *type, bool is_match, UdevRulesCheckOp op,
                      const char *value, const char *data, bool is_case_insensitive, bool has_alternatives,
                      bool is_attr) {
        CheckToken t = {
                .is_match = is_match,
                .op = op,
                .match_type = MATCH_TYPE_INVALID,
                .attr_subst_type = SUBST_TYPE_INVALID,
        };

        if (c->line_failed)
                return;

        if (is_match) {
                if (streq(type, "SUBSYSTEM") && (streq(value, "subsystem") || streq(value, "bus") || streq(value, "class")))
                        t.match_type = MATCH_TYPE_SUBSYSTEM;
                else if (isempty(value))
                        t.match_type = MATCH_TYPE_EMPTY;
                else if (streq(value, "?*")) {
                        /* KEY=="?*" is KEY!="" */
                        t.match_type = MATCH_TYPE_EMPTY;
                        t.op = op == CHECK_OP_MATCH ? CHECK_OP_NOMATCH : CHECK_OP_MATCH;
                } else if (string_is_glob(value))
                        t.match_type = MATCH_TYPE_GLOB;
                else
                        t.match_type = MATCH_TYPE_PLAIN;

                if (has_alternatives) {
                        bool empty = false;
                        const char *p = value;

                        for (;;) {
                                size_t n = strcspn(p, "|");

                                if (n == 0)
                                        empty = true;
                                else {
                                        _cleanup_free_ char *s = strndup(p, n);

                                        if (!s || strv_extend(&t.values, s) < 0)
                                                goto oom;
                                }

                                if (p[n] == '\0')
                                        break;
                                p += n + 1;
                        }

                        if (empty) {
                                if (t.match_type == MATCH_TYPE_GLOB)
                                        t.match_type = MATCH_TYPE_GLOB_WITH_EMPTY;
                                if (t.match_type == MATCH_TYPE_PLAIN)
                                        t.match_type = MATCH_TYPE_PLAIN_WITH_EMPTY;
                        }
                }

                if (is_attr) {
                        size_t len = strlen(value);

                        if (len > 0 && !isspace((unsigned char) value[len - 1]))
                                t.match_type |= MATCH_REMOVE_TRAILING_WHITESPACE;

                        t.attr_subst_type = get_substitution_type(data);
                }

                if (is_case_insensitive)
                        t.match_type |= MATCH_CASE_INSENSITIVE;
        }

        t.type = strdup(type);
        t.value = strdup(value);
        if (!t.type || !t.value)
                goto oom;
        if (data) {
                t.data = strdup(data);
                if (!t.data)
                        goto oom;
        }

        if (!GREEDY_REALLOC(c->current.tokens, c->n_tokens_allocated, c->current.n_tokens + 1))
                goto oom;

        c->current.tokens[c->current.n_tokens++] = t;
        return;

oom:
        check_token_done(&t);
        log_oom();
}

static void set_label(struct udev_rules_check *c, char **label, const char *value) {
        char *s;

        s = strdup(value);
        if (!s) {
                log_oom();
                return;
        }

        free(*label);
        *label = s;
}

void udev_rules_check_token(struct udev_rules_check *c, const char *base, const char *attr, UdevRulesCheckOp op,
                            const char *value, bool is_case_insensitive) {
        bool is_match = IN_SET(op, CHECK_OP_MATCH, CHECK_OP_NOMATCH);
        mode_t mode;

        assert(c);
        assert(base);
        assert(value);

        c->key_first_token = c->current.n_tokens;
        c->key_had_other = c->current.has_other;

        if (c->line_failed)
                return;

        /* An 'i' prefix of an assignment is reported by the parser. */
        if (!is_match && is_case_insensitive)
                return;

        if (STR_IN_SET(base, "ACTION", "DEVPATH", "KERNEL", "DRIVER", "KERNELS", "SUBSYSTEMS", "DRIVERS",
                       "TAGS", "RESULT", "SUBSYSTEM")) {
                /* An attribute or a wrong operator is reported by the parser. */
                if (attr || !is_match)
                        return;

                add_token(c, base, true, op, value, NULL, is_case_insensitive, true, false);

                if (streq(base, "RESULT"))
                        c->has_result = true;

        } else if (streq(base, "SYMLINK")) {
                if (attr)
                        return;

                if (!is_match) {
                        check_value_format(c, base, value, false);
                        c->current.has_other = true;
                }
                add_token(c, base, is_match, op, value, NULL, is_case_insensitive, true, false);

        } else if (streq(base, "NAME")) {
                /* An attribute or a wrong operator is reported by the parser. */
                if (attr || op == CHECK_OP_REMOVE)
                        return;
                if (op == CHECK_OP_ADD) {
                        log_line_warning(c, "%s key takes '==', '!=', '=', or ':=' operator, assuming '='.", base);
                        op = CHECK_OP_ASSIGN;
                }

                if (!is_match) {
                        /* NAME="%k" and NAME="" are reported by the parser. */
                        if (streq(value, "%k") || isempty(value))
                                return;
                        check_value_format(c, base, value, false);
                        c->current.has_other = true;
                }
                add_token(c, base, is_match, op, value, NULL, is_case_insensitive, true, false);

        } else if (streq(base, "ENV")) {
                /* A missing or empty attribute or a wrong operator is reported by the parser. */
                if (isempty(attr) || op == CHECK_OP_REMOVE)
                        return;
                if (op == CHECK_OP_ASSIGN_FINAL) {
                        log_line_warning(c, "%s key takes '==', '!=', '=', or '+=' operator, assuming '='.", base);
                        op = CHECK_OP_ASSIGN;
                }

                if (!is_match) {
                        check_value_format(c, base, value, false);
                        c->current.has_other = true;
                }
                add_token(c, base, is_match, op, value, attr, is_case_insensitive, true, false);

        } else if (streq(base, "TAG")) {
                if (attr)
                        return;
                if (op == CHECK_OP_ASSIGN_FINAL) {
                        log_line_warning(c, "%s key takes '==', '!=', '=', or '+=' operator, assuming '='.", base);
                        op = CHECK_OP_ASSIGN;
                }

                if (!is_match) {
                        check_value_format(c, base, value, true);
                        c->current.has_other = true;
                }
                add_token(c, base, is_match, op, value, NULL, is_case_insensitive, true, false);

        } else if (STR_IN_SET(base, "ATTR", "SYSCTL")) {
                if (isempty(attr))
                        return;
                check_attr_format(c, base, attr);
                if (c->line_failed)
                        return;
                if (op == CHECK_OP_REMOVE)
                        return;
                if (IN_SET(op, CHECK_OP_ADD, CHECK_OP_ASSIGN_FINAL)) {
                        log_line_warning(c, "%s key takes '==', '!=', or '=' operator, assuming '='.", base);
                        op = CHECK_OP_ASSIGN;
                }

                if (!is_match) {
                        check_value_format(c, base, value, false);
                        c->current.has_other = true;
                }
                add_token(c, base, is_match, op, value, attr, is_case_insensitive, true, streq(base, "ATTR"));

        } else if (streq(base, "ATTRS")) {
                if (isempty(attr))
                        return;
                check_attr_format(c, base, attr);
                if (c->line_failed || !is_match)
                        return;

                add_token(c, base, true, op, value, attr, is_case_insensitive, true, true);

        } else if (streq(base, "TEST")) {
                _cleanup_free_ char *m = NULL;

                if (!isempty(attr)) {
                        /* An invalid mode is reported by the parser. */
                        if (parse_mode(attr, &mode) < 0)
                                return;
                        if (asprintf(&m, "%04o", (unsigned) mode) < 0) {
                                log_oom();
                                return;
                        }
                }
                check_value_format(c, base, value, true);
                /* A wrong operator or an 'i' prefix is reported by the parser. */
                if (c->line_failed || !is_match || is_case_insensitive)
                        return;

                add_token(c, base, true, op, value, m, false, false, false);

        } else if (streq(base, "PROGRAM")) {
                check_value_format(c, base, value, true);
                if (c->line_failed || op == CHECK_OP_REMOVE || is_case_insensitive)
                        return;

                /* PROGRAM="..." is a match. */
                add_token(c, base, true, is_match ? op : CHECK_OP_MATCH, value, NULL, false, false, false);
                c->current.has_other = true;

                if (c->has_result && !c->order_checked) {
                        log_line_warning(c, "Reordering RESULT check after PROGRAM assignment.");
                        c->order_checked = true;
                }

        } else if (streq(base, "IMPORT")) {
                _cleanup_free_ char *type = NULL;

                /* A missing or unknown type, an unknown builtin command, a wrong operator and
                 * an 'i' prefix are reported by the parser. */
                if (isempty(attr))
                        return;
                check_value_format(c, base, value, true);
                if (c->line_failed || op == CHECK_OP_REMOVE || is_case_insensitive)
                        return;
                if (!STR_IN_SET(attr, "program", "builtin", "file", "db", "cmdline", "parent"))
                        return;

                /* IMPORT{program} of a builtin command is IMPORT{builtin}. */
                if (streq(attr, "program") && value[0] != '/' && udev_builtin_lookup(value) < UDEV_BUILTIN_MAX)
                        type = strdup("IMPORT{builtin}");
                else
                        type = strjoin("IMPORT{", attr, "}", NULL);
                if (!type) {
                        log_oom();
                        return;
                }

                add_token(c, type, true, is_match ? op : CHECK_OP_MATCH, value, NULL, false, false, false);
                c->current.has_other = true;

        } else if (streq(base, "RUN")) {
                _cleanup_free_ char *type = NULL;

                /* A wrong operator is reported by the parser. */
                if (is_match || op == CHECK_OP_REMOVE)
                        return;
                check_value_format(c, base, value, true);
                if (c->line_failed)
                        return;
                /* An unknown type or builtin command is reported by the parser. */
                if (attr && !STR_IN_SET(attr, "program", "builtin"))
                        return;

                type = strjoin("RUN{", attr ?: "program", "}", NULL);
                if (!type) {
                        log_oom();
                        return;
                }

                add_token(c, type, false, op, value, NULL, false, false, false);
                c->current.has_other = true;

        } else if (streq(base, "LABEL")) {
                /* An attribute, a wrong operator and a LABEL after the first are reported by the
                 * parser, which takes the last one. */
                if (attr || op != CHECK_OP_ASSIGN)
                        return;

                set_label(c, &c->current.label, value);

        } else if (streq(base, "GOTO")) {
                /* An attribute, a wrong operator and a GOTO after the first are reported by the
                 * parser, which ignores the later ones. */
                if (attr || op != CHECK_OP_ASSIGN || c->current.goto_label)
                        return;

                set_label(c, &c->current.goto_label, value);

        } else if (STR_IN_SET(base, "OWNER", "GROUP", "MODE")) {
                /* An attribute or a wrong operator is reported by the parser. */
                if (attr || is_match || op == CHECK_OP_REMOVE)
                        return;
                if (op == CHECK_OP_ADD) {
                        log_line_warning(c, "%s key takes '=' or ':=' operator, assuming '='.", base);
                        op = CHECK_OP_ASSIGN;
                }

                /* An empty value, a user or group that cannot be resolved while the rules are read,
                 * and a MODE without substitutions that is not valid, also an empty one, are reported
                 * by the parser, which ignores the key then; it tells about the OWNER and GROUP keys
                 * with udev_rules_check_key_dropped(). */
                if (streq(base, "MODE")) {
                        if (parse_mode(value, &mode) < 0) {
                                if (get_substitution_type(value) == SUBST_TYPE_PLAIN)
                                        return;
                                check_value_format(c, base, value, true);
                        }
                } else if (!in_charset(value, DIGITS)) {
                        /* Like the parser: names without substitutions are resolved when the rules are
                         * read, if names are resolved early, other names whenever the rule is applied,
                         * and no names if name resolution is disabled. */
                        if (c->resolve_names < 0) {
                                c->current.names_ignored = true;
                                return;
                        }
                        if (!(c->resolve_names > 0 && get_substitution_type(value) == SUBST_TYPE_PLAIN))
                                check_value_format(c, base, value, true);
                }
                if (c->line_failed)
                        return;

                add_token(c, base, false, op, value, NULL, false, false, false);
                c->current.has_other = true;

        } else if (streq(base, "SECLABEL")) {
                /* A missing or empty attribute is reported by the parser. */
                if (isempty(attr))
                        return;
                check_value_format(c, base, value, true);
                /* A wrong operator is reported by the parser. */
                if (c->line_failed || is_match || op == CHECK_OP_REMOVE)
                        return;
                if (op == CHECK_OP_ASSIGN_FINAL) {
                        log_line_warning(c, "%s key takes '=' or '+=' operator, assuming '='.", base);
                        op = CHECK_OP_ASSIGN;
                }

                add_token(c, base, false, op, value, attr, false, false, false);
                c->current.has_other = true;

        } else if (streq(base, "OPTIONS")) {
                _cleanup_strv_free_ char **options = NULL;
                bool known = false;
                char **o;

                /* A wrong operator, unknown options and invalid values of link_priority= and
                 * log_level= are reported by the parser. */
                if (attr || op == CHECK_OP_REMOVE || is_match)
                        return;

                /* eudev takes several comma separated options in one value. */
                if (strv_split_and_extend(&options, value, ",", false) < 0) {
                        log_oom();
                        return;
                }

                STRV_FOREACH(o, options)
                        if (udev_rules_option_is_known(*o))
                                known = true;
                if (!known)
                        return;

                add_token(c, base, false, op == CHECK_OP_ADD ? CHECK_OP_ASSIGN : op, value, NULL, false, false, false);
                c->current.has_other = true;
        }

        /* Other keys are reported by the parser as unknown. */
}

void udev_rules_check_key_dropped(struct udev_rules_check *c) {
        assert(c);

        while (c->current.n_tokens > c->key_first_token)
                check_token_done(&c->current.tokens[--c->current.n_tokens]);
        c->current.has_other = c->key_had_other;
}

static bool strv_set_eq(char **a, char **b) {
        char **i;

        STRV_FOREACH(i, a)
                if (!strv_contains(b, *i))
                        return false;

        STRV_FOREACH(i, b)
                if (!strv_contains(a, *i))
                        return false;

        return true;
}

static bool token_type_and_value_eq(const CheckToken *a, const CheckToken *b) {
        if (!streq(a->type, b->type) ||
            a->is_match != b->is_match ||
            a->match_type != b->match_type)
                return false;

        /* token value is ignored for certain match types */
        if (IN_SET(a->match_type, MATCH_TYPE_EMPTY, MATCH_TYPE_SUBSYSTEM))
                return true;

        return a->values || b->values ? strv_set_eq(a->values, b->values) : streq_ptr(a->value, b->value);
}

static bool conflicting_op(UdevRulesCheckOp a, UdevRulesCheckOp b) {
        return (a == CHECK_OP_MATCH && b == CHECK_OP_NOMATCH) ||
               (a == CHECK_OP_NOMATCH && b == CHECK_OP_MATCH);
}

/* test whether all fields besides the operator of two tokens match */
static bool tokens_eq(const CheckToken *a, const CheckToken *b) {
        return a->attr_subst_type == b->attr_subst_type &&
               token_type_and_value_eq(a, b) &&
               streq_ptr(a->data, b->data);
}

static bool alternatives_conflict(const CheckToken *a, const CheckToken *b) {
        char **i, **j;

        if (!(streq(a->type, b->type) &&
              a->is_match && b->is_match &&
              a->values && b->values &&
              a->op == b->op &&
              a->op == CHECK_OP_MATCH &&
              a->match_type == b->match_type &&
              a->attr_subst_type == b->attr_subst_type &&
              streq_ptr(a->data, b->data)))
                return false;

        if (a->match_type == MATCH_TYPE_PLAIN) {
                STRV_FOREACH(i, a->values)
                        if (strv_contains(b->values, *i))
                                return false;
                return true;
        }

        if (a->match_type == MATCH_TYPE_GLOB) {
                STRV_FOREACH(i, a->values) {
                        size_t i_n = strcspn(*i, GLOB_CHARS);

                        if (i_n == 0)
                                return false;
                        STRV_FOREACH(j, b->values) {
                                size_t j_n = strcspn(*j, GLOB_CHARS);

                                if (j_n == 0 || strneq(*i, *j, MIN(i_n, j_n)))
                                        return false;
                        }
                }
                return true;
        }

        return false;
}

static void check_conflicts_duplicates(struct udev_rules_check *c, CheckLine *line) {
        bool conflicts = false, duplicates = false;
        size_t i, j;

        for (i = 0; i < line->n_tokens; i++)
                for (j = i + 1; j < line->n_tokens; j++) {
                        const CheckToken *token = &line->tokens[i], *t = &line->tokens[j];
                        bool new_conflicts = false, new_duplicates = false;

                        if (tokens_eq(token, t)) {
                                if (!duplicates && token->op == t->op)
                                        new_duplicates = true;
                                if (!conflicts && conflicting_op(token->op, t->op))
                                        new_conflicts = true;
                        } else if (!conflicts && alternatives_conflict(token, t))
                                new_conflicts = true;
                        else
                                continue;

                        if (new_duplicates) {
                                duplicates = new_duplicates;
                                log_line_warning(c, "duplicate expressions.");
                        }
                        if (new_conflicts) {
                                conflicts = new_conflicts;
                                log_line_error(c, "conflicting match expressions, the line has no effect.");
                        }
                        if (conflicts && duplicates)
                                return;
                }
}

void udev_rules_check_line_end(struct udev_rules_check *c, bool valid) {
        assert(c);

        if (!valid || c->line_failed) {
                check_line_done(&c->current);
                c->n_tokens_allocated = 0;
                return;
        }

        if (!c->current.has_other && !c->current.label && !c->current.goto_label) {
                /* A line that only sets names that are not resolved has no effect with
                 * --resolve-names=never, which the user asked for: that is not a problem of the
                 * rules. */
                if (!c->current.names_ignored)
                        log_line_warning(c, "The line has no effect, ignoring.");
                check_line_done(&c->current);
                c->n_tokens_allocated = 0;
                return;
        }

        if (!GREEDY_REALLOC(c->lines, c->n_lines_allocated, c->n_lines + 1)) {
                log_oom();
                return;
        }

        c->lines[c->n_lines++] = c->current;
        memzero(&c->current, sizeof(CheckLine));
        c->n_tokens_allocated = 0;
}

/* Called by the parser after it reported that a GOTO of the line has no matching label. Like
 * rule_resolve_goto() of systemd, report right after that when the line has no effect any more. */
void udev_rules_check_goto_unresolved(struct udev_rules_check *c, unsigned line_nr) {
        size_t i, k;

        assert(c);

        for (i = 0; i < c->n_lines; i++) {
                CheckLine *line = &c->lines[i];

                if (line->line_nr != line_nr || !line->goto_label)
                        continue;

                if (line->has_other || line->dropped)
                        return;

                c->line_nr = line_nr;
                if (!line->names_ignored)
                        log_line_warning(c, "The line has no effect any more, dropping.");

                for (k = 0; k < line->n_tokens; k++)
                        check_token_done(&line->tokens[k]);
                line->n_tokens = 0;
                line->dropped = true;
                return;
        }
}

void udev_rules_check_file_end(struct udev_rules_check *c) {
        size_t i, j;

        assert(c);

        /* Link GOTOs to LABELs like the parser, to find the unused labels. A GOTO without a matching
         * label, and a line that has no effect any more then, are reported while the file is parsed. */
        for (i = 0; i < c->n_lines; i++) {
                CheckLine *line = &c->lines[i];

                if (!line->goto_label)
                        continue;

                for (j = i + 1; j < c->n_lines; j++)
                        if (streq_ptr(c->lines[j].label, line->goto_label)) {
                                c->lines[j].referenced = true;
                                break;
                        }
        }

        for (i = 0; i < c->n_lines; i++) {
                CheckLine *line = &c->lines[i];

                c->line_nr = line->line_nr;

                if (line->label && !line->referenced)
                        log_line_notice(c, "style: LABEL=\"%s\" is unused.", line->label);

                check_conflicts_duplicates(c, line);
        }

        check_lines_clear(c);
}
