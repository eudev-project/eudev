/*
 * Copyright (C) 2003-2012 Kay Sievers <kay@vrfy.org>
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

#include <stddef.h>
#include <limits.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <fnmatch.h>
#include <time.h>
#include <grp.h>
#include <pwd.h>
#include <sys/sysmacros.h>

#include "def.h"
#include "udev.h"
#include "udev-rules-check.h"
#include "path-util.h"
#include "conf-files.h"
#include "fileio.h"
#include "netif-naming-scheme.h"
#include "socket-util.h"
#include "strbuf.h"
#include "strv.h"
#include "util.h"
#include "utf8.h"
#include "sysctl-util.h"

/* While 'udevadm verify' checks a rules file, see udev-rules-check.c, the levels of all
 * messages about it are collected, also of the ones that are not shown with the current
 * log level. */
static struct udev_rules_check *checking = NULL;

/* The rules file and the line of the rule that is being parsed. The messages about the rule start
 * with them, like systemd's. For a rule that is continued on the following lines, this is the first
 * line of the rule. */
static const char *parse_filename = NULL;
static unsigned parse_line_nr = 0;

#undef log_full_errno
#define log_full_errno(level, error, ...)                                         \
        ({                                                                        \
                int _l = (level), _e = (error);                                   \
                if (checking)                                                     \
                        udev_rules_check_note_level(checking, _l);                \
                (log_get_max_level() >= LOG_PRI(_l))                              \
                ? log_internal(_l, _e, __FILE__, __LINE__, __func__, __VA_ARGS__) \
                : -abs(_e);                                                       \
        })

/* systemd's text, also noted while checking a rules file */
#undef log_oom
#define log_oom()                               log_full_errno(LOG_ERR, ENOMEM, "Out of memory.")

#define log_rule_full_errno(level, error, fmt, ...)                               \
        log_full_errno(level, error, "%s:%u " fmt, strna(parse_filename), parse_line_nr, ##__VA_ARGS__)
#define log_rule_full(level, ...)               log_rule_full_errno(level, 0, __VA_ARGS__)
#define log_rule_debug(...)                     log_rule_full(LOG_DEBUG, __VA_ARGS__)
#define log_rule_warning(...)                   log_rule_full(LOG_WARNING, __VA_ARGS__)
#define log_rule_error(...)                     log_rule_full(LOG_ERR, __VA_ARGS__)
#define log_rule_error_errno(error, ...)        log_rule_full_errno(LOG_ERR, error, __VA_ARGS__)
#define log_rule_invalid_op(key)                log_rule_error("Invalid operator for %s.", key)
#define log_rule_invalid_attr(key)              log_rule_error("Invalid attribute for %s.", key)
#define log_rule_invalid_prefix(key)            log_rule_error("Invalid prefix 'i' for %s.", key)

/* A warning about a rule that 'udevadm verify' does not count as an issue of the rules file, like the ones
 * that systemd logs with log_struct() instead of log_line_*(). */
#define log_rule_warning_no_issue(fmt, ...)                                                         \
        ((log_get_max_level() >= LOG_WARNING)                                                       \
         ? log_internal(LOG_WARNING, 0, __FILE__, __LINE__, __func__, "%s:%u " fmt,                 \
                        strna(parse_filename), parse_line_nr, ##__VA_ARGS__)                        \
         : 0)

/* The messages about applying a rule to the device of an event start, like the ones of log_event_*() of
 * systemd, with the name of the device and the rules file and first line of the rule, followed by the key
 * the message is about, when there is one, as the text of the token in systemd, e.g.
 * "sda: /usr/lib/udev/rules.d/60-block.rules:14 SUBSYSTEM=="block": ...". For the keys that match the
 * parent devices, e.g. ATTRS{}, the device is the parent device that is checked. rule is the TK_RULE token
 * of the rule, tok the token of the key or NULL. See token_to_string() and event_log_device(). */
#define log_event_full_errno(event, rules, rule, tok, level, error, fmt, ...)                     \
        ({                                                                                        \
                int _level = (level);                                                             \
                struct token *_token = (tok);                                                     \
                const char *_sysname = udev_device_get_sysname(event_log_device((event), _token)); \
                _cleanup_free_ char *_key = NULL;                                                 \
                                                                                                  \
                if (_token && log_get_max_level() >= LOG_PRI(_level))                             \
                        _key = token_to_string((rules), _token);                                  \
                log_full_errno(_level, error, "%s%s%s:%u %s%s" fmt,                               \
                               _sysname ?: "", _sysname ? ": " : "",                              \
                               rules_str(rules, (rule)->rule.filename_off),                       \
                               (rule)->rule.filename_line,                                        \
                               _key ?: "", _key ? ": " : "", ##__VA_ARGS__);                      \
        })
#define log_event_full(event, rules, rule, tok, level, ...)   \
        log_event_full_errno(event, rules, rule, tok, level, 0, __VA_ARGS__)
#define log_event_debug(event, rules, rule, tok, ...)         log_event_full(event, rules, rule, tok, LOG_DEBUG, __VA_ARGS__)
#define log_event_info(event, rules, rule, tok, ...)          log_event_full(event, rules, rule, tok, LOG_INFO, __VA_ARGS__)
#define log_event_warning(event, rules, rule, tok, ...)       log_event_full(event, rules, rule, tok, LOG_WARNING, __VA_ARGS__)
#define log_event_error(event, rules, rule, tok, ...)         log_event_full(event, rules, rule, tok, LOG_ERR, __VA_ARGS__)
#define log_event_debug_errno(event, rules, rule, tok, error, ...)    \
        log_event_full_errno(event, rules, rule, tok, LOG_DEBUG, error, __VA_ARGS__)
#define log_event_warning_errno(event, rules, rule, tok, error, ...)  \
        log_event_full_errno(event, rules, rule, tok, LOG_WARNING, error, __VA_ARGS__)
#define log_event_error_errno(event, rules, rule, tok, error, ...)    \
        log_event_full_errno(event, rules, rule, tok, LOG_ERR, error, __VA_ARGS__)
/* Like log_event_trace() of systemd: a debug message only in trace mode, see struct udev_event. */
#define log_event_trace(event, rules, rule, tok, ...)                                             \
        ((event)->trace ? log_event_debug(event, rules, rule, tok, __VA_ARGS__) : 0)
#define log_event_trace_errno(event, rules, rule, tok, error, ...)                                \
        ((event)->trace ? log_event_debug_errno(event, rules, rule, tok, error, __VA_ARGS__) : 0)
/* Like log_event_done() of systemd: in trace mode, that an action of the rules was done. */
#define log_event_done(event, rules, rule, tok)                                                   \
        log_event_trace(event, rules, rule, tok, "DONE")
/* Like log_event_final_set() of systemd: in trace mode, that an action of the rules is ignored, as a
 * final value was assigned before. */
#define log_event_final_set(event, rules, rule, tok)                                              \
        log_event_trace(event, rules, rule, tok, "Already assigned final value, ignoring further %s.", \
                        (tok)->key.op == OP_REMOVE ? "modification" : "assignment")

#define PREALLOC_TOKEN          2048
#define IMPORT_PROGRAM_SIZE     (128 * 1024)

struct uid_gid {
        unsigned int name_off;
        union {
                uid_t uid;
                gid_t gid;
        };
};

/* The directories of the rules files, in the order of precedence, like CONF_PATHS("udev/rules.d") of
 * systemd: a file in an earlier directory overrides the files with the same name in the later ones. Some
 * of them can be the same directory, e.g. UDEV_RULES_DIR is UDEV_LIBEXEC_DIR "/rules.d", and with
 * split-usr one of /lib/udev/rules.d and /usr/lib/udev/rules.d is usually one of them too; see
 * udev_rules_get_dirs(). */
static const char* const rules_dirs_all[] = {
        UDEV_CONF_DIR "/rules.d",
        UDEV_ROOT_RUN "/udev/rules.d",
        "/usr/local/lib/udev/rules.d",
        UDEV_RULES_DIR,
        UDEV_LIBEXEC_DIR "/rules.d",
#ifdef HAVE_SPLIT_USR
        "/lib/udev/rules.d",
        "/usr/lib/udev/rules.d",
#endif
        NULL};

/* The directories of rules_dirs_all, each path only once, where it comes first. udevadm cat and verify use
 * them, also below another root directory; the rules of this system are read from the ones of
 * udev_rules_get_dirs_runtime(). */
const char* const* udev_rules_get_dirs(void) {
        static const char *dirs[ELEMENTSOF(rules_dirs_all)];
        static bool initialized = false;
        size_t i, j, n = 0;

        if (initialized)
                return dirs;

        for (i = 0; rules_dirs_all[i]; i++) {
                for (j = 0; j < n; j++)
                        if (path_equal(dirs[j], rules_dirs_all[i]))
                                break;
                if (j == n)
                        dirs[n++] = rules_dirs_all[i];
        }
        dirs[n] = NULL;
        initialized = true;

        return dirs;
}

/* The directories of udev_rules_get_dirs(), where a directory that exists is listed only once, at its first
 * position, also when it has several of the paths, like /lib/udev/rules.d and /usr/lib/udev/rules.d on a
 * merged /usr, or a bind mount; it is found out by its device and inode. The directories that do not exist
 * stay in the list, to be looked at later. Returns a new list, or NULL when out of memory. udev_rules_new()
 * looks them up once and keeps them, for loading the rules and for udev_rules_check_timestamp(); when a
 * directory is created or mounted later, its timestamp changes, so that the rules are loaded again, with the
 * directories looked up again. */
char **udev_rules_get_dirs_runtime(void) {
        struct stat st[ELEMENTSOF(rules_dirs_all)];
        bool exists[ELEMENTSOF(rules_dirs_all)];
        _cleanup_strv_free_ char **dirs = NULL;
        const char* const* d;
        size_t j, n = 0;

        dirs = new0(char *, ELEMENTSOF(rules_dirs_all));
        if (!dirs)
                return NULL;

        for (d = udev_rules_get_dirs(); *d; d++) {
                struct stat s;
                bool e = stat(*d, &s) >= 0;

                for (j = 0; e && j < n; j++)
                        if (exists[j] && st[j].st_dev == s.st_dev && st[j].st_ino == s.st_ino)
                                break;
                if (e && j < n)
                        continue;

                dirs[n] = strdup(*d);
                if (!dirs[n])
                        return NULL;
                exists[n] = e;
                if (e)
                        st[n] = s;
                n++;
        }

        return TAKE_PTR(dirs);
}

struct udev_rules {
        struct udev *udev;
        /* the directories of the rules, see udev_rules_get_dirs_runtime() */
        char **dirs;
        usec_t dirs_ts_usec;
        int resolve_names;

        /* every key in the rules file becomes a token */
        struct token *tokens;
        unsigned int token_cur;
        unsigned int token_max;

        /* all key strings are copied and de-duplicated in a single continuous string buffer */
        struct strbuf *strbuf;

        /* during rule parsing, uid/gid lookup results are cached */
        struct uid_gid *uids;
        unsigned int uids_cur;
        unsigned int uids_max;
        struct uid_gid *gids;
        unsigned int gids_cur;
        unsigned int gids_max;
};

static char *rules_str(struct udev_rules *rules, unsigned int off) {
        return rules->strbuf->buf + off;
}

/* Adds a string to the string buffer, and returns its offset in ret_off. Returns -ENOMEM when out of
 * memory, and -E2BIG when the buffer would be larger than the offsets can be. */
static int rules_add_string(struct udev_rules *rules, const char *s, unsigned int *ret_off) {
        ssize_t off;

        off = strbuf_add_string(rules->strbuf, s, strlen(s));
        if (off < 0)
                return off;
        if ((size_t) off > UINT_MAX)
                return -E2BIG;

        *ret_off = off;
        return 0;
}

/* KEY=="", KEY!="", KEY+="", KEY-="", KEY="", KEY:="" */
enum operation_type {
        OP_UNSET,

        OP_MATCH,
        OP_NOMATCH,
        OP_MATCH_MAX,

        OP_ADD,
        OP_REMOVE,
        OP_ASSIGN,
        OP_ASSIGN_FINAL,
};

static UdevRulesCheckOp check_op(enum operation_type op) {
        switch (op) {
        case OP_NOMATCH:
                return CHECK_OP_NOMATCH;
        case OP_ADD:
                return CHECK_OP_ADD;
        case OP_REMOVE:
                return CHECK_OP_REMOVE;
        case OP_ASSIGN:
                return CHECK_OP_ASSIGN;
        case OP_ASSIGN_FINAL:
                return CHECK_OP_ASSIGN_FINAL;
        default:
                return CHECK_OP_MATCH;
        }
}

enum string_glob_type {
        GL_UNSET,
        GL_PLAIN,                       /* no special chars */
        GL_GLOB,                        /* shell globs ?,*,[] */
        GL_SPLIT,                       /* multi-value A|B */
        GL_SPLIT_GLOB,                  /* multi-value with glob A*|B* */
        GL_SOMETHING,                   /* commonly used "?*" */
};

enum string_subst_type {
        SB_UNSET,
        SB_NONE,
        SB_FORMAT,
        SB_SUBSYS,
};

/* tokens of a rule are sorted/handled in this order */
enum token_type {
        TK_UNSET,
        TK_RULE,

        TK_M_ACTION,                    /* val */
        TK_M_DEVPATH,                   /* val */
        TK_M_KERNEL,                    /* val */
        TK_M_DEVLINK,                   /* val */
        TK_M_NAME,                      /* val */
        TK_M_ENV,                       /* val, attr */
        TK_M_TAG,                       /* val */
        TK_M_SUBSYSTEM,                 /* val */
        TK_M_DRIVER,                    /* val */
        TK_M_ATTR,                      /* val, attr */
        TK_M_SYSCTL,                    /* val, attr */

        TK_M_PARENTS_MIN,
        TK_M_KERNELS,                   /* val */
        TK_M_SUBSYSTEMS,                /* val */
        TK_M_DRIVERS,                   /* val */
        TK_M_ATTRS,                     /* val, attr */
        TK_M_TAGS,                      /* val */
        TK_M_PARENTS_MAX,

        TK_M_TEST,                      /* val, mode_t */
        TK_M_PROGRAM,                   /* val */
        TK_M_IMPORT_FILE,               /* val */
        TK_M_IMPORT_PROG,               /* val */
        TK_M_IMPORT_BUILTIN,            /* val */
        TK_M_IMPORT_DB,                 /* val */
        TK_M_IMPORT_CMDLINE,            /* val */
        TK_M_IMPORT_PARENT,             /* val */
        TK_M_RESULT,                    /* val */
        TK_M_MAX,

        TK_A_DUMP,                      /* JsonFormatFlags */
        TK_A_STRING_ESCAPE_NONE,
        TK_A_STRING_ESCAPE_REPLACE,
        TK_A_DB_PERSIST,
        TK_A_NET_ALTNAMES,
        TK_A_INOTIFY_WATCH,             /* int */
        TK_A_DEVLINK_PRIO,              /* int */
        TK_A_LOG_LEVEL,                 /* int, -1 for "reset" */
        TK_A_OWNER,                     /* val */
        TK_A_GROUP,                     /* val */
        TK_A_MODE,                      /* val */
        TK_A_OWNER_ID,                  /* uid_t */
        TK_A_GROUP_ID,                  /* gid_t */
        TK_A_MODE_ID,                   /* mode_t */
        TK_A_TAG,                       /* val */
        TK_A_STATIC_NODE,               /* val */
        TK_A_SECLABEL,                  /* val, attr */
        TK_A_ENV,                       /* val, attr */
        TK_A_NAME,                      /* val */
        TK_A_DEVLINK,                   /* val */
        TK_A_ATTR,                      /* val, attr */
        TK_A_SYSCTL,                    /* val, attr */
        TK_A_RUN_BUILTIN,               /* val, bool */
        TK_A_RUN_PROGRAM,               /* val, bool */
        TK_A_GOTO,                      /* size_t */

        TK_END,
};

/* We try to pack stuff in a way that we take only 16 bytes per token. The offsets into the string buffer
 * (label_off, filename_off, value_off, attr_off) and the index of a token (rule_goto) take 32 bits, like
 * the line number; the number of the tokens of a rule, which counts the rule token too, takes 16 bits,
 * see RULE_TOKENS_MAX. */
struct token {
        union {
                unsigned char type;                /* same in rule and key */
                struct {
                        enum token_type type:8;
                        /* What the rule has, like the line types of systemd, see rule_add_key(): */
                        bool has_name:1;                /* NAME= */
                        bool has_devlink:1;             /* SYMLINK=, OWNER=, GROUP= or MODE= */
                        bool has_static_node:1;         /* OPTIONS="static_node=" */
                        bool has_goto:1;                /* a GOTO= that has its LABEL= */
                        bool update_something:1;        /* other assignments, PROGRAM or IMPORT */
                        unsigned int unused:3;
                        unsigned short token_count;
                        unsigned int label_off;
                        unsigned int filename_off;
                        unsigned int filename_line;
                } rule;
                struct {
                        enum token_type type:8;
                        enum operation_type op:8;
                        enum string_glob_type glob:7;
                        bool case_insensitive:1;  /* string or pattern is matched case-insensitively */
                        enum string_subst_type subst:4;
                        enum string_subst_type attrsubst:4;
                        unsigned int value_off;
                        union {
                                unsigned int attr_off;
                                unsigned int rule_goto;
                                mode_t  mode;
                                uid_t uid;
                                gid_t gid;
                                int devlink_prio;
                                int watch;
                                int log_level;
                                JsonFormatFlags dump_flags;
                                enum udev_builtin_cmd builtin_cmd;
                        };
                } key;
        };
};

/* Rule keys, builtins and OPTIONS values that systemd-udevd supports, but eudev does not. A rule line
 * using one of them is dropped, like any invalid line, but with a message saying why. */
enum systemd_only_type {
        SYSTEMD_ONLY_KEY,               /* e.g. CONST{virt}=="kvm" */
        SYSTEMD_ONLY_BUILTIN,           /* e.g. IMPORT{builtin}="uaccess" or RUN{builtin}+="uaccess" */
        SYSTEMD_ONLY_OPTION,            /* e.g. OPTIONS="foo" or OPTIONS="foo=bar", matched without "=bar" */
};

static const struct systemd_only {
        enum systemd_only_type type;
        const char *name;
} systemd_only_table[] = {
        /* CONST{arch}, CONST{virt} and CONST{cvm} match the architecture, the virtualization and the
         * confidential virtualization technology of the system. */
        { SYSTEMD_ONLY_KEY,     "CONST" },
        /* dissect_image: probes a disk image; net_setup_link: applies systemd.link(5) files; uaccess:
         * gives the logged in user access to the device node, with ACLs managed by systemd-logind. */
        { SYSTEMD_ONLY_BUILTIN, "dissect_image" },
        { SYSTEMD_ONLY_BUILTIN, "net_setup_link" },
        { SYSTEMD_ONLY_BUILTIN, "uaccess" },
        /* eudev supports all OPTIONS values of systemd. */
};

static const char *const systemd_only_type_table[] = {
        [SYSTEMD_ONLY_KEY]     = "key",
        [SYSTEMD_ONLY_BUILTIN] = "builtin",
        [SYSTEMD_ONLY_OPTION]  = "OPTIONS value",
};

/* Checks whether the first len characters of name are a systemd-only key, builtin or option. */
static bool is_systemd_only(enum systemd_only_type type, const char *name, size_t len) {
        unsigned int i;

        for (i = 0; i < ELEMENTSOF(systemd_only_table); i++)
                if (systemd_only_table[i].type == type &&
                    strlen(systemd_only_table[i].name) == len &&
                    strneq(systemd_only_table[i].name, name, len))
                        return true;

        return false;
}

/* Logs that the rule line uses a systemd-only feature, the caller drops the line. */
static void log_systemd_only(enum systemd_only_type type, const char *what) {
        log_rule_error("%s is a systemd-only %s, not supported by eudev, ignoring the rule.",
                       what, systemd_only_type_table[type]);
}

/* Checks whether the command of IMPORT{builtin}, IMPORT{program}, RUN{builtin}, RUN{program} or
 * PROGRAM names a builtin of eudev that this build leaves out, i.e. tpm2_id, and logs it. For PROGRAM
 * and RUN{program}, this is a program of the same name, which does not exist either. */
static bool check_disabled_builtin(const char *key, const char *cmd) {
#ifndef ENABLE_TPM2
        size_t len;

        cmd += strspn(cmd, WHITESPACE);
        len = strcspn(cmd, WHITESPACE);
        if (len == strlen("tpm2_id") && strneq(cmd, "tpm2_id", len)) {
                log_rule_error("%s=\"tpm2_id\" is not supported by this build of eudev (configured with --disable-tpm2), ignoring the rule.",
                               key);
                return true;
        }
#endif
        return false;
}

/* Checks whether the command of IMPORT{builtin}, IMPORT{program} or RUN{builtin} is a systemd-only
 * builtin, or a builtin of eudev that this build leaves out, and logs it. */
static bool check_systemd_only_builtin(const char *key, const char *cmd) {
        _cleanup_free_ char *what = NULL;
        size_t len;

        if (check_disabled_builtin(key, cmd))
                return true;

        cmd += strspn(cmd, WHITESPACE);
        len = strcspn(cmd, WHITESPACE);
        if (!is_systemd_only(SYSTEMD_ONLY_BUILTIN, cmd, len))
                return false;

        if (asprintf(&what, "%s=\"%.*s\"", key, (int) len, cmd) < 0)
                what = NULL;
        log_systemd_only(SYSTEMD_ONLY_BUILTIN, what ?: cmd);
        return true;
}

/* Logs the lines of OPTIONS="dump", each with the device name prefixed, so that they can be found in
 * the logs. The lines may be longer than the log buffer. */
static void log_dump(struct udev_device *dev, const char *buf) {
        const char *sysname = udev_device_get_sysname(dev) ?: "n/a";
        const char *p = buf;

        while (*p != '\0') {
                _cleanup_free_ char *line = NULL;
                size_t n = strcspn(p, "\n");

                if (asprintf(&line, "%s: %.*s", sysname, (int) n, p) < 0) {
                        log_oom();
                        return;
                }
                log_full_long(LOG_INFO, line);

                p += n;
                if (*p == '\n')
                        p++;
        }
}

/* The values of OPTIONS=, like parse_token() of systemd-udevd takes them. A value must be one of the
 * names exactly, or, for a name ending in '=', start with it and give the argument after it.
 * Unlike systemd-udevd, several values may be given, separated by commas. To add a value, add an
 * OPTION_ id, a row to option_table[] and a case to parse_options(). */
enum option_id {
        OPTION_DUMP,
        OPTION_DUMP_JSON,
        OPTION_STRING_ESCAPE_NONE,
        OPTION_STRING_ESCAPE_REPLACE,
        OPTION_DB_PERSIST,
        OPTION_NET_ALTNAMES,
        OPTION_WATCH,
        OPTION_NOWATCH,
        OPTION_STATIC_NODE,
        OPTION_LINK_PRIORITY,
        OPTION_LOG_LEVEL,
};

static const struct option_def {
        const char *name;
        enum option_id id;
} option_table[] = {
        { "dump",                       OPTION_DUMP },
        { "dump-json",                  OPTION_DUMP_JSON },
        { "string_escape=none",         OPTION_STRING_ESCAPE_NONE },
        { "string_escape=replace",      OPTION_STRING_ESCAPE_REPLACE },
        { "db_persist",                 OPTION_DB_PERSIST },
        { "net_altnames",               OPTION_NET_ALTNAMES },
        { "watch",                      OPTION_WATCH },
        { "nowatch",                    OPTION_NOWATCH },
        { "static_node=",               OPTION_STATIC_NODE },
        { "link_priority=",             OPTION_LINK_PRIORITY },
        { "log_level=",                 OPTION_LOG_LEVEL },
};

/* Looks up one value of OPTIONS=, and returns the argument of an option that takes one. */
static const struct option_def *option_lookup(const char *value, const char **ret_arg) {
        unsigned int i;

        for (i = 0; i < ELEMENTSOF(option_table); i++) {
                const char *name = option_table[i].name;
                const char *arg;

                if (endswith(name, "=")) {
                        arg = startswith(value, name);
                        if (!arg)
                                continue;
                } else if (streq(value, name))
                        arg = NULL;
                else
                        continue;

                *ret_arg = arg;
                return &option_table[i];
        }

        return NULL;
}

bool udev_rules_option_is_known(const char *value) {
        const char *arg;

        return option_lookup(value, &arg);
}

/* The rule token and the tokens of the keys of a rule, the most that token_count of the rule token,
 * an unsigned short, can count. */
#define RULE_TOKENS_MAX       USHRT_MAX

struct rule_tmp {
        struct udev_rules *rules;
        struct token rule;
        /* the tokens of the keys, like systemd without a fixed limit, grown as needed */
        struct token *token;
        size_t token_cur;
        size_t token_allocated;
        /* a key could not be added, because the rule has too many keys, or out of memory; the rule
         * is dropped */
        bool failed;
        /* the value of the currently parsed key has the "i" prefix */
        bool case_insensitive;
        /* the rule has a GOTO already */
        bool has_goto;
        /* the rule has a LABEL already */
        bool has_label;
};

static const char *operation_key_str(enum operation_type op) {
        switch (op) {
        case OP_MATCH:
                return "==";
        case OP_NOMATCH:
                return "!=";
        case OP_ADD:
                return "+=";
        case OP_REMOVE:
                return "-=";
        case OP_ASSIGN_FINAL:
                return ":=";
        default:
                return "=";
        }
}

/* The device that a message about the token is about: the parent device that is checked for the keys that
 * match parent devices, like token_is_for_parents() in the logging of systemd, otherwise the device of the
 * event. */
static struct udev_device *event_log_device(struct udev_event *event, struct token *token) {
        if (token && token->type > TK_M_PARENTS_MIN && token->type < TK_M_PARENTS_MAX && event->dev_parent)
                return event->dev_parent;

        return event->dev;
}

static char *escape_byte(char *t, char c) {
        *(t++) = '\\';
        *(t++) = 'x';
        *(t++) = hexchar((unsigned char) c >> 4);
        *(t++) = hexchar((unsigned char) c);
        return t;
}

/* Escapes a string of the rules for the messages about the keys: valid UTF-8 is kept as it is, so that e.g.
 * an "ä" stays readable, and control characters (also tab and newline, and the C1 ones) are written as
 * \xNN, like utf8_escape_non_printable() of systemd does. Unlike there, also the bytes of invalid UTF-8
 * are written as \xNN instead of U+FFFD, and a backslash and a '"' are written as \\ and \", so that the
 * escapes are unambiguous. In the rules, a '"' is written as \" too, but a backslash is written as \\
 * only in values with the "e" prefix, and as a single one in the other values. */
static char *escape_key_text(const char *s) {
        char *buf, *t;

        assert(s);

        buf = new(char, strlen(s) * 4 + 1);
        if (!buf)
                return NULL;

        for (t = buf; *s; ) {
                int len, c;

                len = utf8_encoded_valid_unichar(s);
                if (len <= 0) {
                        /* invalid UTF-8: escape this byte and look at the next one */
                        t = escape_byte(t, *(s++));
                        continue;
                }

                c = utf8_encoded_to_unichar(s);
                if (c < ' ' || (c >= 0x7f && c <= 0x9f))
                        for (; len > 0; len--)
                                t = escape_byte(t, *(s++));
                else if (IN_SET(c, '\\', '"')) {
                        *(t++) = '\\';
                        *(t++) = *(s++);
                } else {
                        t = mempcpy(t, s, len);
                        s += len;
                }
        }
        *t = '\0';

        return buf;
}

/* Formats a token like the key of the rule line it comes from, e.g. KERNEL=="sd*", for the trace
 * logs. The text of the rules is not kept, so OPTIONS are shown one by one, and RUN with its type.
 * Unlike the token text of systemd, the attribute and the value are escaped with escape_key_text(), so
 * that control characters and invalid UTF-8 of the rules do not get into the logs, and a '"' is shown
 * as \", as it is written in the rules. */
static char *token_to_string(struct udev_rules *rules, struct token *token) {
        const char *op = operation_key_str(token->key.op);
        _cleanup_free_ char *value = NULL, *attr = NULL;
        const char *key = NULL, *option = NULL;
        bool has_attr = false;
        char *s = NULL;
        int r;

        value = escape_key_text(rules_str(rules, token->key.value_off));
        if (!value)
                return NULL;

        switch (token->type) {
        case TK_M_ACTION:
                key = "ACTION";
                break;
        case TK_M_DEVPATH:
                key = "DEVPATH";
                break;
        case TK_M_KERNEL:
                key = "KERNEL";
                break;
        case TK_M_DEVLINK:
        case TK_A_DEVLINK:
                key = "SYMLINK";
                break;
        case TK_M_NAME:
        case TK_A_NAME:
                key = "NAME";
                break;
        case TK_M_ENV:
        case TK_A_ENV:
                key = "ENV";
                has_attr = true;
                break;
        case TK_M_TAG:
        case TK_A_TAG:
                key = "TAG";
                break;
        case TK_M_SUBSYSTEM:
                key = "SUBSYSTEM";
                break;
        case TK_M_DRIVER:
                key = "DRIVER";
                break;
        case TK_M_ATTR:
        case TK_A_ATTR:
                key = "ATTR";
                has_attr = true;
                break;
        case TK_M_SYSCTL:
        case TK_A_SYSCTL:
                key = "SYSCTL";
                has_attr = true;
                break;
        case TK_M_KERNELS:
                key = "KERNELS";
                break;
        case TK_M_SUBSYSTEMS:
                key = "SUBSYSTEMS";
                break;
        case TK_M_DRIVERS:
                key = "DRIVERS";
                break;
        case TK_M_ATTRS:
                key = "ATTRS";
                has_attr = true;
                break;
        case TK_M_TAGS:
                key = "TAGS";
                break;
        case TK_M_TEST:
                if (token->key.mode != MODE_INVALID) {
                        r = asprintf(&s, "TEST{%#o}%s\"%s\"", (unsigned) token->key.mode, op, value);
                        return r < 0 ? NULL : s;
                }
                key = "TEST";
                break;
        case TK_M_PROGRAM:
                key = "PROGRAM";
                break;
        case TK_M_IMPORT_FILE:
                key = "IMPORT{file}";
                break;
        case TK_M_IMPORT_PROG:
                key = "IMPORT{program}";
                break;
        case TK_M_IMPORT_BUILTIN:
                key = "IMPORT{builtin}";
                break;
        case TK_M_IMPORT_DB:
                key = "IMPORT{db}";
                break;
        case TK_M_IMPORT_CMDLINE:
                key = "IMPORT{cmdline}";
                break;
        case TK_M_IMPORT_PARENT:
                key = "IMPORT{parent}";
                break;
        case TK_M_RESULT:
                key = "RESULT";
                break;
        case TK_A_DUMP:
                option = json_format_enabled(token->key.dump_flags) ? "dump-json" : "dump";
                break;
        case TK_A_STRING_ESCAPE_NONE:
                option = "string_escape=none";
                break;
        case TK_A_STRING_ESCAPE_REPLACE:
                option = "string_escape=replace";
                break;
        case TK_A_DB_PERSIST:
                option = "db_persist";
                break;
        case TK_A_NET_ALTNAMES:
                option = "net_altnames";
                break;
        case TK_A_INOTIFY_WATCH:
                option = token->key.watch ? "watch" : "nowatch";
                break;
        case TK_A_DEVLINK_PRIO:
                r = asprintf(&s, "OPTIONS%s\"link_priority=%i\"", op, token->key.devlink_prio);
                return r < 0 ? NULL : s;
        case TK_A_LOG_LEVEL:
                if (token->key.log_level < 0)
                        option = "log_level=reset";
                else {
                        r = asprintf(&s, "OPTIONS%s\"log_level=%i\"", op, token->key.log_level);
                        return r < 0 ? NULL : s;
                }
                break;
        case TK_A_STATIC_NODE:
                r = asprintf(&s, "OPTIONS%s\"static_node=%s\"", op, value);
                return r < 0 ? NULL : s;
        case TK_A_OWNER:
                key = "OWNER";
                break;
        case TK_A_GROUP:
                key = "GROUP";
                break;
        case TK_A_MODE:
                key = "MODE";
                break;
        case TK_A_OWNER_ID:
                r = asprintf(&s, "OWNER%s\"%u\"", op, (unsigned) token->key.uid);
                return r < 0 ? NULL : s;
        case TK_A_GROUP_ID:
                r = asprintf(&s, "GROUP%s\"%u\"", op, (unsigned) token->key.gid);
                return r < 0 ? NULL : s;
        case TK_A_MODE_ID:
                r = asprintf(&s, "MODE%s\"%#o\"", op, (unsigned) token->key.mode);
                return r < 0 ? NULL : s;
        case TK_A_SECLABEL:
                key = "SECLABEL";
                has_attr = true;
                break;
        case TK_A_RUN_BUILTIN:
                key = "RUN{builtin}";
                break;
        case TK_A_RUN_PROGRAM:
                key = "RUN{program}";
                break;
        case TK_A_GOTO:
                key = "GOTO";
                op = "=";
                break;
        default:
                return NULL;
        }

        if (option)
                r = asprintf(&s, "OPTIONS%s\"%s\"", op, option);
        else if (has_attr) {
                attr = escape_key_text(rules_str(rules, token->key.attr_off));
                if (!attr)
                        return NULL;
                r = asprintf(&s, "%s{%s}%s%s\"%s\"", key, attr, op, token->key.case_insensitive ? "i" : "", value);
        } else
                r = asprintf(&s, "%s%s%s\"%s\"", key, op, token->key.case_insensitive ? "i" : "", value);

        return r < 0 ? NULL : s;
}

#ifdef DEBUG
/* Logs the token, with the text of token_to_string() for the keys. */
static void dump_token(struct udev_rules *rules, struct token *token) {
        _cleanup_free_ char *s = NULL;

        switch (token->type) {
        case TK_RULE:
                log_debug("* RULE %s:%u, token: %u, count: %u, label: '%s'",
                          rules_str(rules, token->rule.filename_off), token->rule.filename_line,
                          (unsigned) (token - rules->tokens), token->rule.token_count,
                          rules_str(rules, token->rule.label_off));
                break;
        case TK_END:
                log_debug("* END");
                break;
        default:
                s = token_to_string(rules, token);
                if (s)
                        log_debug("%s", s);
                else
                        log_debug("unknown type %u", token->type);
                break;
        }
}

static void dump_rules(struct udev_rules *rules) {
        unsigned int i;

        log_debug("dumping %u tokens (%zu bytes), %zu strings (%zu bytes)",
                  rules->token_cur,
                  rules->token_cur * sizeof(struct token),
                  rules->strbuf->in_count,
                  rules->strbuf->in_len);
        for (i = 0; i < rules->token_cur; i++)
                dump_token(rules, &rules->tokens[i]);
}
#else
static inline void dump_token(struct udev_rules *rules __attribute__((unused)), struct token *token __attribute__((unused))) {}
static inline void dump_rules(struct udev_rules *rules __attribute__((unused))) {}
#endif /* DEBUG */

/* Like systemd's trace logs of 'udevadm test --verbose' (event->trace): a message about the rule
 * line of the token, prefixed like the other messages about applying a rule with the device name and
 * the file name and line number, see log_event_full_errno(). */
_printf_(4, 5)
static void trace_line(struct udev_event *event, struct udev_rules *rules, struct token *rule, const char *format, ...) {
        _cleanup_free_ char *message = NULL;
        va_list ap;
        int r;

        if (!event->trace)
                return;

        va_start(ap, format);
        r = vasprintf(&message, format, ap);
        va_end(ap);
        if (r < 0)
                return;

        log_event_debug(event, rules, rule, NULL, "%s", message);
}

/* Logs the tokens that the parent devices are checked against. */
static void trace_parent_tokens(struct udev_event *event, struct udev_rules *rules, struct token *rule,
                                struct token *first, struct token *end) {
        _cleanup_free_ char *joined = NULL;
        struct token *token;

        if (!event->trace)
                return;

        for (token = first; token < end; token++) {
                _cleanup_free_ char *s = NULL;
                char *n;

                s = token_to_string(rules, token);
                if (!s)
                        continue;

                n = strjoin(joined ?: "", joined ? ", " : "", s, NULL);
                if (!n)
                        return;
                free(joined);
                joined = n;
        }

        trace_line(event, rules, rule, "Checking conditions for parent devices (including self): %s", strna(joined));
}

static int add_token(struct udev_rules *rules, struct token *token) {
        /* grow buffer if needed */
        if (rules->token_cur+1 >= rules->token_max) {
                struct token *tokens;
                unsigned int add;

                /* double the buffer size */
                add = rules->token_max;
                if (add < 8)
                        add = 8;

                tokens = realloc(rules->tokens, (rules->token_max + add ) * sizeof(struct token));
                if (tokens == NULL)
                        return -1;
                rules->tokens = tokens;
                rules->token_max += add;
        }
        memcpy(&rules->tokens[rules->token_cur], token, sizeof(struct token));
        rules->token_cur++;
        return 0;
}

/* The ID of the nobody user and group, and the range of the IDs of the foreign users and groups of
 * systemd, with the base of the --with-foreign-uid-base option of configure, which systemd synthesizes
 * when the database does not know them. */
#define UID_NOBODY              ((uid_t) 65534U)
#define GID_NOBODY              ((gid_t) 65534U)
assert_cc((FOREIGN_UID_BASE & 0xFFFFU) == 0);
#define FOREIGN_UID_MIN         ((uid_t) FOREIGN_UID_BASE + 0U)
#define FOREIGN_UID_MAX         ((uid_t) FOREIGN_UID_BASE + 0xFFFFU)

static bool uid_is_foreign(uid_t uid) {
        return uid >= FOREIGN_UID_MIN && uid <= FOREIGN_UID_MAX;
}

/* Like synthesize_nobody() of systemd: the nobody user and group are synthesized, unless the file
 * /etc/systemd/dont-synthesize-nobody, or eudev's own UDEV_CONF_DIR "/dont-synthesize-nobody", exists, for
 * the compatibility with systems that use the name of the nobody user or group for another ID than 65534.
 *
 * Like in systemd, the cache is not synchronized: in the worst case, threads find it out twice, with the
 * same result. */
static bool synthesize_nobody(void) {
        static int cache = -1;

        if (cache < 0)
                cache = access("/etc/systemd/dont-synthesize-nobody", F_OK) < 0 &&
                        access(UDEV_CONF_DIR "/dont-synthesize-nobody", F_OK) < 0;

        return cache;
}

/* Like valid_user_group_name(u, VALID_USER_RELAX) of systemd. */
static bool valid_user_group_name_relaxed(const char *u) {
        if (isempty(u))
                return false;

        /* something that parses as numeric user ID is no name */
        if (parse_uid(u, NULL) >= 0)
                return false;

        if (startswith(u, " ") || endswith(u, " "))
                return false;
        if (!utf8_is_valid(u))
                return false;
        if (string_has_cc(u, NULL))
                return false;
        if (strpbrk(u, ":/"))
                return false;
        if (in_charset(u, DIGITS))
                return false;
        if (u[0] == '-' && in_charset(u + 1, DIGITS))
                return false;
        if (streq(u, ".") || streq(u, ".."))
                return false;

        return true;
}

/* The ID of a foreign user or group of systemd, named "foreign-N", with N up to 65535. */
static bool name_is_foreign(const char *name, uid_t *ret) {
        const char *e;
        uid_t id;

        e = startswith(name, "foreign-");
        if (!e || parse_uid(e, &id) < 0 || id > 0xFFFF)
                return false;

        *ret = FOREIGN_UID_MIN + id;
        return true;
}

/* Resolves a user or group like userdb_by_name() and groupdb_by_name() of systemd with USERDB_PARSE_NUMERIC
 * and USERDB_SYNTHESIZE_NUMERIC do it, from the user and group database of NSS: a name that is a valid ID is
 * looked up by the ID, any other name must be valid. When the database does not know it, like systemd
 * synthesizes them, the ID 0 and the name "root", the ID 65534 and the name of the nobody user or group of
 * configure, "nobody" by default, unless synthesize_nobody() says no, the IDs of the foreign range of systemd
 * and the names "foreign-N", and the IDs of system accounts are taken as they are. Returns -EINVAL for a name
 * that is not valid, and -ESRCH for an unknown one. */
static int resolve_user_or_group(const char *name, bool group, uid_t *ret) {
        uid_t id;

        assert(name);
        assert(ret);

        if (parse_uid(name, &id) >= 0) {
                if (group) {
                        struct group *g = getgrgid(id);

                        if (g) {
                                *ret = g->gr_gid;
                                return 0;
                        }
                } else {
                        struct passwd *p = getpwuid(id);

                        if (p) {
                                *ret = p->pw_uid;
                                return 0;
                        }
                }

                if (id == 0 ||
                    (id == (group ? GID_NOBODY : UID_NOBODY) && synthesize_nobody()) ||
                    uid_is_foreign(id) ||
                    (group ? gid_is_system(id) : uid_is_system(id))) {
                        *ret = id;
                        return 0;
                }
                return -ESRCH;
        }

        if (!valid_user_group_name_relaxed(name))
                return -EINVAL;

        if (group) {
                struct group *g = getgrnam(name);

                if (g) {
                        *ret = g->gr_gid;
                        return 0;
                }
        } else {
                struct passwd *p = getpwnam(name);

                if (p) {
                        *ret = p->pw_uid;
                        return 0;
                }
        }

        if (streq(name, "root")) {
                *ret = 0;
                return 0;
        }
        if (streq(name, group ? NOBODY_GROUP_NAME : NOBODY_USER_NAME) && synthesize_nobody()) {
                *ret = group ? GID_NOBODY : UID_NOBODY;
                return 0;
        }
        if (name_is_foreign(name, ret))
                return 0;

        return -ESRCH;
}

/* Like systemd, device nodes should be owned by system accounts. */
#define NON_SYSTEM_ACCOUNT_WARNING(Kind, kind)                                                          \
        Kind " %s configured to own a device node is not a system " kind ". "                           \
        "Support for device node ownership by non-system accounts is deprecated and will be removed in the future."

/* Like STRERROR_USER() and STRERROR_GROUP() of systemd. Like STRERROR() of systemd, the message of another
 * error is taken with strerror_r() into the buffer, as strerror() is not thread-safe. */
#define ERRNO_BUF_LEN 1024
#define STRERROR_USER_GROUP(error, group) \
        strerror_user_group((error), (group), (char[ERRNO_BUF_LEN]) { 0 }, ERRNO_BUF_LEN)

static const char *strerror_user_group(int error, bool group, char *buf, size_t size) {
        switch (abs(error)) {
        case ESRCH:
                return group ? "Unknown group" : "Unknown user";
        case ENOEXEC:
                return group ? "Not a system group" : "Not a system user";
        default:
#ifdef STRERROR_R_CHAR_P
                /* the GNU strerror_r() of glibc returns the message, maybe a static one */
                return strerror_r(abs(error), buf, size);
#else
                /* the POSIX strerror_r(), e.g. of musl */
                if (strerror_r(abs(error), buf, size) != 0)
                        (void) snprintf(buf, size, "Unknown error %i", abs(error));
                return buf;
#endif
        }
}

/* Like rule_resolve_user() and rule_resolve_group() of systemd: resolves a user or group of a rule while the
 * rules are read, and remembers it for the next rules. A user or group that cannot be resolved is an error:
 * -ESRCH for one that does not exist, and -EINVAL for an invalid value; the caller drops the key then. Other
 * errors, e.g. -ENOMEM, make the caller drop the rule line. */
static int rule_resolve_user_or_group(struct udev_rules *rules, const char *name, bool group, uid_t *ret) {
        struct uid_gid **cache = group ? &rules->gids : &rules->uids;
        unsigned int *cur = group ? &rules->gids_cur : &rules->uids_cur;
        unsigned int *max = group ? &rules->gids_max : &rules->uids_max;
        unsigned int i;
        uid_t id;
        int r;

        /* lookup, if we know it already */
        for (i = 0; i < *cur; i++)
                if (streq(rules_str(rules, (*cache)[i].name_off), name)) {
                        *ret = (*cache)[i].uid;
                        return 0;
                }

        r = resolve_user_or_group(name, group, &id);
        if (r < 0)
                return log_rule_error_errno(r, "Failed to resolve %s '%s', ignoring: %s",
                                            group ? "group" : "user", name, STRERROR_USER_GROUP(r, group));
        if (group && !gid_is_system(id))
                log_rule_warning_no_issue(NON_SYSTEM_ACCOUNT_WARNING("Group", "group"), name);
        else if (!group && !uid_is_system(id))
                log_rule_warning_no_issue(NON_SYSTEM_ACCOUNT_WARNING("User", "user"), name);

        /* grow buffer if needed */
        if (*cur + 1 >= *max) {
                struct uid_gid *ids;
                unsigned int add;

                /* double the buffer size */
                add = *max;
                if (add < 1)
                        add = 8;

                ids = realloc(*cache, (*max + add) * sizeof(struct uid_gid));
                if (!ids)
                        return log_oom();
                *cache = ids;
                *max += add;
        }

        r = rules_add_string(rules, name, &(*cache)[*cur].name_off);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                return log_rule_error_errno(r, "Failed to remember %s '%s': %m", group ? "group" : "user", name);

        (*cache)[*cur].uid = id;
        (*cur)++;

        *ret = id;
        return 0;
}

/* Whether a value of a rule has no substitutions, like rule_get_substitution_type() of systemd. */
static bool value_is_plain(const char *value) {
        return value[0] != '[' && !strchr(value, '%') && !strchr(value, '$');
}

/* Adds a property imported by the rule to the device of the event. Failures are logged. Only -ENOMEM is
 * fatal, like in systemd it stops the processing of the rules for the event, see
 * udev_rules_apply_to_event(). */
static int import_property(struct udev_event *event, struct udev_rules *rules, struct token *rule,
                           struct token *token, const char *key, const char *val) {
        int r;

        r = udev_device_add_property(event->dev, key, val);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                _cleanup_free_ char *k = cescape(key), *v = cescape(val ?: "");

                log_event_warning_errno(event, rules, rule, token, r, "Failed to import property \"%s=%s\", ignoring: %m",
                                        k ?: key, v ?: "");
        } else
                log_event_trace(event, rules, rule, token, "Imported property \"%s=%s\".", key, val ?: "");
        return r;
}

/* Imports a "KEY=VALUE" line. Lines that are empty, comments or invalid are skipped. Returns -ENOMEM
 * when out of memory, 0 otherwise. */
static int import_property_from_string(struct udev_event *event, struct udev_rules *rules, struct token *rule,
                                       struct token *token, char *line) {
        char *key;
        char *val;
        size_t len;
        int r;

        /* find key */
        key = line;
        while (isspace((unsigned char) key[0]))
                key++;

        /* comment or empty line */
        if (key[0] == '#' || key[0] == '\0')
                return 0;

        /* split key/value */
        val = strchr(key, '=');
        if (val == NULL)
                return 0;
        val[0] = '\0';
        val++;

        /* find value */
        while (isspace((unsigned char) val[0]))
                val++;

        /* terminate key */
        len = strlen(key);
        if (len == 0)
                return 0;
        while (isspace((unsigned char) key[len-1]))
                len--;
        key[len] = '\0';

        /* terminate value */
        len = strlen(val);
        if (len == 0)
                return 0;
        while (isspace((unsigned char) val[len-1]))
                len--;
        val[len] = '\0';

        if (len == 0)
                return 0;

        /* unquote */
        if (val[0] == '"' || val[0] == '\'') {
                if (len == 1 || val[len-1] != val[0]) {
                        _cleanup_free_ char *escaped = cescape(val);

                        /* the line is split into the key and the value by now */
                        log_event_debug_errno(event, rules, rule, token, EINVAL,
                                              "Failed to parse key and value from '%s=%s', ignoring: %m",
                                              key, escaped ?: val);
                        return 0;
                }
                val[len-1] = '\0';
                val++;
        }

        r = import_property(event, rules, rule, token, key, val);
        return r == -ENOMEM ? r : 0;
}

/* Like IMPORT{file} of systemd-udevd: returns 1 when the file was imported, 0 when it does not exist
 * or could not be read, and the key does not match, or a negative error when it cannot be opened or
 * when out of memory, which stops the processing of the rules for the event. */
static int import_file_into_properties(struct udev_event *event, struct udev_rules *rules, struct token *rule,
                                       struct token *token, const char *import) {
        _cleanup_fclose_ FILE *f = NULL;

        f = fopen(import, "re");
        if (f == NULL) {
                if (errno == ENOENT)
                        return 0;
                return log_event_error_errno(event, rules, rule, token, errno, "Failed to open \"%s\": %m", import);
        }

        /* Like systemd-udevd: lines of up to 1 MiB. A longer line, or a read error, stops the import,
         * and the key does not match; the properties imported before stay. */
        for (;;) {
                _cleanup_free_ char *line = NULL;
                int r;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0) {
                        log_event_debug_errno(event, rules, rule, token, r, "Failed to read \"%s\", ignoring: %m", import);
                        return 0;
                }
                if (r == 0)
                        return 1;

                r = import_property_from_string(event, rules, rule, token, line);
                if (r < 0)
                        return r;
        }
}

/* Returns 1 when the output of the program was imported, 0 when the program failed, and the key does
 * not match, or -ENOMEM when out of memory, which stops the processing of the rules for the event. */
static int import_program_into_properties(struct udev_event *event, struct udev_rules *rules, struct token *rule,
                                          struct token *token,
                                          usec_t timeout_usec,
                                          const char *program, const sigset_t *sigmask) {
        struct udev_device *dev = event->dev;
        char **envp;
        _cleanup_free_ char *result = NULL;
        char *line;
        bool truncated = false;
        int err;

        result = malloc(IMPORT_PROGRAM_SIZE);
        if (result == NULL)
                return log_oom();

        envp = udev_device_get_properties_envp(dev);
        err = udev_event_spawn(event, timeout_usec, program, envp, sigmask, result, IMPORT_PROGRAM_SIZE, &truncated);
        if (err < 0)
                return 0;

        if (truncated) {
                log_event_debug(event, rules, rule, token,
                                "Result of \"%s\" is too long and truncated, ignoring the last line of the result.",
                                program);

                /* Drop the last line. */
                line = strrchr(result, '\n');
                if (line)
                        line[0] = '\0';
                else
                        result[0] = '\0';
        }

        line = result;
        while (line != NULL) {
                char *pos;

                pos = strchr(line, '\n');
                if (pos != NULL) {
                        pos[0] = '\0';
                        pos = &pos[1];
                }
                err = import_property_from_string(event, rules, rule, token, line);
                if (err < 0)
                        return err;
                line = pos;
        }
        return 1;
}

/* Returns the number of imported properties, 0 also when the device has no parent, or -ENOMEM when out
 * of memory, which stops the processing of the rules for the event. */
static int import_parent_into_properties(struct udev_event *event, struct udev_rules *rules, struct token *rule,
                                         struct token *token, const char *filter) {
        struct udev_device *dev_parent;
        struct udev_list_entry *list_entry;
        int n = 0;

        dev_parent = udev_device_get_parent(event->dev);
        if (dev_parent == NULL)
                return 0;

        udev_list_entry_foreach(list_entry, udev_device_get_properties_list_entry(dev_parent)) {
                const char *key = udev_list_entry_get_name(list_entry);
                const char *val = udev_list_entry_get_value(list_entry);
                int r;

                if (fnmatch(filter, key, 0) != 0)
                        continue;

                r = import_property(event, rules, rule, token, key, val);
                if (r == -ENOMEM)
                        return r;
                if (r >= 0)
                        n++;
        }

        return n;
}

/* Like attr_subst_subdir() of systemd: replaces the first path component "*" of attr with the first
 * subdirectory in which the rest of the path exists. Returns 0 when attr has no such component or it was
 * replaced, -ENOENT when no subdirectory has the rest of the path, or when the path would be too long, and
 * the error when the directory cannot be opened. Unlike systemd, where only as many characters as the
 * directory has are left for the subdirectory and the rest of the path, so that it hardly ever finds
 * anything since v243, the room of the whole buffer is used. */
static int attr_subst_subdir(char attr[static UTIL_PATH_SIZE]) {
        _cleanup_closedir_ DIR *dir = NULL;
        char buf[UTIL_PATH_SIZE], *p;
        const char *tail;
        struct dirent *de;
        size_t len, size;
        bool truncated;

        tail = strstr(attr, "/*/");
        if (!tail)
                return 0;

        len = tail - attr + 1; /* include slash at the end */
        tail += 2; /* include slash at the beginning */

        p = buf;
        size = strnpcpy_full(&p, sizeof(buf), attr, len, &truncated);
        if (truncated)
                return -ENOENT;

        dir = opendir(buf);
        if (!dir)
                return -errno;

        for (de = readdir(dir); de; de = readdir(dir)) {
                if (de->d_name[0] == '.')
                        continue;

                strscpyl_full(p, size, &truncated, de->d_name, tail, NULL);
                if (truncated)
                        continue;

                if (faccessat(dirfd(dir), p, F_OK, 0) < 0)
                        continue;

                strcpy(attr, buf);
                return 0;
        }

        return -ENOENT;
}

/* Make the absolute canonical path 'path' relative to the absolute canonical directory 'dir',
 * like systemd's path_make_relative(). */
static int make_relative_path(const char *dir, const char *path, char *ret, size_t size) {
        size_t i, common = 0;
        const char *d;
        char *p = ret;

        /* find the longest common leading path, ending at a component boundary */
        for (i = 0; dir[i] != '\0' && dir[i] == path[i]; i++)
                if (dir[i] == '/')
                        common = i;
        if ((dir[i] == '\0' && IN_SET(path[i], '/', '\0')) ||
            (path[i] == '\0' && dir[i] == '/'))
                common = i;

        ret[0] = '\0';

        /* go up once for each remaining component of dir */
        for (d = dir + common; *d != '\0'; d++)
                if (*d == '/')
                        size = strpcpy(&p, size, "../");

        if (size > 0)
                size = strpcpy(&p, size, path[common] == '/' ? path + common + 1 : path + common);
        if (size == 0)
                return -ENAMETOOLONG;

        return 0;
}

/* like systemd's verify_regular_at(AT_FDCWD, path, follow) */
static int verify_regular(const char *path, bool follow) {
        struct stat st;

        if ((follow ? stat(path, &st) : lstat(path, &st)) < 0)
                return -errno;
        if (S_ISDIR(st.st_mode))
                return -EISDIR;
        if (S_ISLNK(st.st_mode))
                return -ELOOP;
        if (!S_ISREG(st.st_mode))
                return -EBADFD;
        return 0;
}

/* Parses the next KEY{attribute}<operator>"value" of a rule, like parse_line() of systemd: the key ends
 * at whitespace, '=', '{' or an operator, the attribute is everything up to the closing brace, e.g.
 * ATTR{a b} and ATTR{a=b} are fine, and whitespace may precede and follow the operator. Returns 1 and
 * moves *line behind the value, 0 at the end of the line, or -EINVAL for a syntax error, with *line
 * unchanged. */
static int get_key(char **line, char **ret_key, char **ret_attr, enum operation_type *op, char **value,
                   bool *is_case_insensitive) {
        char *linepos;
        char *key, *key_end, *attr = NULL;
        unsigned i, j;
        bool is_escaped = false;
        const char *k;

        key = *line + strspn(*line, WHITESPACE ",");
        if (key[0] == '\0')
                return 0;

        for (key_end = key; ; key_end++) {
                if (key_end[0] == '\0')
                        return -EINVAL;
                if (strchr(WHITESPACE "={", key_end[0]))
                        break;
                if (strchr("+-!:", key_end[0]) && key_end[1] == '=')
                        break;
        }

        if (key_end[0] == '{') {
                attr = key_end + 1;
                linepos = strchr(attr, '}');
                if (!linepos)
                        return -EINVAL;
                *(linepos++) = '\0';
        } else
                linepos = key_end;

        /* skip whitespace after key */
        linepos += strspn(linepos, WHITESPACE);

        /* get operation type */
        if (linepos[0] == '=' && linepos[1] == '=') {
                *op = OP_MATCH;
                linepos += 2;
        } else if (linepos[0] == '!' && linepos[1] == '=') {
                *op = OP_NOMATCH;
                linepos += 2;
        } else if (linepos[0] == '+' && linepos[1] == '=') {
                *op = OP_ADD;
                linepos += 2;
        } else if (linepos[0] == '-' && linepos[1] == '=') {
                *op = OP_REMOVE;
                linepos += 2;
        } else if (linepos[0] == '=') {
                *op = OP_ASSIGN;
                linepos++;
        } else if (linepos[0] == ':' && linepos[1] == '=') {
                *op = OP_ASSIGN_FINAL;
                linepos += 2;
        } else
                return -EINVAL;

        /* terminate key */
        key_end[0] = '\0';

        /* skip whitespace after operator */
        linepos += strspn(linepos, WHITESPACE);

        /* check if the value is prefixed with:
         * - "e" for C-style escaped strings
         * - "i" for case insensitive match
         *
         * Note both e and i can be set but do not allow duplicates ("eei", "eii"). */
        *is_case_insensitive = false;
        for (k = linepos; *k != '"' && k < linepos + 2; k++)
                if (*k == 'e' && !is_escaped)
                        is_escaped = true;
                else if (*k == 'i' && !*is_case_insensitive)
                        *is_case_insensitive = true;
                else
                        return -EINVAL;
        linepos += is_escaped + *is_case_insensitive;

        /* value must be double quotated */
        if (linepos[0] == '"')
                linepos++;
        else
                return -EINVAL;
        *value = linepos;

        if (!is_escaped) {
                /* terminate */
                for (i = 0, j = 0; ; i++, j++) {

                        if (linepos[i] == '"')
                                break;

                        if (linepos[i] == '\0')
                                return -EINVAL;

                        /* double quotes can be escaped */
                        if (linepos[i] == '\\')
                                if (linepos[i+1] == '"')
                                        i++;

                        linepos[j] = linepos[i];
                }
                linepos[j] = '\0';
        } else {
                _cleanup_free_ char *unescaped = NULL;
                int r;

                /* find the end position of value */
                for (i = 0; linepos[i] != '"'; i++) {
                        if (linepos[i] == '\\')
                                i++;
                        if (linepos[i] == '\0')
                                return -EINVAL;
                }
                linepos[i] = '\0';

                r = cunescape_length(linepos, i, 0, &unescaped);
                if (r < 0)
                        return -EINVAL;
                assert((unsigned) r <= i);
                memcpy(linepos, unescaped, r + 1);
        }

        /* move line to next key */
        *line = linepos + i + 1;
        *ret_key = key;
        *ret_attr = attr;
        return 1;
}

static int rule_add_key(struct rule_tmp *rule_tmp, enum token_type type,
                        enum operation_type op,
                        const char *value, const void *data) {
        struct token *token;
        const char *attr = NULL;
        int r = 0;

        /* Most callers do not check the result, add_rule() drops the rule then. */
        if (rule_tmp->failed)
                return -EINVAL;
        if (1 + rule_tmp->token_cur + 1 > RULE_TOKENS_MAX) {
                log_rule_error("The rule has more than %u keys, ignoring.", RULE_TOKENS_MAX - 1);
                rule_tmp->failed = true;
                return -E2BIG;
        }
        if (!GREEDY_REALLOC(rule_tmp->token, rule_tmp->token_allocated, rule_tmp->token_cur + 1)) {
                rule_tmp->failed = true;
                return log_oom();
        }

        token = &rule_tmp->token[rule_tmp->token_cur];
        memzero(token, sizeof(struct token));

        if (type < TK_M_MAX)
                token->key.case_insensitive = rule_tmp->case_insensitive;

        switch (type) {
        case TK_M_ACTION:
        case TK_M_DEVPATH:
        case TK_M_KERNEL:
        case TK_M_SUBSYSTEM:
        case TK_M_DRIVER:
        case TK_M_DEVLINK:
        case TK_M_NAME:
        case TK_M_KERNELS:
        case TK_M_SUBSYSTEMS:
        case TK_M_DRIVERS:
        case TK_M_TAGS:
        case TK_M_PROGRAM:
        case TK_M_IMPORT_FILE:
        case TK_M_IMPORT_PROG:
        case TK_M_IMPORT_DB:
        case TK_M_IMPORT_CMDLINE:
        case TK_M_IMPORT_PARENT:
        case TK_M_RESULT:
        case TK_A_OWNER:
        case TK_A_GROUP:
        case TK_A_MODE:
        case TK_A_DEVLINK:
        case TK_A_NAME:
        case TK_A_GOTO:
        case TK_M_TAG:
        case TK_A_TAG:
        case TK_A_STATIC_NODE:
                r = rules_add_string(rule_tmp->rules, value, &token->key.value_off);
                break;
        case TK_M_IMPORT_BUILTIN:
                r = rules_add_string(rule_tmp->rules, value, &token->key.value_off);
                token->key.builtin_cmd = *(enum udev_builtin_cmd *)data;
                break;
        case TK_M_ENV:
        case TK_M_ATTR:
        case TK_M_SYSCTL:
        case TK_M_ATTRS:
        case TK_A_ATTR:
        case TK_A_SYSCTL:
        case TK_A_ENV:
        case TK_A_SECLABEL:
                attr = data;
                r = rules_add_string(rule_tmp->rules, value, &token->key.value_off);
                if (r >= 0)
                        r = rules_add_string(rule_tmp->rules, attr, &token->key.attr_off);
                break;
        case TK_M_TEST:
                r = rules_add_string(rule_tmp->rules, value, &token->key.value_off);
                /* like systemd, TEST{} without a mode checks only whether the file exists */
                token->key.mode = data ? *(mode_t *)data : MODE_INVALID;
                break;
        case TK_A_DUMP:
                token->key.dump_flags = *(JsonFormatFlags *)data;
                break;
        case TK_A_STRING_ESCAPE_NONE:
        case TK_A_STRING_ESCAPE_REPLACE:
        case TK_A_DB_PERSIST:
        case TK_A_NET_ALTNAMES:
                break;
        case TK_A_RUN_BUILTIN:
        case TK_A_RUN_PROGRAM:
                token->key.builtin_cmd = *(enum udev_builtin_cmd *)data;
                r = rules_add_string(rule_tmp->rules, value, &token->key.value_off);
                break;
        case TK_A_INOTIFY_WATCH:
        case TK_A_DEVLINK_PRIO:
                token->key.devlink_prio = *(int *)data;
                break;
        case TK_A_LOG_LEVEL:
                token->key.log_level = *(int *)data;
                break;
        case TK_A_OWNER_ID:
                token->key.uid = *(uid_t *)data;
                break;
        case TK_A_GROUP_ID:
                token->key.gid = *(gid_t *)data;
                break;
        case TK_A_MODE_ID:
                token->key.mode = *(mode_t *)data;
                break;
        case TK_RULE:
        case TK_M_PARENTS_MIN:
        case TK_M_PARENTS_MAX:
        case TK_M_MAX:
        case TK_END:
        case TK_UNSET:
                log_rule_error("wrong type %u", type);
                return -1;
        }

        /* Like systemd, which drops the rule line when it cannot add a token, drop the rule, see
         * add_rule(). */
        if (r < 0) {
                rule_tmp->failed = true;
                if (r == -ENOMEM)
                        return log_oom();
                return log_rule_error_errno(r, "Failed to add the key: %m");
        }

        if (value != NULL && type < TK_M_MAX) {
                /* check if we need to split or call fnmatch() while matching rules */
                enum string_glob_type glob;
                int has_split;
                int has_glob;

                has_split = (strchr(value, '|') != NULL);
                has_glob = string_is_glob(value);
                if (has_split && has_glob) {
                        glob = GL_SPLIT_GLOB;
                } else if (has_split) {
                        glob = GL_SPLIT;
                } else if (has_glob) {
                        if (streq(value, "?*"))
                                glob = GL_SOMETHING;
                        else
                                glob = GL_GLOB;
                } else {
                        glob = GL_PLAIN;
                }
                token->key.glob = glob;
        }

        if (value != NULL && type > TK_M_MAX) {
                /* check if assigned value has substitution chars */
                if (value[0] == '[')
                        token->key.subst = SB_SUBSYS;
                else if (strchr(value, '%') != NULL || strchr(value, '$') != NULL)
                        token->key.subst = SB_FORMAT;
                else
                        token->key.subst = SB_NONE;
        }

        if (attr != NULL) {
                /* check if property/attribute name has substitution chars */
                if (attr[0] == '[')
                        token->key.attrsubst = SB_SUBSYS;
                else if (strchr(attr, '%') != NULL || strchr(attr, '$') != NULL)
                        token->key.attrsubst = SB_FORMAT;
                else
                        token->key.attrsubst = SB_NONE;
        }

        token->key.type = type;
        token->key.op = op;
        rule_tmp->token_cur++;

        /* Like the line types of rule_line_add_token() of systemd, which udev_rules_apply_to_event() uses to
         * skip the rules that cannot do anything for the event. A GOTO without its LABEL is cleared in
         * parse_file(). */
        if (type == TK_A_NAME)
                rule_tmp->rule.rule.has_name = true;
        else if (IN_SET(type, TK_A_DEVLINK, TK_A_OWNER, TK_A_GROUP, TK_A_MODE, TK_A_OWNER_ID, TK_A_GROUP_ID,
                        TK_A_MODE_ID))
                rule_tmp->rule.rule.has_devlink = true;
        else if (type == TK_A_STATIC_NODE)
                rule_tmp->rule.rule.has_static_node = true;
        else if (type == TK_A_GOTO)
                rule_tmp->rule.rule.has_goto = true;
        else if (type > TK_M_MAX ||
                 IN_SET(type, TK_M_PROGRAM, TK_M_IMPORT_FILE, TK_M_IMPORT_PROG, TK_M_IMPORT_BUILTIN,
                        TK_M_IMPORT_DB, TK_M_IMPORT_CMDLINE, TK_M_IMPORT_PARENT))
                rule_tmp->rule.rule.update_something = true;
        return 0;
}

static int sort_token(struct udev_rules *rules, struct rule_tmp *rule_tmp) {
        size_t i;
        size_t start = 0;
        size_t end = rule_tmp->token_cur;

        for (i = 0; i < rule_tmp->token_cur; i++) {
                enum token_type next_val = TK_UNSET;
                size_t next_idx = 0;
                size_t j;

                /* find smallest value */
                for (j = start; j < end; j++) {
                        if (rule_tmp->token[j].type == TK_UNSET)
                                continue;
                        if (next_val == TK_UNSET || rule_tmp->token[j].type < next_val) {
                                next_val = rule_tmp->token[j].type;
                                next_idx = j;
                        }
                }

                /* add token and mark done */
                if (add_token(rules, &rule_tmp->token[next_idx]) != 0)
                        return -1;
                rule_tmp->token[next_idx].type = TK_UNSET;

                /* shrink range */
                if (next_idx == start)
                        start++;
                if (next_idx+1 == end)
                        end--;
        }
        return 0;
}

/* Parses the comma separated values of OPTIONS=. An unknown value is ignored with a warning, like
 * systemd-udevd does. Returns -EINVAL when the line is invalid, and -EOPNOTSUPP when it uses a
 * systemd-only value and is ignored. */
static int parse_options(struct rule_tmp *rule_tmp, enum operation_type op, const char *value) {
        const char *p = value;

        for (;;) {
                _cleanup_free_ char *word = NULL;
                const struct option_def *o;
                const char *arg = NULL;
                size_t n = strcspn(p, ",");
                bool last = p[n] == '\0';

                word = strndup(p, n);
                if (!word)
                        return log_oom();
                p += last ? n : n + 1;

                o = option_lookup(word, &arg);
                if (!o) {
                        _cleanup_free_ char *escaped = NULL;

                        if (is_systemd_only(SYSTEMD_ONLY_OPTION, word, strcspn(word, "="))) {
                                _cleanup_free_ char *what = NULL;

                                if (asprintf(&what, "OPTIONS=\"%s\"", word) < 0)
                                        what = NULL;
                                log_systemd_only(SYSTEMD_ONLY_OPTION, what ?: word);
                                return -EOPNOTSUPP;
                        }

                        escaped = cescape(word);
                        log_rule_warning("Invalid value for OPTIONS key, ignoring: '%s'", escaped ?: word);
                } else
                        switch (o->id) {
                        case OPTION_DUMP: {
                                const JsonFormatFlags flags = JSON_FORMAT_OFF;

                                rule_add_key(rule_tmp, TK_A_DUMP, op, NULL, &flags);
                                break;
                        }
                        case OPTION_DUMP_JSON: {
                                const JsonFormatFlags flags = JSON_FORMAT_NEWLINE;

                                rule_add_key(rule_tmp, TK_A_DUMP, op, NULL, &flags);
                                break;
                        }
                        case OPTION_STRING_ESCAPE_NONE:
                                rule_add_key(rule_tmp, TK_A_STRING_ESCAPE_NONE, op, NULL, NULL);
                                break;
                        case OPTION_STRING_ESCAPE_REPLACE:
                                rule_add_key(rule_tmp, TK_A_STRING_ESCAPE_REPLACE, op, NULL, NULL);
                                break;
                        case OPTION_DB_PERSIST:
                                rule_add_key(rule_tmp, TK_A_DB_PERSIST, op, NULL, NULL);
                                break;
                        case OPTION_NET_ALTNAMES:
                                rule_add_key(rule_tmp, TK_A_NET_ALTNAMES, op, NULL, NULL);
                                break;
                        case OPTION_WATCH:
                        case OPTION_NOWATCH: {
                                const int watch = o->id == OPTION_WATCH;

                                rule_add_key(rule_tmp, TK_A_INOTIFY_WATCH, op, NULL, &watch);
                                break;
                        }
                        case OPTION_STATIC_NODE:
                                rule_add_key(rule_tmp, TK_A_STATIC_NODE, op, arg, NULL);
                                break;
                        case OPTION_LINK_PRIORITY: {
                                int prio, r;

                                r = safe_atoi(arg, &prio);
                                if (r < 0) {
                                        log_rule_error_errno(r, "Failed to parse link priority '%s': %m", arg);
                                        return -EINVAL;
                                }
                                rule_add_key(rule_tmp, TK_A_DEVLINK_PRIO, op, NULL, &prio);
                                break;
                        }
                        case OPTION_LOG_LEVEL: {
                                int level;

                                if (streq(arg, "reset"))
                                        level = -1;
                                else {
                                        level = log_level_from_string(arg);
                                        if (level < 0) {
                                                log_rule_error_errno(EINVAL, "Failed to parse log level '%s': %m", arg);
                                                return -EINVAL;
                                        }
                                }
                                rule_add_key(rule_tmp, TK_A_LOG_LEVEL, op, NULL, &level);
                                break;
                        }
                        }

                if (last)
                        return 0;
        }
}

static int add_rule(struct udev_rules *rules, char *line,
                    unsigned int filename_off, unsigned int lineno) {
        char *linepos;
        struct rule_tmp rule_tmp;
        unsigned int first_token;

        memzero(&rule_tmp, sizeof(struct rule_tmp));
        rule_tmp.rules = rules;
        rule_tmp.rule.type = TK_RULE;
        rule_tmp.rule.rule.filename_off = filename_off;
        rule_tmp.rule.rule.filename_line = lineno;

        if (checking)
                udev_rules_check_line_begin(checking, lineno, line);

        linepos = line;
        for (;;) {
                char *key, *attr;
                char *value;
                enum operation_type op;
                bool is_case_insensitive;
                int r;

                if (checking)
                        udev_rules_check_delimiters(checking, linepos);

                /* The line ends after the last key, possibly after whitespace and stray commas, which
                 * systemd-udevd accepts as well. */
                r = get_key(&linepos, &key, &attr, &op, &value, &is_case_insensitive);
                if (r == 0)
                        break;
                if (r < 0) {
                        /* A parsing error. Drop the whole line, like systemd-udevd does, instead of
                         * applying only the keys before the error. */
                        log_rule_error("Invalid key/value pair, ignoring.");
                        if (linepos[strspn(linepos, WHITESPACE ",")] == '#')
                                log_rule_error("Hint: comments can only start at the beginning of a line.");
                        goto invalid;
                }

                if (checking)
                        udev_rules_check_token(checking, key, attr, check_op(op), value, is_case_insensitive);

                if (is_case_insensitive && op > OP_MATCH_MAX) {
                        log_rule_error("Invalid prefix 'i' for '%s'. The 'i' prefix can be specified only for '==' or '!=' operator.", key);
                        goto invalid;
                }
                rule_tmp.case_insensitive = is_case_insensitive;

                /* Like systemd, refuse an attribute of the keys that take none, and a missing or empty
                 * attribute of the keys that need one. TEST and RUN check theirs below. */
                if (attr && STR_IN_SET(key, "ACTION", "DEVPATH", "KERNEL", "SUBSYSTEM", "DRIVER",
                                       "KERNELS", "SUBSYSTEMS", "DRIVERS", "TAGS", "TAG", "PROGRAM",
                                       "RESULT", "LABEL", "GOTO", "NAME", "SYMLINK", "OWNER", "GROUP",
                                       "MODE", "OPTIONS")) {
                        log_rule_invalid_attr(key);
                        goto invalid;
                }
                if (isempty(attr) && STR_IN_SET(key, "ATTR", "SYSCTL", "SECLABEL", "ATTRS", "ENV", "IMPORT")) {
                        log_rule_invalid_attr(key);
                        goto invalid;
                }

                if (streq(key, "ACTION")) {
                        if (op > OP_MATCH_MAX) {
                                log_rule_invalid_op("ACTION");
                                goto invalid;
                        }
                        rule_add_key(&rule_tmp, TK_M_ACTION, op, value, NULL);
                        continue;
                }

                if (streq(key, "DEVPATH")) {
                        if (op > OP_MATCH_MAX) {
                                log_rule_invalid_op("DEVPATH");
                                goto invalid;
                        }
                        rule_add_key(&rule_tmp, TK_M_DEVPATH, op, value, NULL);
                        continue;
                }

                if (streq(key, "KERNEL")) {
                        if (op > OP_MATCH_MAX) {
                                log_rule_invalid_op("KERNEL");
                                goto invalid;
                        }
                        rule_add_key(&rule_tmp, TK_M_KERNEL, op, value, NULL);
                        continue;
                }

                if (streq(key, "SUBSYSTEM")) {
                        if (op > OP_MATCH_MAX) {
                                log_rule_invalid_op("SUBSYSTEM");
                                goto invalid;
                        }
                        /* bus, class, subsystem events should all be the same */
                        if (streq(value, "subsystem") ||
                            streq(value, "bus") ||
                            streq(value, "class")) {
                                if (streq(value, "bus") || streq(value, "class"))
                                        log_rule_warning("\"%s\" must be specified as \"subsystem\".", value);
                                rule_add_key(&rule_tmp, TK_M_SUBSYSTEM, op, "subsystem|class|bus", NULL);
                        } else
                                rule_add_key(&rule_tmp, TK_M_SUBSYSTEM, op, value, NULL);
                        continue;
                }

                if (streq(key, "DRIVER")) {
                        if (op > OP_MATCH_MAX) {
                                log_rule_invalid_op("DRIVER");
                                goto invalid;
                        }
                        rule_add_key(&rule_tmp, TK_M_DRIVER, op, value, NULL);
                        continue;
                }

                if (streq(key, "ATTR")) {
                        if (op == OP_REMOVE) {
                                log_rule_invalid_op("ATTR");
                                goto invalid;
                        }
                        if (op < OP_MATCH_MAX)
                                rule_add_key(&rule_tmp, TK_M_ATTR, op, value, attr);
                        else
                                rule_add_key(&rule_tmp, TK_A_ATTR, op, value, attr);
                        continue;
                }

                if (streq(key, "SYSCTL")) {
                        if (op == OP_REMOVE) {
                                log_rule_invalid_op("SYSCTL");
                                goto invalid;
                        }
                        if (op < OP_MATCH_MAX)
                                rule_add_key(&rule_tmp, TK_M_SYSCTL, op, value, attr);
                        else
                                rule_add_key(&rule_tmp, TK_A_SYSCTL, op, value, attr);
                        continue;
                }

                if (streq(key, "SECLABEL")) {
                        if (op < OP_MATCH_MAX || op == OP_REMOVE) {
                                log_rule_invalid_op("SECLABEL");
                                goto invalid;
                        }

                        rule_add_key(&rule_tmp, TK_A_SECLABEL, op, value, attr);
                        continue;
                }

                if (streq(key, "KERNELS")) {
                        if (op > OP_MATCH_MAX) {
                                log_rule_invalid_op("KERNELS");
                                goto invalid;
                        }
                        rule_add_key(&rule_tmp, TK_M_KERNELS, op, value, NULL);
                        continue;
                }

                if (streq(key, "SUBSYSTEMS")) {
                        if (op > OP_MATCH_MAX) {
                                log_rule_invalid_op("SUBSYSTEMS");
                                goto invalid;
                        }
                        rule_add_key(&rule_tmp, TK_M_SUBSYSTEMS, op, value, NULL);
                        continue;
                }

                if (streq(key, "DRIVERS")) {
                        if (op > OP_MATCH_MAX) {
                                log_rule_invalid_op("DRIVERS");
                                goto invalid;
                        }
                        rule_add_key(&rule_tmp, TK_M_DRIVERS, op, value, NULL);
                        continue;
                }

                if (streq(key, "ATTRS")) {
                        if (op > OP_MATCH_MAX) {
                                log_rule_invalid_op("ATTRS");
                                goto invalid;
                        }
                        if (startswith(attr, "device/"))
                                log_rule_warning("'device' link may not be available in future kernels.");
                        if (strstr(attr, "../"))
                                log_rule_warning("Direct reference to parent sysfs directory, may break in future kernels.");
                        rule_add_key(&rule_tmp, TK_M_ATTRS, op, value, attr);
                        continue;
                }

                if (streq(key, "TAGS")) {
                        if (op > OP_MATCH_MAX) {
                                log_rule_invalid_op("TAGS");
                                goto invalid;
                        }
                        rule_add_key(&rule_tmp, TK_M_TAGS, op, value, NULL);
                        continue;
                }

                if (streq(key, "ENV")) {
                        if (op == OP_REMOVE) {
                                log_rule_invalid_op("ENV");
                                goto invalid;
                        }
                        if (op < OP_MATCH_MAX) {
                                if (rule_add_key(&rule_tmp, TK_M_ENV, op, value, attr) != 0)
                                        goto invalid;
                        } else {
                                static const char *blacklist[] = {
                                        /* basic properties set by kernel, only in netlink event */
                                        "ACTION", "SEQNUM", "SYNTH_UUID",
                                        /* basic properties set by kernel, both in netlink event and uevent file */
                                        "DEVPATH", "DEVPATH_OLD", "SUBSYSTEM", "DEVTYPE", "DRIVER", "MODALIAS",
                                        /* device node */
                                        "DEVNAME", "DEVMODE", "DEVUID", "DEVGID", "MAJOR", "MINOR",
                                        /* block device */
                                        "DISKSEQ", "PARTN",
                                        /* network interface (INTERFACE_OLD is set by udevd) */
                                        "IFINDEX", "INTERFACE", "INTERFACE_OLD",
                                        /* basic properties set by udevd */
                                        "DEVLINKS", "TAGS", "CURRENT_TAGS", "USEC_INITIALIZED", "UDEV_DATABASE_VERSION",
                                };
                                unsigned int i;

                                for (i = 0; i < ELEMENTSOF(blacklist); i++) {
                                        if (!streq(attr, blacklist[i]))
                                                continue;
                                        log_rule_error("Invalid ENV attribute. '%s' cannot be set.", attr);
                                        goto invalid;
                                }
                                /* Similar to SYNTH_UUID, but set based on KEY=VALUE arguments passed by userspace.
                                 * See kernel's f36776fafbaa0094390dd4e7e3e29805e0b82730 (v4.13) */
                                if (startswith(attr, "SYNTH_ARG_")) {
                                        log_rule_error("Invalid ENV attribute. '%s' cannot be set.", attr);
                                        goto invalid;
                                }
                                if (rule_add_key(&rule_tmp, TK_A_ENV, op, value, attr) != 0)
                                        goto invalid;
                        }
                        continue;
                }

                if (streq(key, "TAG")) {
                        if (op < OP_MATCH_MAX)
                                rule_add_key(&rule_tmp, TK_M_TAG, op, value, NULL);
                        else
                                rule_add_key(&rule_tmp, TK_A_TAG, op, value, NULL);
                        continue;
                }

                if (streq(key, "PROGRAM")) {
                        if (is_case_insensitive) {
                                log_rule_invalid_prefix("PROGRAM");
                                goto invalid;
                        }
                        if (op == OP_REMOVE) {
                                log_rule_invalid_op("PROGRAM");
                                goto invalid;
                        }
                        if (check_disabled_builtin("PROGRAM", value))
                                goto ignore;
                        rule_add_key(&rule_tmp, TK_M_PROGRAM, op, value, NULL);
                        continue;
                }

                if (streq(key, "RESULT")) {
                        if (op > OP_MATCH_MAX) {
                                log_rule_invalid_op("RESULT");
                                goto invalid;
                        }
                        rule_add_key(&rule_tmp, TK_M_RESULT, op, value, NULL);
                        continue;
                }

                if (streq(key, "IMPORT")) {
                        if (op == OP_REMOVE) {
                                log_rule_invalid_op("IMPORT");
                                goto invalid;
                        }
                        if (is_case_insensitive) {
                                log_rule_invalid_prefix("IMPORT");
                                goto invalid;
                        }
                        if (streq(attr, "program")) {
                                /* find known built-in command */
                                if (value[0] != '/') {
                                        enum udev_builtin_cmd cmd;

                                        cmd = udev_builtin_lookup(value);
                                        if (cmd < UDEV_BUILTIN_MAX) {
                                                log_rule_debug("Found builtin command '%s' for IMPORT, replacing attribute.", value);
                                                rule_add_key(&rule_tmp, TK_M_IMPORT_BUILTIN, op, value, &cmd);
                                                continue;
                                        }
                                        /* systemd takes the command for its builtin */
                                        if (check_systemd_only_builtin("IMPORT{program}", value))
                                                goto ignore;
                                }
                                rule_add_key(&rule_tmp, TK_M_IMPORT_PROG, op, value, NULL);
                        } else if (streq(attr, "builtin")) {
                                enum udev_builtin_cmd cmd = udev_builtin_lookup(value);

                                if (cmd < UDEV_BUILTIN_MAX)
                                        rule_add_key(&rule_tmp, TK_M_IMPORT_BUILTIN, op, value, &cmd);
                                else if (check_systemd_only_builtin("IMPORT{builtin}", value))
                                        goto ignore;
                                else {
                                        log_rule_error("Unknown builtin command: %s", value);
                                        goto invalid;
                                }
                        } else if (streq(attr, "file")) {
                                rule_add_key(&rule_tmp, TK_M_IMPORT_FILE, op, value, NULL);
                        } else if (streq(attr, "db")) {
                                rule_add_key(&rule_tmp, TK_M_IMPORT_DB, op, value, NULL);
                        } else if (streq(attr, "cmdline")) {
                                rule_add_key(&rule_tmp, TK_M_IMPORT_CMDLINE, op, value, NULL);
                        } else if (streq(attr, "parent")) {
                                rule_add_key(&rule_tmp, TK_M_IMPORT_PARENT, op, value, NULL);
                        } else {
                                log_rule_invalid_attr("IMPORT");
                                goto invalid;
                        }
                        continue;
                }

                if (streq(key, "TEST")) {
                        mode_t mode = 0;

                        if (op > OP_MATCH_MAX) {
                                log_rule_invalid_op("TEST");
                                goto invalid;
                        }
                        if (is_case_insensitive) {
                                log_rule_invalid_prefix("TEST");
                                goto invalid;
                        }
                        /* like systemd, an invalid mode is an error, and TEST{} has no mode; unlike systemd,
                         * where TEST{0} never matches, a mask of 0 is an error too */
                        if (!isempty(attr)) {
                                r = parse_mode(attr, &mode);
                                if (r < 0) {
                                        log_rule_error_errno(r, "Failed to parse mode '%s': %m", attr);
                                        goto invalid;
                                }
                                if (mode == 0) {
                                        log_rule_error("Mode mask of TEST must not be zero, ignoring.");
                                        goto invalid;
                                }
                                rule_add_key(&rule_tmp, TK_M_TEST, op, value, &mode);
                        } else
                                rule_add_key(&rule_tmp, TK_M_TEST, op, value, NULL);
                        continue;
                }

                if (streq(key, "RUN")) {
                        const char *what = attr ? "RUN{program}" : "RUN";

                        if (!attr)
                                attr = (char *) "program";
                        if (op < OP_MATCH_MAX || op == OP_REMOVE) {
                                log_rule_invalid_op("RUN");
                                goto invalid;
                        }

                        if (streq(attr, "builtin")) {
                                enum udev_builtin_cmd cmd = udev_builtin_lookup(value);

                                if (cmd < UDEV_BUILTIN_MAX)
                                        rule_add_key(&rule_tmp, TK_A_RUN_BUILTIN, op, value, &cmd);
                                else if (check_systemd_only_builtin("RUN{builtin}", value))
                                        goto ignore;
                                else {
                                        log_rule_error("Unknown builtin command '%s', ignoring.", value);
                                        goto invalid;
                                }
                        } else if (streq(attr, "program")) {
                                enum udev_builtin_cmd cmd = UDEV_BUILTIN_MAX;

                                if (check_disabled_builtin(what, value))
                                        goto ignore;
                                rule_add_key(&rule_tmp, TK_A_RUN_PROGRAM, op, value, &cmd);
                        } else {
                                log_rule_invalid_attr("RUN");
                                goto invalid;
                        }

                        continue;
                }

                if (streq(key, "LABEL")) {
                        if (op != OP_ASSIGN) {
                                log_rule_invalid_op("LABEL");
                                goto invalid;
                        }
                        /* like systemd, the last LABEL counts */
                        if (rule_tmp.has_label)
                                log_rule_warning("Contains multiple LABEL keys, ignoring LABEL=\"%s\".",
                                                 rules_str(rules, rule_tmp.rule.rule.label_off));
                        rule_tmp.has_label = true;
                        r = rules_add_string(rules, value, &rule_tmp.rule.rule.label_off);
                        if (r == -ENOMEM) {
                                log_oom();
                                goto invalid;
                        }
                        if (r < 0) {
                                log_rule_error_errno(r, "Failed to add the key: %m");
                                goto invalid;
                        }
                        continue;
                }

                if (streq(key, "GOTO")) {
                        if (op != OP_ASSIGN) {
                                log_rule_invalid_op("GOTO");
                                goto invalid;
                        }
                        /* like systemd, only the first GOTO counts */
                        if (rule_tmp.has_goto) {
                                log_rule_warning("Contains multiple GOTO keys, ignoring GOTO=\"%s\".", value);
                                continue;
                        }
                        rule_tmp.has_goto = true;
                        rule_add_key(&rule_tmp, TK_A_GOTO, 0, value, NULL);
                        continue;
                }

                if (streq(key, "NAME")) {
                        if (op == OP_REMOVE) {
                                log_rule_invalid_op("NAME");
                                goto invalid;
                        }
                        if (op < OP_MATCH_MAX) {
                                rule_add_key(&rule_tmp, TK_M_NAME, op, value, NULL);
                        } else {
                                /* like systemd, drop the line */
                                if (streq(value, "%k")) {
                                        log_rule_error("Ignoring NAME=\"%%k\", as it will take no effect.");
                                        goto invalid;
                                }
                                if (value[0] == '\0') {
                                        log_rule_error("Ignoring NAME=\"\", as udev will not delete any network interfaces.");
                                        goto invalid;
                                }
                                rule_add_key(&rule_tmp, TK_A_NAME, op, value, NULL);
                        }
                        continue;
                }

                if (streq(key, "SYMLINK")) {
                        if (op < OP_MATCH_MAX)
                                rule_add_key(&rule_tmp, TK_M_DEVLINK, op, value, NULL);
                        else
                                rule_add_key(&rule_tmp, TK_A_DEVLINK, op, value, NULL);
                        continue;
                }

                if (streq(key, "OWNER") || streq(key, "GROUP")) {
                        bool group = streq(key, "GROUP");
                        uid_t id;

                        if (op < OP_MATCH_MAX || op == OP_REMOVE) {
                                log_rule_invalid_op(key);
                                goto invalid;
                        }

                        /* Like systemd: a number, which must be a valid ID, also an empty value, and a name
                         * without substitutions when names are resolved early, are resolved now. Other values
                         * are resolved whenever the rule is applied, and ignored when names are never
                         * resolved. Unlike systemd, which drops the line, a user or group that does not
                         * exist, and an invalid value, e.g. an empty one or a number with leading zeros, drop
                         * only this key, like an invalid MODE, so that the rest of the line, e.g. MODE or
                         * SYMLINK, still applies on a system that lacks a user or group of the rules. */
                        if (in_charset(value, DIGITS) || (rules->resolve_names > 0 && value_is_plain(value))) {
                                r = rule_resolve_user_or_group(rules, value, group, &id);
                                if (IN_SET(r, -ESRCH, -EINVAL)) {
                                        if (checking)
                                                udev_rules_check_key_dropped(checking);
                                        continue;
                                }
                                if (r < 0)
                                        goto invalid;
                                rule_add_key(&rule_tmp, group ? TK_A_GROUP_ID : TK_A_OWNER_ID, op, NULL, &id);
                        } else if (rules->resolve_names >= 0)
                                rule_add_key(&rule_tmp, group ? TK_A_GROUP : TK_A_OWNER, op, value, NULL);
                        else {
                                if (group)
                                        log_rule_debug("Resolving group name is disabled, ignoring GROUP=\"%s\".", value);
                                else
                                        log_rule_debug("User name resolution is disabled, ignoring OWNER=\"%s\".", value);
                                continue;
                        }
                        continue;
                }

                if (streq(key, "MODE")) {
                        mode_t mode;

                        if (op < OP_MATCH_MAX || op == OP_REMOVE) {
                                log_rule_invalid_op("MODE");
                                goto invalid;
                        }

                        /* Like systemd, a value with substitutions is parsed whenever the rule is applied.
                         * Unlike systemd, which keeps the key, and fails whenever the rule is applied, or
                         * makes the mode final with ':=' without setting it, a value without substitutions
                         * that is not a valid mode, also an empty one, drops only this key, like an unknown
                         * user or group: the rest of the line still applies. */
                        r = parse_mode(value, &mode);
                        if (r >= 0)
                                rule_add_key(&rule_tmp, TK_A_MODE_ID, op, NULL, &mode);
                        else if (value_is_plain(value)) {
                                log_rule_error_errno(r, "Failed to parse mode \"%s\", ignoring: %m", value);
                                continue;
                        } else
                                rule_add_key(&rule_tmp, TK_A_MODE, op, value, NULL);
                        continue;
                }

                if (streq(key, "OPTIONS")) {
                        int r;

                        /* like systemd-udevd, which takes += as = */
                        if (op < OP_MATCH_MAX || op == OP_REMOVE) {
                                log_rule_invalid_op("OPTIONS");
                                goto invalid;
                        }
                        if (op == OP_ADD)
                                op = OP_ASSIGN;

                        r = parse_options(&rule_tmp, op, value);
                        if (r == -EOPNOTSUPP)
                                goto ignore;
                        if (r < 0)
                                goto invalid;
                        continue;
                }

                if (is_systemd_only(SYSTEMD_ONLY_KEY, key, strlen(key))) {
                        _cleanup_free_ char *what = NULL;

                        if (attr && asprintf(&what, "%s{%s}", key, attr) < 0)
                                what = NULL;
                        log_systemd_only(SYSTEMD_ONLY_KEY, what ?: key);
                        goto ignore;
                }

                log_rule_error("Invalid key '%s'.", key);
                goto invalid;
        }

        if (rule_tmp.failed)
                goto invalid;

        /* add rule token */
        first_token = rules->token_cur;
        rule_tmp.rule.rule.token_count = 1 + rule_tmp.token_cur;
        if (add_token(rules, &rule_tmp.rule) != 0)
                goto oom;

        /* add tokens to list, sorted by type */
        if (sort_token(rules, &rule_tmp) != 0)
                goto oom;

        free(rule_tmp.token);
        if (checking)
                udev_rules_check_line_end(checking, true);
        return 0;
oom:
        /* do not leave a part of the rule behind */
        rules->token_cur = first_token;
        log_oom();
invalid:
ignore:
        free(rule_tmp.token);
        if (checking)
                udev_rules_check_line_end(checking, false);
        return -1;
}

/* Reads the rules file path. Like systemd's udev_rules_parse_file(), which reads the file it found and
 * uses its original path in the messages and as the file name of its rules, the messages and rules use
 * filename, e.g. the name of a symlink as given to udevadm verify. */
static int parse_file(struct udev_rules *rules, const char *path, const char *filename) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *continuation = NULL;
        unsigned int first_token;
        unsigned int filename_off = 0;  /* avoid false maybe-uninitialized warning */
        unsigned line_nr = 0, first_line_nr = 0, too_long_line_nr = 0;
        bool ignore_line = false;
        unsigned int i, rule_idx;
        int r;

        f = fopen(path, "re");
        if (!f) {
                if (errno == ENOENT)
                        return 0;
                else
                        return -errno;
        }

        if (null_or_empty_fd(fileno(f))) {
                log_debug("Skipping empty file: %s", filename);
                return 0;
        } else
                log_debug("Reading rules file: %s", filename);

        /* Without the name, no rule of the file can be added. Like systemd, which skips the file when out of
         * memory, see udev_rules_new(). */
        r = rules_add_string(rules, filename, &filename_off);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                return log_error_errno(r, "Failed to add the name of the rules file %s: %m", filename);

        first_token = rules->token_cur;
        parse_filename = filename;

        /* Like udev_rules_parse_file() of systemd: a line ending with a backslash is continued on the next
         * line, without the leading whitespace of that, lines beginning with '#' are ignored also within
         * a continued rule, and a rule of UTIL_LINE_SIZE characters or more is ignored. Unlike systemd,
         * which ignores the whole file when a single line is that long, only ignore the rule, and say
         * which line it is. */
        for (;;) {
                _cleanup_free_ char *buf = NULL;
                bool too_long = false;
                char *line;
                size_t len;
                int r;

                /* Skip the beginning of an extremely long line, until its end, which is still needed to
                 * find out whether the rule continues on the next line. */
                while ((r = read_line(f, LONG_LINE_MAX, &buf)) == -ENOBUFS)
                        too_long = true;
                if (r < 0) {
                        log_error_errno(r, "Failed to read rules file %s, ignoring the rest of it: %m", filename);
                        break;
                }
                if (r == 0 && !too_long)
                        break;

                line_nr++;
                if (!continuation)
                        first_line_nr = line_nr;

                line = buf + strspn(buf, WHITESPACE);

                /* Lines beginning with '#' are ignored regardless of line continuation. */
                if (!too_long && line[0] == '#')
                        continue;

                len = strlen(line);

                /* remember the first line of the rule that is too long by itself */
                if ((too_long || len >= UTIL_LINE_SIZE) && too_long_line_nr == 0)
                        too_long_line_nr = line_nr;

                if (too_long)
                        ignore_line = true;
                else if (continuation && !ignore_line) {
                        if (strlen(continuation) + len >= UTIL_LINE_SIZE)
                                ignore_line = true;
                        else {
                                char *joined;

                                joined = strappend(continuation, line);
                                if (!joined)
                                        return log_oom();
                                free_and_replace(continuation, joined);

                                line = continuation;
                                len = strlen(line);
                        }
                } else if (!continuation && len >= UTIL_LINE_SIZE)
                        ignore_line = true;

                if (len > 0 && line[len - 1] == '\\') {
                        if (!ignore_line) {
                                line[len - 1] = '\0';
                                if (!continuation) {
                                        continuation = strdup(line);
                                        if (!continuation)
                                                return log_oom();
                                }
                        } else if (!continuation) {
                                /* too long already, only remember that the rule continues */
                                continuation = strdup("");
                                if (!continuation)
                                        return log_oom();
                        }
                        continue;
                }

                parse_line_nr = first_line_nr;
                if (ignore_line && too_long_line_nr > 0)
                        log_rule_error("Line %u is longer than %u characters, ignoring the rule.",
                                       too_long_line_nr, UTIL_LINE_SIZE - 1);
                else if (ignore_line)
                        log_rule_error("Line is too long, ignored.");
                else if (len > 0)
                        add_rule(rules, line, filename_off, first_line_nr);

                free(continuation);
                continuation = NULL;
                ignore_line = false;
                too_long_line_nr = 0;
        }

        if (continuation) {
                parse_line_nr = first_line_nr;
                log_rule_error("Unexpected EOF after line continuation, line ignored.");
        }

        /* link GOTOs to LABEL rules in this file to be able to fast-forward */
        for (i = first_token, rule_idx = first_token; i < rules->token_cur; i++) {
                if (rules->tokens[i].type == TK_RULE) {
                        parse_line_nr = rules->tokens[i].rule.filename_line;
                        rule_idx = i;
                }
                if (rules->tokens[i].type == TK_A_GOTO) {
                        char *label = rules_str(rules, rules->tokens[i].key.value_off);
                        unsigned int j;

                        for (j = i+1; j < rules->token_cur; j++) {
                                if (rules->tokens[j].type != TK_RULE)
                                        continue;
                                if (rules->tokens[j].rule.label_off == 0)
                                        continue;
                                if (!streq(label, rules_str(rules, rules->tokens[j].rule.label_off)))
                                        continue;
                                rules->tokens[i].key.rule_goto = j;
                                break;
                        }
                        if (rules->tokens[i].key.rule_goto == 0) {
                                struct token *rt = &rules->tokens[rule_idx];

                                /* like systemd, the rule has no GOTO then */
                                rt->rule.has_goto = false;
                                log_rule_error("GOTO=\"%s\" has no matching label, ignoring.", label);
                                /* like rule_resolve_goto() of systemd, which drops such a line; here, it is
                                 * skipped, see udev_rules_apply_to_event(); udevadm verify reports it its
                                 * own way */
                                if (checking)
                                        udev_rules_check_goto_unresolved(checking, parse_line_nr);
                                else if (!rt->rule.has_name && !rt->rule.has_devlink && !rt->rule.has_static_node &&
                                         !rt->rule.update_something)
                                        log_rule_warning("The line has no effect any more, dropping.");
                        }
                }
        }

        parse_filename = NULL;
        parse_line_nr = 0;

        if (checking)
                udev_rules_check_file_end(checking);
        return 0;
}

int udev_rules_parse_file_for_check(struct udev *udev, int resolve_names, const char *filename,
                                    const char *path, struct udev_rules_check *c) {
        struct udev_rules *rules;
        int r;

        assert(filename);
        assert(path);
        assert(c);

        /* parse_file() ignores missing files */
        if (access(path, R_OK) < 0)
                return -errno;

        rules = new0(struct udev_rules, 1);
        if (!rules)
                return -ENOMEM;
        rules->udev = udev;
        rules->resolve_names = resolve_names;

        rules->tokens = malloc(PREALLOC_TOKEN * sizeof(struct token));
        rules->token_max = PREALLOC_TOKEN;
        rules->strbuf = strbuf_new();
        if (!rules->tokens || !rules->strbuf) {
                udev_rules_unref(rules);
                return -ENOMEM;
        }

        udev_rules_check_file_begin(c, filename);
        checking = c;
        r = parse_file(rules, path, filename);
        checking = NULL;

        udev_rules_unref(rules);
        return r;
}

struct udev_rules *udev_rules_new(struct udev *udev, int resolve_names) {
        return udev_rules_new_full(udev, resolve_names, NULL);
}

struct udev_rules *udev_rules_new_full(struct udev *udev, int resolve_names, char * const *extra_dirs) {
        _cleanup_strv_free_ char **dirs = NULL;
        struct udev_rules *rules;
        struct udev_list file_list;
        struct token end_token;
        char **files, **f, **d;
        int r;

        rules = new0(struct udev_rules, 1);
        if (rules == NULL)
                return NULL;
        rules->udev = udev;
        rules->resolve_names = resolve_names;
        udev_list_init(udev, &file_list, true);

        /* init token array and string buffer */
        rules->tokens = malloc(PREALLOC_TOKEN * sizeof(struct token));
        if (rules->tokens == NULL)
                return udev_rules_unref(rules);
        rules->token_max = PREALLOC_TOKEN;

        rules->strbuf = strbuf_new();
        if (!rules->strbuf)
                return udev_rules_unref(rules);

        rules->dirs = udev_rules_get_dirs_runtime();
        if (!rules->dirs)
                return udev_rules_unref(rules);

        udev_rules_check_timestamp(rules);

        /* Like systemd's udev_rules_load(): the extra directories come first, so that their files
         * override the ones with the same name in the rules directories. */
        if (!strv_isempty(extra_dirs)) {
                dirs = strv_copy(extra_dirs);
                if (!dirs)
                        return udev_rules_unref(rules);
        }

        STRV_FOREACH(d, rules->dirs)
                if (strv_extend(&dirs, *d) < 0)
                        return udev_rules_unref(rules);

        /* Like udev_rules_load() of systemd: only regular files are read, and masks, i.e. empty files and
         * symlinks to /dev/null, hide the files with the same name in the later directories; anything
         * else, e.g. a directory, a dangling symlink or a FIFO, is skipped and does not hide them. */
        r = conf_files_list_strv(&files, ".rules", NULL, CONF_FILES_REGULAR | CONF_FILES_FILTER_MASKED,
                                 (const char* const*) dirs);
        if (r < 0) {
                log_error_errno(r, "failed to enumerate rules files: %m");
                return udev_rules_unref(rules);
        }

        STRV_FOREACH(f, files) {
                r = parse_file(rules, *f, *f);
                if (r < 0)
                        log_debug_errno(r, "Failed to read rules file %s, ignoring: %m", *f);
        }

        strv_free(files);

        memzero(&end_token, sizeof(struct token));
        end_token.type = TK_END;
        add_token(rules, &end_token);
        log_debug("rules contain %zu bytes tokens (%u * %zu bytes), %zu bytes strings",
                  rules->token_max * sizeof(struct token), rules->token_max, sizeof(struct token), rules->strbuf->len);

        /* cleanup temporary strbuf data */
        log_debug("%zu strings (%zu bytes), %zu de-duplicated (%zu bytes), %zu trie nodes used",
                  rules->strbuf->in_count, rules->strbuf->in_len,
                  rules->strbuf->dedup_count, rules->strbuf->dedup_len, rules->strbuf->nodes_count);
        strbuf_complete(rules->strbuf);

        /* cleanup uid/gid cache */
        free(rules->uids);
        rules->uids = NULL;
        rules->uids_cur = 0;
        rules->uids_max = 0;
        free(rules->gids);
        rules->gids = NULL;
        rules->gids_cur = 0;
        rules->gids_max = 0;

        dump_rules(rules);
        return rules;
}

struct udev_rules *udev_rules_unref(struct udev_rules *rules) {
        if (rules == NULL)
                return NULL;
        strv_free(rules->dirs);
        free(rules->tokens);
        strbuf_cleanup(rules->strbuf);
        free(rules->uids);
        free(rules->gids);
        free(rules);
        return NULL;
}

bool udev_rules_check_timestamp(struct udev_rules *rules) {
        if (!rules)
                return false;

        return paths_check_timestamp((const char* const*) rules->dirs, &rules->dirs_ts_usec, true);
}

/* returns whether the value matches the token's pattern, regardless of the operator */
static bool match_value(struct udev_rules *rules, struct token *token, const char *val) {
        char *key_value = rules_str(rules, token->key.value_off);
        char *pos;
        bool match = false;

        if (val == NULL)
                val = "";

        switch (token->key.glob) {
        case GL_PLAIN:
                if (token->key.case_insensitive)
                        match = (strcasecmp(key_value, val) == 0);
                else
                        match = (streq(key_value, val));
                break;
        case GL_GLOB:
                match = (fnmatch(key_value, val, token->key.case_insensitive ? FNM_CASEFOLD : 0) == 0);
                break;
        case GL_SPLIT:
                {
                        const char *s;
                        size_t len;

                        s = rules_str(rules, token->key.value_off);
                        len = strlen(val);
                        for (;;) {
                                const char *next;

                                next = strchr(s, '|');
                                if (next != NULL) {
                                        size_t matchlen = (size_t)(next - s);

                                        if (token->key.case_insensitive)
                                                match = (matchlen == len && strncasecmp(s, val, matchlen) == 0);
                                        else
                                                match = (matchlen == len && strneq(s, val, matchlen));
                                        if (match)
                                                break;
                                } else {
                                        if (token->key.case_insensitive)
                                                match = (strcasecmp(s, val) == 0);
                                        else
                                                match = (streq(s, val));
                                        break;
                                }
                                s = &next[1];
                        }
                        break;
                }
        case GL_SPLIT_GLOB:
                {
                        char value[UTIL_PATH_SIZE];

                        strscpy(value, sizeof(value), rules_str(rules, token->key.value_off));
                        key_value = value;
                        while (key_value != NULL) {
                                pos = strchr(key_value, '|');
                                if (pos != NULL) {
                                        pos[0] = '\0';
                                        pos = &pos[1];
                                }
                                match = (fnmatch(key_value, val, token->key.case_insensitive ? FNM_CASEFOLD : 0) == 0);
                                if (match)
                                        break;
                                key_value = pos;
                        }
                        break;
                }
        case GL_SOMETHING:
                match = (val[0] != '\0');
                break;
        case GL_UNSET:
                break;
        }

        return match;
}

#ifdef ENABLE_RULE_GENERATOR
/* Returns 0 when the value passes the match of the token, with its operator, -1 when not, without logging. */
static int match_key(struct udev_rules *rules, struct token *token, const char *val) {
        bool match;

        if (token->key.glob == GL_UNSET)
                return -1;

        match = match_value(rules, token, val);

        if (match && (token->key.op == OP_MATCH))
                return 0;
        if (!match && (token->key.op == OP_NOMATCH))
                return 0;
        return -1;
}
#endif

/* Like log_event_result() of systemd: logs PASS or FAIL in trace mode, and returns the result. */
static bool log_event_result(struct udev_event *event, struct udev_rules *rules, struct token *rule,
                             struct token *token, bool result) {
        log_event_trace(event, rules, rule, token, "%s", result ? "PASS" : "FAIL");
        return result;
}

/* The alternatives of the value of a match, like the trace messages of token_match_string() of systemd
 * show them: "" once if one of them is empty, then the others, quoted and separated by ", ", e.g.
 * "", "a", "b*" for "a||b*". Returns the number of alternatives in *ret_n. */
static char *token_value_alternatives(struct udev_rules *rules, struct token *token, unsigned *ret_n) {
        const char *value = rules_str(rules, token->key.value_off), *v;
        bool split = IN_SET(token->key.glob, GL_SPLIT, GL_SPLIT_GLOB), empty = false;
        unsigned n = 0;
        char *buf, *t;

        buf = new(char, strlen(value) * 4 + 8);
        if (!buf)
                return NULL;

        for (v = value;;) {
                size_t len = split ? strcspn(v, "|") : strlen(v);

                if (len == 0)
                        empty = true;
                if (v[len] == '\0')
                        break;
                v += len + 1;
        }

        t = buf;
        *t = '\0';
        if (empty) {
                t = stpcpy(t, "\"\"");
                n++;
        }
        for (v = value;;) {
                size_t len = split ? strcspn(v, "|") : strlen(v);

                if (len > 0) {
                        if (n > 0)
                                t = stpcpy(t, ", ");
                        *(t++) = '"';
                        t = mempcpy(t, v, len);
                        *(t++) = '"';
                        *t = '\0';
                        n++;
                }
                if (v[len] == '\0')
                        break;
                v += len + 1;
        }

        *ret_n = n;
        return buf;
}

/* Like token_match_string() of systemd: whether the string passes the match of the token, with its operator.
 * In trace mode, the comparison is logged, followed by PASS or FAIL when log_result is true, otherwise by a
 * period, as systemd does it for the alternatives of the match: SUBSYSTEM=="subsystem" (which the parser
 * turns into "subsystem|class|bus"), an empty value or "?*", and the alternatives of other values. */
static bool token_match_string(struct udev_event *event, struct udev_rules *rules, struct token *rule,
                               struct token *token, const char *str, bool log_result) {
        const char *value = rules_str(rules, token->key.value_off), *res;
        bool match, result;

        str = str ?: "";
        match = token->key.glob != GL_UNSET && match_value(rules, token, str);
        result = token->key.glob != GL_UNSET && match == (token->key.op != OP_NOMATCH);

        if (!event->trace)
                return result;

        res = log_result ? (result ? ": PASS" : ": FAIL") : ".";

        if (token->type == TK_M_SUBSYSTEM && streq(value, "subsystem|class|bus"))
                log_event_trace(event, rules, rule, token,
                                "String \"%s\" matches %s of \"subsystem\", \"class\", or \"bus\"%s",
                                str, match ? "one" : "neither", res);
        else if (token->key.glob == GL_SOMETHING || isempty(value))
                log_event_trace(event, rules, rule, token, "String \"%s\" is%s empty%s",
                                str, isempty(str) ? "" : " not", res);
        else {
                _cleanup_free_ char *joined = NULL;
                unsigned n = 0;

                joined = token_value_alternatives(rules, token, &n);
                log_event_trace(event, rules, rule, token, "String \"%s\" %s %s%s",
                                str,
                                match ? (n > 1 ? "matches one of" : "matches") : (n > 1 ? "matches neither of" : "does not match"),
                                joined ?: "", res);
        }

        return result;
}

/* Like the matches of SYMLINK, TAG and TAGS in systemd: with ==, one of the values of the list must match
 * the token, with !=, none of them. In trace mode, the comparison with each value that is checked is logged,
 * then the result. skip is the length of a prefix of the values that is not compared, e.g. of "/dev/". */
static bool token_match_list(struct udev_event *event, struct udev_rules *rules, struct token *rule,
                             struct token *token, struct udev_list_entry *first, size_t skip) {
        struct udev_list_entry *list_entry;

        udev_list_entry_foreach(list_entry, first)
                if (token_match_string(event, rules, rule, token, udev_list_entry_get_name(list_entry) + skip,
                                       /* log_result= */ false) == (token->key.op != OP_NOMATCH))
                        return log_event_result(event, rules, rule, token, token->key.op != OP_NOMATCH);

        return log_event_result(event, rules, rule, token, token->key.op == OP_NOMATCH);
}

/* Like apply_format_full() of systemd: substitutes format into result of size. If the result is truncated,
 * like log_event_truncated() of systemd, a match fails, with a debug message, and an assignment is not
 * applied, with a warning; returns false then. what says what is substituted. */
static bool apply_format(struct udev_event *event, struct udev_rules *rules, struct token *rule, struct token *token,
                         const char *format, char *result, size_t size, bool replace_whitespace,
                         struct udev_list *properties_list, const char *what) {
        bool truncated = false;

        (void) udev_event_apply_format(event, format, result, size, replace_whitespace, properties_list, &truncated);
        if (!truncated) {
                if (event->trace && !streq(format, result))
                        log_event_trace(event, rules, rule, token, "Format substitution: \"%s\" -> \"%s\"", format, result);
                return true;
        }

        if (token->type < TK_M_MAX)
                log_event_debug(event, rules, rule, token,
                                "The %s is truncated while substituting into \"%s\", assuming the token fails.",
                                what, format);
        else
                log_event_warning(event, rules, rule, token,
                                  "The %s is truncated while substituting into \"%s\", refusing to apply the token.",
                                  what, format);
        return false;
}

/* Like token_match_attr() of systemd: returns 0 when the attribute matches, -1 when not, and -ENOMEM when out
 * of memory. In trace mode, an attribute that cannot be read is logged, and does not match; otherwise
 * token_match_string() logs the comparison. */
static int match_attr(struct udev_rules *rules, struct udev_device *dev, struct udev_event *event,
                      struct token *rule, struct token *cur, struct udev_list *properties_list) {
        _cleanup_free_ char *stripped = NULL, *subsys_value = NULL;
        const char *name;
        char nbuf[UTIL_NAME_SIZE];
        const char *value;
        size_t len;
        int r;

        name = rules_str(rules, cur->key.attr_off);
        switch (cur->key.attrsubst) {
        case SB_FORMAT:
                if (!apply_format(event, rules, rule, cur, name, nbuf, sizeof(nbuf), false, properties_list,
                                  "sysfs attribute name"))
                        return -1;
                name = nbuf;
                /* fall through */
        case SB_NONE:
                value = udev_device_get_sysattr_value(dev, name);
                if (value == NULL) {
                        log_event_trace_errno(event, rules, rule, cur, errno, "Cannot read sysfs attribute%s%s%s: %m",
                                              name == nbuf ? " \"" : "", name == nbuf ? name : "",
                                              name == nbuf ? "\"" : "");
                        return -1;
                }
                break;
        case SB_SUBSYS:
                /* unlike systemd, which cuts it at 511 bytes, the whole value */
                r = util_resolve_subsys_kernel_value(event->udev, name, &subsys_value);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_event_trace_errno(event, rules, rule, cur, r, "Cannot read sysfs attribute: %m");
                        return -1;
                }
                value = subsys_value;
                break;
        default:
                return -1;
        }

        /* remove trailing whitespace, if not asked to match for it */
        len = strlen(value);
        if (len > 0 && isspace((unsigned char) value[len-1])) {
                const char *key_value;
                size_t klen;

                key_value = rules_str(rules, cur->key.value_off);
                klen = strlen(key_value);
                if (klen > 0 && !isspace((unsigned char) key_value[klen-1])) {
                        while (len > 0 && isspace((unsigned char) value[len - 1]))
                                len--;

                        /* Unlike systemd, which copies the value into a buffer of UDEV_NAME_SIZE, a
                         * longer value is not cut at 511 bytes. */
                        if (value == subsys_value)
                                subsys_value[len] = '\0';
                        else {
                                stripped = strndup(value, len);
                                if (!stripped)
                                        return log_oom();
                                value = stripped;
                        }
                }
        }

        return token_match_string(event, rules, rule, cur, value, /* log_result= */ true) ? 0 : -1;
}

enum escape_type {
        ESCAPE_UNSET,
        ESCAPE_NONE,
        ESCAPE_REPLACE,
};

/* Adds or removes one symlink of SYMLINK=. libudev refuses unsafe symlinks and symlinks containing
 * control characters, and normalizes the others. Like systemd, only running out of memory is an error, which
 * stops the processing of the event. */
static int apply_devlink(struct udev_event *event, struct udev_rules *rules, struct token *rule,
                          struct token *token, enum operation_type op, const char *link) {
        _cleanup_free_ char *escaped = NULL;
        int r;

        if (op == OP_REMOVE)
                r = udev_device_remove_devlink(event->dev, link);
        else
                r = udev_device_add_devlink(event->dev, link);
        if (r >= 0) {
                /* like systemd, only when the symlink was there, or was not there yet */
                if (op == OP_REMOVE && r > 0)
                        log_event_debug(event, rules, rule, token, "Removed device node symlink \"%s\"", link);
                else if (op != OP_REMOVE && r > 0)
                        log_event_debug(event, rules, rule, token, "Added device node symlink \"%s\".", link);
                return 0;
        }
        if (r == -ENOMEM)
                return log_oom();

        escaped = cescape(link);
        if (op == OP_REMOVE)
                log_event_warning_errno(event, rules, rule, token, r,
                                        "Failed to remove device node symlink \"%s\", ignoring: %m", escaped ?: link);
        else
                log_event_warning_errno(event, rules, rule, token, r,
                                        "Failed to add device node symlink \"%s\", ignoring: %m", escaped ?: link);
        return 0;
}

/* Like udev_replace_ifname() of systemd: with the naming schemes that have NAMING_REPLACE_STRICTLY, i.e.
 * v249 and later, every character that is not valid in a network interface name (see ifname_valid()) is
 * replaced with '_', otherwise the characters that are not valid in a device node name except '/'. Returns
 * the number of replaced characters. */
static int udev_replace_ifname(struct udev *udev, char *str) {
        int replaced = 0;
        char *p;

        /* naming_scheme_init() and not naming_scheme(), so that net_naming_scheme= of udev.conf is used
         * also when the net_id builtin did not run before */
        if (!FLAGS_SET(naming_scheme_init(udev)->flags, NAMING_REPLACE_STRICTLY))
                return util_replace_chars(str, "/");

        for (p = str; *p != '\0'; p++)
                if (!ifname_valid_char(*p)) {
                        *p = '_';
                        replaced++;
                }

        return replaced;
}

int udev_rules_apply_to_event(struct udev_rules *rules,
                              struct udev_event *event,
                              usec_t timeout_usec,
                              struct udev_list *properties_list,
                              const sigset_t *sigmask) {
        struct token *cur;
        /* the first token is the one of a rule, or the end, so this is set before it is used; the
         * initialization keeps compilers from warning that it may be used uninitialized */
        struct token *rule = NULL;
        enum escape_type esc = ESCAPE_UNSET;
        bool has_node = false, is_netif = false;
        bool ok;
        int r;

        if (rules->tokens == NULL)
                return 0;

        /* Like udev_rule_apply_line_to_event() of systemd, NAME= applies only to a network interface, and
         * SYMLINK=, OWNER=, GROUP= and MODE= only to a device node, and not on remove events. */
        if (!streq_ptr(udev_device_get_action(event->dev), "remove")) {
                has_node = major(udev_device_get_devnum(event->dev)) > 0;
                is_netif = udev_device_get_ifindex(event->dev) > 0;
        }

        /* loop through token list, match, run actions or forward to next rule */
        cur = &rules->tokens[0];
        for (;;) {
                dump_token(rules, cur);
                switch (cur->type) {
                case TK_RULE:
                        /* current rule */
                        rule = cur;
                        /* Like systemd, do not even evaluate a rule that cannot do anything for the event:
                         * one without assignment, GOTO, PROGRAM or IMPORT, or whose only assignments do not
                         * apply to the device or the event. */
                        if (!rule->rule.has_goto && !rule->rule.update_something &&
                            !(has_node && rule->rule.has_devlink) && !(is_netif && rule->rule.has_name))
                                goto nomatch;
                        esc = ESCAPE_UNSET;
                        break;
                case TK_M_ACTION:
                        if (!token_match_string(event, rules, rule, cur, udev_device_get_action(event->dev), true))
                                goto nomatch;
                        break;
                case TK_M_DEVPATH:
                        if (!token_match_string(event, rules, rule, cur, udev_device_get_devpath(event->dev), true))
                                goto nomatch;
                        break;
                case TK_M_KERNEL:
                        if (!token_match_string(event, rules, rule, cur, udev_device_get_sysname(event->dev), true))
                                goto nomatch;
                        break;
                case TK_M_DEVLINK:
                        if (!token_match_list(event, rules, rule, cur, udev_device_get_devlinks_list_entry(event->dev),
                                              strlen("/dev/")))
                                goto nomatch;
                        break;
                case TK_M_NAME:
                        if (!token_match_string(event, rules, rule, cur, event->name, true))
                                goto nomatch;
                        break;
                case TK_M_ENV: {
                        const char *key_name = rules_str(rules, cur->key.attr_off);
                        const char *value;

                        /* check global properties too */
                        value = udev_event_get_property_value_with_fallback(event->dev, key_name, properties_list);
                        if (!token_match_string(event, rules, rule, cur, value, true))
                                goto nomatch;
                        break;
                }
                case TK_M_TAG:
                        if (!token_match_list(event, rules, rule, cur, udev_device_get_current_tags_list_entry(event->dev), 0))
                                goto nomatch;
                        break;
                case TK_M_SUBSYSTEM:
                        if (!token_match_string(event, rules, rule, cur, udev_device_get_subsystem(event->dev), true))
                                goto nomatch;
                        break;
                case TK_M_DRIVER:
                        if (!token_match_string(event, rules, rule, cur, udev_device_get_driver(event->dev), true))
                                goto nomatch;
                        break;
                case TK_M_ATTR:
                        r = match_attr(rules, event->dev, event, rule, cur, properties_list);
                        if (r == -ENOMEM)
                                return r;
                        if (r != 0)
                                goto nomatch;
                        break;
                case TK_M_SYSCTL: {
                        char filename[UTIL_PATH_SIZE];
                        _cleanup_free_ char *value = NULL;

                        if (!apply_format(event, rules, rule, cur, rules_str(rules, cur->key.attr_off), filename, sizeof(filename),
                                          false, properties_list, "sysctl entry name"))
                                goto nomatch;
                        sysctl_normalize(filename);
                        /* Like systemd, an error other than a missing entry stops the processing of the event. */
                        r = sysctl_read(filename, &value);
                        if (r < 0 && r != -ENOENT)
                                return log_event_error_errno(event, rules, rule, cur, r, "Failed to read sysctl \"%s\": %m",
                                                             filename);

                        /* Like systemd, a missing entry is compared as an empty value, and the whitespace around
                         * the value is removed. */
                        if (!token_match_string(event, rules, rule, cur, value ? strstrip(value) : NULL, true))
                                goto nomatch;
                        break;
                }
                case TK_M_KERNELS:
                case TK_M_SUBSYSTEMS:
                case TK_M_DRIVERS:
                case TK_M_ATTRS:
                case TK_M_TAGS: {
                        struct token *next;

                        /* get whole sequence of parent matches */
                        next = cur;
                        while (next->type > TK_M_PARENTS_MIN && next->type < TK_M_PARENTS_MAX)
                                next++;

                        trace_parent_tokens(event, rules, rule, cur, next);

                        /* loop over parents */
                        event->dev_parent = event->dev;
                        for (;;) {
                                struct token *key;

                                /* loop over sequence of parent match keys */
                                for (key = cur; key < next; key++ ) {
                                        dump_token(rules, key);
                                        /* like systemd, logged with the parent device that is checked */
                                        switch(key->type) {
                                        case TK_M_KERNELS:
                                                if (!token_match_string(event, rules, rule, key,
                                                                        udev_device_get_sysname(event->dev_parent), true))
                                                        goto try_parent;
                                                break;
                                        case TK_M_SUBSYSTEMS:
                                                if (!token_match_string(event, rules, rule, key,
                                                                        udev_device_get_subsystem(event->dev_parent), true))
                                                        goto try_parent;
                                                break;
                                        case TK_M_DRIVERS:
                                                if (!token_match_string(event, rules, rule, key,
                                                                        udev_device_get_driver(event->dev_parent), true))
                                                        goto try_parent;
                                                break;
                                        case TK_M_ATTRS:
                                                r = match_attr(rules, event->dev_parent, event, rule, key, properties_list);
                                                if (r == -ENOMEM)
                                                        return r;
                                                if (r != 0)
                                                        goto try_parent;
                                                break;
                                        case TK_M_TAGS:
                                                if (!token_match_list(event, rules, rule, key,
                                                                      udev_device_get_current_tags_list_entry(event->dev_parent), 0))
                                                        goto try_parent;
                                                break;
                                        default:
                                                goto nomatch;
                                        }
                                }
                                break;

                        try_parent:
                                event->dev_parent = udev_device_get_parent(event->dev_parent);
                                if (event->dev_parent == NULL) {
                                        trace_line(event, rules, rule, "No parent device passed parent conditions.");
                                        goto nomatch;
                                }
                        }
                        trace_line(event, rules, rule, "Parent device \"%s\" passed all parent conditions.",
                                   udev_device_get_syspath(event->dev_parent));
                        /* move behind our sequence of parent match keys */
                        cur = next;
                        continue;
                }
                case TK_M_TEST: {
                        char filename[UTIL_PATH_SIZE];
                        struct stat statbuf;
                        int match;

                        if (!apply_format(event, rules, rule, cur, rules_str(rules, cur->key.value_off), filename, sizeof(filename),
                                          false, properties_list, "file name"))
                                goto nomatch;
                        if (util_resolve_subsys_kernel(event->udev, filename, filename, sizeof(filename)) < 0) {
                                if (filename[0] != '/') {
                                        char tmp[UTIL_PATH_SIZE];
                                        bool truncated;

                                        strscpy(tmp, sizeof(tmp), filename);
                                        /* like systemd, a path that does not fit fails */
                                        strscpyl_full(filename, sizeof(filename), &truncated,
                                                      udev_device_get_syspath(event->dev), "/", tmp, NULL);
                                        if (truncated) {
                                                log_event_result(event, rules, rule, cur, false);
                                                goto nomatch;
                                        }
                                }
                        }

                        /* Like systemd, an error of resolving a "*" path component other than that nothing is
                         * found stops the processing of the event; an error of stat() other than a missing file
                         * is logged, and taken as a missing file. */
                        r = attr_subst_subdir(filename);
                        if (r < 0 && r != -ENOENT)
                                return log_event_error_errno(event, rules, rule, cur, r,
                                                             "Failed to test for the existence of \"%s\": %m", filename);
                        if (r < 0)
                                match = false;
                        else if (stat(filename, &statbuf) < 0) {
                                if (errno != ENOENT)
                                        log_event_warning_errno(event, rules, rule, cur, errno,
                                                                "Failed to stat \"%s\", ignoring: %m", filename);
                                match = false;
                        } else
                                match = true;

                        /* like systemd, with a mode mask, at least one of its bits must be set */
                        if (match && cur->key.mode != MODE_INVALID)
                                match = ((statbuf.st_mode & cur->key.mode) > 0);
                        if (!log_event_result(event, rules, rule, cur, match == (cur->key.op != OP_NOMATCH)))
                                goto nomatch;
                        break;
                }
                case TK_M_PROGRAM: {
                        char program[UTIL_LINE_SIZE];
                        char **envp;
                        char result[UTIL_LINE_SIZE];

                        free(event->program_result);
                        event->program_result = NULL;
                        if (!apply_format(event, rules, rule, cur, rules_str(rules, cur->key.value_off), program, sizeof(program),
                                          false, properties_list, "command"))
                                goto nomatch;
                        envp = udev_device_get_properties_envp(event->dev);
                        log_event_debug(event, rules, rule, cur, "Running command \"%s\"", program);

                        if (udev_event_spawn(event, timeout_usec, program, envp, sigmask, result, sizeof(result), NULL) < 0) {
                                if (!log_event_result(event, rules, rule, cur, cur->key.op == OP_NOMATCH))
                                        goto nomatch;
                        } else {
                                int count;

                                util_remove_trailing_chars(result, '\n');
                                if (esc == ESCAPE_UNSET || esc == ESCAPE_REPLACE) {
                                        count = util_replace_chars(result, UDEV_ALLOWED_CHARS_INPUT);
                                        if (count > 0)
                                                log_event_trace(event, rules, rule, cur,
                                                                "Replaced %i character(s) from command output, results to \"%s\"",
                                                                count, result);
                                }
                                event->program_result = strdup(result);
                                if (!log_event_result(event, rules, rule, cur, cur->key.op != OP_NOMATCH))
                                        goto nomatch;
                        }
                        break;
                }
                case TK_M_IMPORT_FILE: {
                        char import[UTIL_PATH_SIZE];

                        if (!apply_format(event, rules, rule, cur, rules_str(rules, cur->key.value_off), import, sizeof(import),
                                          false, properties_list, "file name to be imported"))
                                goto nomatch;
                        log_event_debug(event, rules, rule, cur, "Importing properties from \"%s\"", import);
                        r = import_file_into_properties(event, rules, rule, cur, import);
                        if (r < 0)
                                return r;
                        if (!log_event_result(event, rules, rule, cur, (r > 0) == (cur->key.op != OP_NOMATCH)))
                                goto nomatch;
                        break;
                }
                case TK_M_IMPORT_PROG: {
                        char import[UTIL_LINE_SIZE];

                        if (!apply_format(event, rules, rule, cur, rules_str(rules, cur->key.value_off), import, sizeof(import),
                                          false, properties_list, "command"))
                                goto nomatch;
                        log_event_debug(event, rules, rule, cur, "Importing properties from results of \"%s\"", import);

                        r = import_program_into_properties(event, rules, rule, cur, timeout_usec,
                                                           import, sigmask);
                        if (r < 0)
                                return r;
                        if (!log_event_result(event, rules, rule, cur, (r > 0) == (cur->key.op != OP_NOMATCH)))
                                goto nomatch;
                        break;
                }
                case TK_M_IMPORT_BUILTIN: {
                        char command[UTIL_LINE_SIZE];

                        /* check if we ran already */
                        if (udev_builtin_run_once(cur->key.builtin_cmd) &&
                            (event->builtin_run & (1 << cur->key.builtin_cmd))) {
                                log_event_debug(event, rules, rule, cur,
                                                "Builtin command \"%s\" has already run, skipping.",
                                                udev_builtin_name(cur->key.builtin_cmd));
                                /* return the result from earlier run */
                                ok = !(event->builtin_ret & (1 << cur->key.builtin_cmd));
                                if (!log_event_result(event, rules, rule, cur, ok == (cur->key.op != OP_NOMATCH)))
                                        goto nomatch;
                                break;
                        }

                        if (!apply_format(event, rules, rule, cur, rules_str(rules, cur->key.value_off), command, sizeof(command),
                                          false, properties_list, "builtin command"))
                                goto nomatch;

                        /* Mark as ran. Unlike systemd, only when the builtin really runs: a command that does not
                         * fit is not run, and a later IMPORT{builtin} of the same builtin must not take the
                         * result of a run that did not happen. */
                        if (udev_builtin_run_once(cur->key.builtin_cmd))
                                event->builtin_run |= (1 << cur->key.builtin_cmd);
                        log_event_debug(event, rules, rule, cur,
                                        "Importing properties from results of builtin command \"%s\".", command);

                        r = udev_builtin_run(event->dev, cur->key.builtin_cmd, command, event->event_mode);
                        ok = r == 0;
                        if (!ok) {
                                /* remember failure */
                                if (r < 0)
                                        log_event_debug_errno(event, rules, rule, cur, r, "Failed to run builtin \"%s\": %m", command);
                                else
                                        log_event_debug(event, rules, rule, cur, "Builtin command \"%s\" returned non-zero", command);
                                event->builtin_ret |= (1 << cur->key.builtin_cmd);
                        }
                        if (!log_event_result(event, rules, rule, cur, ok == (cur->key.op != OP_NOMATCH)))
                                goto nomatch;
                        break;
                }
                case TK_M_IMPORT_DB: {
                        const char *key = rules_str(rules, cur->key.value_off);
                        const char *value;

                        value = udev_device_get_property_value(event->dev_db, key);
                        if (value != NULL &&
                            import_property(event, rules, rule, cur, key, value) == -ENOMEM)
                                return -ENOMEM;
                        if (!log_event_result(event, rules, rule, cur, (value != NULL) == (cur->key.op != OP_NOMATCH)))
                                goto nomatch;
                        break;
                }
                case TK_M_IMPORT_CMDLINE: {
                        _cleanup_free_ char *value = NULL;
                        bool imported = false;
                        const char *key;

                        key = rules_str(rules, cur->key.value_off);

                        /* Like systemd, an error stops the processing of the rules for the event. */
                        r = proc_cmdline_get_key(key, &value);
                        if (r < 0)
                                return log_event_error_errno(event, rules, rule, cur, r,
                                                             "Failed to read \"%s\" option from /proc/cmdline: %m", key);
                        if (r > 0) {
                                imported = true;

                                /* we import simple flags as 'FLAG=1' */
                                if (import_property(event, rules, rule, cur, key, value ?: "1") == -ENOMEM)
                                        return -ENOMEM;
                        }

                        if (!log_event_result(event, rules, rule, cur, imported == (cur->key.op != OP_NOMATCH)))
                                goto nomatch;
                        break;
                }
                case TK_M_IMPORT_PARENT: {
                        char import[UTIL_PATH_SIZE];

                        if (!apply_format(event, rules, rule, cur, rules_str(rules, cur->key.value_off), import, sizeof(import),
                                          false, properties_list, "property name"))
                                goto nomatch;
                        /* Like systemd-udevd, match only when at least one property was imported. */
                        r = import_parent_into_properties(event, rules, rule, cur, import);
                        if (r < 0)
                                return r;
                        if (!log_event_result(event, rules, rule, cur, (r > 0) == (cur->key.op != OP_NOMATCH)))
                                goto nomatch;
                        break;
                }
                case TK_M_RESULT:
                        if (!token_match_string(event, rules, rule, cur, event->program_result, true))
                                goto nomatch;
                        break;
                case TK_A_DUMP: {
                        _cleanup_free_ char *buf = NULL;
                        size_t size = 0;
                        FILE *f;

                        log_event_info(event, rules, rule, cur, "Dumping current state:");

                        f = open_memstream(&buf, &size);
                        if (!f)
                                return log_oom();

                        (void) dump_event(event, cur->key.dump_flags, f);

                        if (fclose(f) != 0)
                                log_event_warning_errno(event, rules, rule, cur, errno,
                                                        "Failed to finalize memory stream, ignoring: %m");
                        else
                                log_dump(event->dev, buf);

                        log_event_info(event, rules, rule, cur, "DONE");
                        break;
                }
                case TK_A_STRING_ESCAPE_NONE:
                        esc = ESCAPE_NONE;
                        log_event_done(event, rules, rule, cur);
                        break;
                case TK_A_STRING_ESCAPE_REPLACE:
                        esc = ESCAPE_REPLACE;
                        log_event_done(event, rules, rule, cur);
                        break;
                case TK_A_DB_PERSIST:
                        udev_device_set_db_persist(event->dev);
                        log_event_done(event, rules, rule, cur);
                        break;
                case TK_A_NET_ALTNAMES:
                        event->net_altnames = true;
                        log_event_debug(event, rules, rule, cur, "OPTIONS net_altnames");
                        break;
                case TK_A_INOTIFY_WATCH:
                        if (event->inotify_watch_final) {
                                log_event_final_set(event, rules, rule, cur);
                                break;
                        }
                        if (cur->key.op == OP_ASSIGN_FINAL)
                                event->inotify_watch_final = true;
                        event->inotify_watch = cur->key.watch;
                        log_event_done(event, rules, rule, cur);
                        break;
                case TK_A_DEVLINK_PRIO:
                        udev_device_set_devlink_priority(event->dev, cur->key.devlink_prio);
                        log_event_done(event, rules, rule, cur);
                        break;
                case TK_A_LOG_LEVEL: {
                        int level = cur->key.log_level;

                        if (level < 0)
                                level = event->default_log_level;

                        if (event->event_mode == EVENT_UDEV_WORKER)
                                log_set_max_level(level);
                        else {
                                _cleanup_free_ char *level_str = NULL;

                                (void) log_level_to_string_alloc(level, &level_str);
                                log_event_debug(event, rules, rule, cur,
                                                "Running in test mode, skipping changing maximum log level to %s.",
                                                strna(level_str));
                        }

                        if (level == LOG_DEBUG && !event->log_level_was_debug) {
                                /* The log level becomes LOG_DEBUG at first time. Let's log basic information. */
                                if (event->event_mode == EVENT_UDEV_WORKER)
                                        log_debug("%s: The log level is changed to 'debug' while processing device (SEQNUM=%llu, ACTION=%s)",
                                                  udev_device_get_sysname(event->dev), udev_device_get_seqnum(event->dev),
                                                  udev_device_get_action(event->dev) ?: "n/a");
                                event->log_level_was_debug = true;
                        }
                        log_event_done(event, rules, rule, cur);
                        break;
                }
                case TK_A_OWNER: {
                        char owner[UTIL_NAME_SIZE];
                        uid_t uid;

                        if (event->owner_final) {
                                log_event_final_set(event, rules, rule, cur);
                                break;
                        }
                        if (cur->key.op == OP_ASSIGN_FINAL)
                                event->owner_final = true;
                        if (!apply_format(event, rules, rule, cur, rules_str(rules, cur->key.value_off), owner, sizeof(owner),
                                          false, properties_list, "user name"))
                                break;

                        /* Like systemd, leave the owner as it is when the user cannot be resolved. */
                        r = resolve_user_or_group(owner, false, &uid);
                        if (r < 0) {
                                log_event_error_errno(event, rules, rule, cur, r, "Failed to resolve user \"%s\", ignoring: %s",
                                                      owner, STRERROR_USER_GROUP(r, false));
                                break;
                        }
                        if (!uid_is_system(uid))
                                log_event_warning(event, rules, rule, cur, NON_SYSTEM_ACCOUNT_WARNING("User", "user"), owner);
                        event->owner_set = true;
                        event->uid = uid;
                        log_event_debug(event, rules, rule, cur, "Set owner: %s(%u)", owner, event->uid);
                        break;
                }
                case TK_A_GROUP: {
                        char group[UTIL_NAME_SIZE];
                        gid_t gid;

                        if (event->group_final) {
                                log_event_final_set(event, rules, rule, cur);
                                break;
                        }
                        if (cur->key.op == OP_ASSIGN_FINAL)
                                event->group_final = true;
                        if (!apply_format(event, rules, rule, cur, rules_str(rules, cur->key.value_off), group, sizeof(group),
                                          false, properties_list, "group name"))
                                break;

                        /* Like systemd, leave the group as it is when the group cannot be resolved. */
                        r = resolve_user_or_group(group, true, &gid);
                        if (r < 0) {
                                log_event_error_errno(event, rules, rule, cur, r, "Failed to resolve group \"%s\", ignoring: %s",
                                                      group, STRERROR_USER_GROUP(r, true));
                                break;
                        }
                        if (!gid_is_system(gid))
                                log_event_warning(event, rules, rule, cur, NON_SYSTEM_ACCOUNT_WARNING("Group", "group"), group);
                        event->group_set = true;
                        event->gid = gid;
                        log_event_debug(event, rules, rule, cur, "Set group: %s(%u)", group, event->gid);
                        break;
                }
                case TK_A_MODE: {
                        char mode_str[UTIL_NAME_SIZE];
                        mode_t mode;
                        int r;

                        if (event->mode_final) {
                                log_event_final_set(event, rules, rule, cur);
                                break;
                        }
                        /* like systemd, also when the value is not valid */
                        if (cur->key.op == OP_ASSIGN_FINAL)
                                event->mode_final = true;
                        if (!apply_format(event, rules, rule, cur, rules_str(rules, cur->key.value_off), mode_str, sizeof(mode_str),
                                          false, properties_list, "mode"))
                                break;
                        r = parse_mode(mode_str, &mode);
                        if (r < 0) {
                                log_event_error_errno(event, rules, rule, cur, r, "Failed to parse mode \"%s\", ignoring: %m", mode_str);
                                break;
                        }
                        event->mode_set = true;
                        event->mode = mode;
                        log_event_debug(event, rules, rule, cur, "Set mode: %#o", event->mode);
                        break;
                }
                case TK_A_OWNER_ID:
                        if (event->owner_final) {
                                log_event_final_set(event, rules, rule, cur);
                                break;
                        }
                        if (cur->key.op == OP_ASSIGN_FINAL)
                                event->owner_final = true;
                        event->owner_set = true;
                        event->uid = cur->key.uid;
                        log_event_debug(event, rules, rule, cur, "Set owner ID: %u", event->uid);
                        break;
                case TK_A_GROUP_ID:
                        if (event->group_final) {
                                log_event_final_set(event, rules, rule, cur);
                                break;
                        }
                        if (cur->key.op == OP_ASSIGN_FINAL)
                                event->group_final = true;
                        event->group_set = true;
                        event->gid = cur->key.gid;
                        log_event_debug(event, rules, rule, cur, "Set group ID: %u", event->gid);
                        break;
                case TK_A_MODE_ID:
                        if (event->mode_final) {
                                log_event_final_set(event, rules, rule, cur);
                                break;
                        }
                        if (cur->key.op == OP_ASSIGN_FINAL)
                                event->mode_final = true;
                        event->mode_set = true;
                        event->mode = cur->key.mode;
                        log_event_debug(event, rules, rule, cur, "Set mode: %#o", event->mode);
                        break;
                case TK_A_SECLABEL: {
                        char label_str[UTIL_LINE_SIZE] = {};
                        const char *name, *label;

                        name = rules_str(rules, cur->key.attr_off);
                        if (!apply_format(event, rules, rule, cur, rules_str(rules, cur->key.value_off), label_str, sizeof(label_str),
                                          false, properties_list, "security label"))
                                break;
                        if (label_str[0] != '\0')
                                label = label_str;
                        else
                                label = rules_str(rules, cur->key.value_off);

                        if (cur->key.op == OP_ASSIGN || cur->key.op == OP_ASSIGN_FINAL)
                                udev_list_cleanup(&event->seclabel_list);
                        /* like systemd, failing to store it stops the processing of the event */
                        if (!udev_list_entry_add(&event->seclabel_list, name, label))
                                return log_oom();
                        log_event_debug(event, rules, rule, cur, "Set security label: %s=%s", name, label);
                        break;
                }
                case TK_A_ENV: {
                        const char *name = rules_str(rules, cur->key.attr_off);
                        char *value = rules_str(rules, cur->key.value_off);
                        char value_new[UTIL_NAME_SIZE], *p = value_new;
                        size_t l = sizeof(value_new);
                        const char *value_old = NULL;
                        int r;

                        if (value[0] == '\0') {
                                if (cur->key.op == OP_ADD) {
                                        log_event_done(event, rules, rule, cur);
                                        break;
                                }
                                /* like systemd, a failure stops the processing of the event */
                                r = udev_device_add_property(event->dev, name, NULL);
                                if (r < 0)
                                        return log_event_error_errno(event, rules, rule, cur, r,
                                                                     "Failed to remove property \"%s\": %m", name);
                                log_event_trace(event, rules, rule, cur, "Removed property \"%s\".", name);
                                break;
                        }

                        /* Like systemd: append the new value to the old one, separated by a space, and refuse
                         * it when either does not fit. */
                        if (cur->key.op == OP_ADD)
                                value_old = udev_event_get_property_value_with_fallback(event->dev, name, properties_list);
                        if (value_old) {
                                bool truncated;

                                l = strpcpyl_full(&p, l, &truncated, value_old, " ", NULL);
                                if (truncated) {
                                        log_event_warning(event, rules, rule, cur,
                                                          "The buffer for the property is full, refusing to append new property \"%s=%s\".",
                                                          name, value);
                                        break;
                                }
                        }

                        if (!apply_format(event, rules, rule, cur, value, p, l, false, properties_list, "property value"))
                                break;

                        if (esc == ESCAPE_REPLACE) {
                                int count = util_replace_chars(p, NULL);
                                if (count > 0)
                                        log_event_trace(event, rules, rule, cur,
                                                        "Replaced %i character(s) from property value, results to \"%s\"",
                                                        count, p);
                        }

                        /* like systemd, running out of memory stops the processing of the event */
                        r = udev_device_add_property(event->dev, name, value_new);
                        if (r == -ENOMEM)
                                return log_oom();
                        if (r < 0) {
                                _cleanup_free_ char *v = cescape(value_new);

                                log_event_warning_errno(event, rules, rule, cur, r, "Failed to set property \"%s=%s\", ignoring: %m",
                                                        name, v ?: "");
                        } else
                                log_event_trace(event, rules, rule, cur, "Set property \"%s=%s\".", name, value_new);
                        break;
                }
                case TK_A_TAG: {
                        char tag[UTIL_PATH_SIZE];
                        bool assign = cur->key.op == OP_ASSIGN || cur->key.op == OP_ASSIGN_FINAL;

                        if (!apply_format(event, rules, rule, cur, rules_str(rules, cur->key.value_off), tag, sizeof(tag),
                                          false, properties_list, "tag name"))
                                break;
                        if (assign) {
                                r = udev_device_cleanup_tags(event->dev, event->dev_db);
                                if (r < 0)
                                        log_event_warning_errno(event, rules, rule, cur, r,
                                                                "Failed to clear previously assigned tags, ignoring: %m");
                        }
                        if (cur->key.op == OP_REMOVE) {
                                udev_device_remove_tag(event->dev, tag);
                                log_event_trace(event, rules, rule, cur, "Removed tag \"%s\".", tag);
                        } else {
                                r = udev_device_add_tag(event->dev, tag, true);
                                if (r == -ENOMEM) /* like systemd, this stops the processing of the event */
                                        return log_oom();
                                /* like systemd, also for an empty tag */
                                if (r < 0)
                                        log_event_warning_errno(event, rules, rule, cur, r, "Failed to %s tag \"%s\", ignoring: %m",
                                                                assign ? "set" : "add", tag);
                                else
                                        log_event_trace(event, rules, rule, cur, "%s tag \"%s\".", assign ? "Set" : "Added", tag);
                        }
                        break;
                }
                case TK_A_NAME: {
                        const char *name  = rules_str(rules, cur->key.value_off);

                        char name_str[UTIL_PATH_SIZE];
                        int count;

                        if (event->name_final) {
                                log_event_final_set(event, rules, rule, cur);
                                break;
                        }
                        if (cur->key.op == OP_ASSIGN_FINAL)
                                event->name_final = true;
                        /* Like systemd, ignore NAME for a device that is not a network interface; the name of
                         * the device node of a block or character device cannot be changed. */
                        if (udev_device_get_ifindex(event->dev) <= 0) {
                                log_event_warning(event, rules, rule, cur, "Only network interfaces can be renamed, ignoring.");
                                break;
                        }
                        if (!apply_format(event, rules, rule, cur, name, name_str, sizeof(name_str), false, properties_list,
                                          "network interface name"))
                                break;
                        if (esc == ESCAPE_UNSET || esc == ESCAPE_REPLACE) {
                                count = udev_replace_ifname(event->udev, name_str);
                                if (count > 0)
                                        log_event_trace(event, rules, rule, cur,
                                                        "Replaced %i character(s) from network interface name, results to \"%s\"",
                                                        count, name_str);
                        }
                        /* like systemd, running out of memory stops the processing of the event */
                        r = free_and_strdup(&event->name, name_str);
                        if (r < 0)
                                return log_oom();
                        log_event_debug(event, rules, rule, cur, "Set network interface name: %s", strna(event->name));
                        break;
                }
                case TK_A_DEVLINK: {
                        char temp[UTIL_PATH_SIZE];
                        char *pos, *next;
                        int count = 0;

                        if (event->devlink_final) {
                                log_event_final_set(event, rules, rule, cur);
                                break;
                        }
                        if (major(udev_device_get_devnum(event->dev)) == 0) {
                                log_event_debug(event, rules, rule, cur,
                                                "Device does not have device node, ignoring to manage device node symlink.");
                                break;
                        }
                        if (cur->key.op == OP_ASSIGN_FINAL)
                                event->devlink_final = true;
                        if (cur->key.op == OP_ASSIGN || cur->key.op == OP_ASSIGN_FINAL)
                                udev_device_cleanup_devlinks_list(event->dev);

                        /* allow  multiple symlinks separated by spaces */
                        if (!apply_format(event, rules, rule, cur, rules_str(rules, cur->key.value_off), temp, sizeof(temp),
                                          esc != ESCAPE_NONE, properties_list, "symbolic link path"))
                                break;
                        if (esc == ESCAPE_UNSET)
                                count = util_replace_chars(temp, "/ ");
                        else if (esc == ESCAPE_REPLACE)
                                count = util_replace_chars(temp, "/");
                        if (count > 0)
                                log_event_trace(event, rules, rule, cur,
                                                "Replaced %i character(s) from device node symlink, results to \"%s\"",
                                                count, temp);
                        pos = temp;
                        while (isspace((unsigned char) pos[0]))
                                pos++;
                        next = strchr(pos, ' ');
                        while (next != NULL) {
                                next[0] = '\0';
                                r = apply_devlink(event, rules, rule, cur, cur->key.op, pos);
                                if (r < 0)
                                        return r;
                                while (isspace((unsigned char) next[1]))
                                        next++;
                                pos = &next[1];
                                next = strchr(pos, ' ');
                        }
                        if (pos[0] != '\0') {
                                r = apply_devlink(event, rules, rule, cur, cur->key.op, pos);
                                if (r < 0)
                                        return r;
                        }
                        break;
                }
                case TK_A_ATTR: {
                        const char *key_name = rules_str(rules, cur->key.attr_off);
                        const char *syspath = udev_device_get_syspath(event->dev);
                        _cleanup_free_ char *canonical = NULL;
                        char attr[UTIL_PATH_SIZE];
                        char resolved[UTIL_PATH_SIZE];
                        char value[UTIL_NAME_SIZE];
                        int r;

                        /* First, try to resolve "[<SUBSYSTEM>/<KERNEL>]<attribute>" format. */
                        if (util_resolve_subsys_kernel(event->udev, key_name, attr, sizeof(attr)) < 0) {
                                if (key_name[0] == '[') {
                                        log_event_warning(event, rules, rule, cur, "Failed to resolve sysfs attribute \"%s\", ignoring.",
                                                          key_name);
                                        break;
                                }

                                /* If not, make the path to sysfs attribute absolute, to make '*' resolvable by attr_subst_subdir(). */
                                if (strscpyl(attr, sizeof(attr), syspath, "/", key_name, NULL) == 0) {
                                        log_event_warning(event, rules, rule, cur,
                                                          "The path to the attribute \"%s/%s\" is too long, refusing to set the attribute.",
                                                          syspath, key_name);
                                        break;
                                }

                                /* Resolve '*' in the path. */
                                r = attr_subst_subdir(attr);
                                if (r < 0) {
                                        log_event_error_errno(event, rules, rule, cur, r,
                                                              "Could not find file matches \"%s\", ignoring: %m", attr);
                                        break;
                                }
                        }

                        /* Then, make the path relative again. This also checks if the path being inside of the sysfs. */
                        canonical = realpath(attr, NULL);
                        if (canonical == NULL) {
                                log_event_error_errno(event, rules, rule, cur, errno,
                                                      "Could not chase sysfs attribute \"%s\", ignoring: %m", attr);
                                break;
                        }
                        /* like systemd, which refuses it with EINVAL */
                        if (isempty(path_startswith(canonical, "/sys"))) {
                                log_event_error_errno(event, rules, rule, cur, EINVAL,
                                                      "Could not chase sysfs attribute \"%s\", ignoring: %m", attr);
                                break;
                        }
                        r = make_relative_path(syspath, canonical, resolved, sizeof(resolved));
                        if (r < 0) {
                                log_event_error_errno(event, rules, rule, cur, r,
                                                      "Could not chase sysfs attribute \"%s\", ignoring: %m", attr);
                                break;
                        }

                        /* Apply formatting to the value. */
                        if (!apply_format(event, rules, rule, cur, rules_str(rules, cur->key.value_off), value, sizeof(value),
                                          false, properties_list, "attribute value"))
                                break;

                        if (EVENT_MODE_DESTRUCTIVE(event)) {
                                log_event_debug(event, rules, rule, cur, "Writing \"%s\" to sysfs attribute \"%s\".", value, resolved);
                                r = udev_device_set_sysattr_value(event->dev, resolved, value);
                                if (r < 0)
                                        log_event_error_errno(event, rules, rule, cur, r,
                                                              "Failed to write \"%s\" to sysfs attribute \"%s\", ignoring: %m",
                                                              value, resolved);
                                else {
                                        event_cache_written_sysattr(event, resolved, value);
                                        log_event_done(event, rules, rule, cur);
                                }
                        } else {
                                log_event_debug(event, rules, rule, cur,
                                                "Running in test mode, skipping writing \"%s\" to sysfs attribute \"%s\".",
                                                value, resolved);

                                /* We assume the attribute is writable if the path points to a regular file, and cache
                                 * the value to make it shown by 'udevadm test' or obtained by later ATTR match token. */
                                r = verify_regular(canonical, true);
                                if (r < 0 && !IN_SET(r, -EACCES, -EPERM))
                                        log_event_error_errno(event, rules, rule, cur, r,
                                                              "Failed to verify sysfs attribute \"%s\" is a regular file: %m",
                                                              resolved);
                                else {
                                        event_cache_written_sysattr(event, resolved, value);

                                        /* like systemd, where failing to copy the value stops the processing of
                                         * the event, as it does not fit into memory, and caching it may fail */
                                        r = udev_device_cache_sysattr_value(event->dev, resolved, value);
                                        if (r == -ENOMEM)
                                                return log_oom();
                                        if (r < 0)
                                                log_event_warning_errno(event, rules, rule, cur, r,
                                                                        "Failed to cache sysfs attribute \"%s\", ignoring: %m",
                                                                        resolved);
                                }
                        }
                        break;
                }
                case TK_A_SYSCTL: {
                        char filename[UTIL_PATH_SIZE];
                        char value[UTIL_NAME_SIZE];
                        int r;

                        if (!apply_format(event, rules, rule, cur, rules_str(rules, cur->key.attr_off), filename, sizeof(filename),
                                          false, properties_list, "sysctl entry name"))
                                break;
                        if (!apply_format(event, rules, rule, cur, rules_str(rules, cur->key.value_off), value, sizeof(value),
                                          false, properties_list, "sysctl value"))
                                break;
                        sysctl_normalize(filename);
                        if (!EVENT_MODE_DESTRUCTIVE(event)) {
                                _cleanup_free_ char *path = NULL;

                                log_event_debug(event, rules, rule, cur,
                                                "Running in test mode, skipping writing \"%s\" to sysctl entry \"%s\".",
                                                value, filename);

                                /* like systemd, not cut; running out of memory stops the processing of the event */
                                path = strjoin("/proc/sys/", filename, NULL);
                                if (!path)
                                        return log_oom();
                                r = verify_regular(path, true);
                                if (r < 0 && !IN_SET(r, -EACCES, -EPERM))
                                        log_event_error_errno(event, rules, rule, cur, r,
                                                              "Failed to verify sysctl entry \"%s\" is a regular file: %m",
                                                              filename);
                                else
                                        event_cache_written_sysctl(event, filename, value);
                                break;
                        }
                        log_event_debug(event, rules, rule, cur, "Writing \"%s\" to sysctl entry \"%s\".", value, filename);
                        r = sysctl_write(filename, value);
                        if (r < 0)
                                log_event_error_errno(event, rules, rule, cur, r,
                                                      "Failed to write \"%s\" to sysctl entry \"%s\", ignoring: %m",
                                                      value, filename);
                        else {
                                event_cache_written_sysctl(event, filename, value);
                                log_event_done(event, rules, rule, cur);
                        }
                        break;
                }
                case TK_A_RUN_BUILTIN:
                case TK_A_RUN_PROGRAM: {
                        struct udev_list_entry *entry;
                        char cmd[UTIL_LINE_SIZE];

                        if (event->run_final) {
                                log_event_final_set(event, rules, rule, cur);
                                break;
                        }
                        if (cur->key.op == OP_ASSIGN_FINAL)
                                event->run_final = true;
                        if (cur->key.op == OP_ASSIGN || cur->key.op == OP_ASSIGN_FINAL)
                                udev_list_cleanup(&event->run_list);

                        if (!apply_format(event, rules, rule, cur, rules_str(rules, cur->key.value_off), cmd, sizeof(cmd),
                                          false, properties_list, "command"))
                                break;

                        log_event_debug(event, rules, rule, cur, "Set command: %s", cmd);
                        /* like systemd, failing to store it stops the processing of the event */
                        entry = udev_list_entry_add(&event->run_list, cmd, NULL);
                        if (entry == NULL)
                                return log_oom();
                        udev_list_entry_set_num(entry, cur->key.builtin_cmd);
                        break;
                }
                case TK_A_STATIC_NODE:
                        /* like systemd, nothing to do for events */
                        break;
                case TK_A_GOTO:
                        if (cur->key.rule_goto == 0)
                                break;
                        /* like systemd, which logs it after the other keys of the line, as here */
                        trace_line(event, rules, rule, "GOTO=%s", rules_str(rules, cur->key.value_off));
                        cur = &rules->tokens[cur->key.rule_goto];
                        continue;
                case TK_END:
                        return 0;

                case TK_M_PARENTS_MIN:
                case TK_M_PARENTS_MAX:
                case TK_M_MAX:
                case TK_UNSET:
                        log_error("wrong type %u", cur->type);
                        goto nomatch;
                }

                /* like systemd, the keys log their result themselves in trace mode */
                cur++;
                continue;
        nomatch:
                /* fast-forward to next rule */
                cur = rule + rule->rule.token_count;
        }
}

int udev_rules_apply_static_dev_perms(struct udev_rules *rules) {
        struct token *cur;
        struct token *rule;
        uid_t uid = UID_INVALID;
        gid_t gid = GID_INVALID;
        mode_t mode = MODE_INVALID;
        _cleanup_strv_free_ char **tags = NULL;
        int r = 0;

        if (rules->tokens == NULL)
                return 0;

        cur = &rules->tokens[0];
        for (;;) {
                switch (cur->type) {
                case TK_RULE:
                        /* current rule */
                        rule = cur;

                        /* skip rules without a static_node tag */
                        if (!rule->rule.has_static_node)
                                goto next;

                        /* like systemd, 0 is a value as any other, e.g. OWNER="root" */
                        uid = UID_INVALID;
                        gid = GID_INVALID;
                        mode = MODE_INVALID;
                        strv_free(tags);
                        tags = NULL;
                        break;
                case TK_A_OWNER_ID:
                        uid = cur->key.uid;
                        break;
                case TK_A_GROUP_ID:
                        gid = cur->key.gid;
                        break;
                case TK_A_MODE_ID:
                        mode = cur->key.mode;
                        break;
                case TK_A_TAG:
                        r = strv_extend(&tags, rules_str(rules, cur->key.value_off));
                        if (r < 0)
                                goto finish;

                        break;
                case TK_A_STATIC_NODE:
                        /* we assure, that the permissions tokens are sorted before the static token */
                        r = static_node_apply_permissions(rules_str(rules, cur->key.value_off),
                                                          mode, uid, gid, tags);
                        if (r < 0)
                                goto finish;
                        break;
                case TK_END:
                        goto finish;
                }

                cur++;
                continue;
next:
                /* fast-forward to next rule */
                cur = rule + rule->rule.token_count;
                continue;
        }

finish:
        return r;
}

#ifdef ENABLE_RULE_GENERATOR
/* function to return the count of rules that assign NAME= to a value matching arg#2 - returns 0,1 */
int udev_rules_assigning_name_to(struct udev_rules *rules, const char *match_name)
{
        struct token *cur;
        /* set by the first token, see udev_rules_apply_to_event() */
        struct token *rule = NULL;

        if (rules->tokens == NULL)
                return 0;

        /* loop through token list, match, run actions or forward to next rule */
        cur = &rules->tokens[0];
        for (;;) {
                dump_token(rules, cur);
                switch (cur->type) {
                case TK_RULE:
                        /* current rule */
                        rule = cur;
                        if (!rule->rule.has_name)
                                goto nomatch;
                        break;
                case TK_M_SUBSYSTEM:
                        if (match_key(rules, cur, "net") != 0)
                                goto nomatch;
                        break;
                case TK_M_ACTION:
                        if (match_key(rules, cur, "add") != 0)
                                goto nomatch;
                        break;
                case TK_A_NAME: {
                        const char *name  = rules_str(rules, cur->key.value_off);
                        char name_str[UTIL_PATH_SIZE];
                        int count;

                        strscpy(name_str,UTIL_PATH_SIZE,name);
                        count = udev_replace_ifname(rules->udev, name_str);
                        if (count > 0)
                                log_debug("%i character(s) replaced\n", count);
                        if (streq(name_str,match_name)) {
                                log_debug("found a match! NAME assigns %s in: %s:%u\n",
                                          name,
                                          rules_str(rules, rule->rule.filename_off),
                                          rule->rule.filename_line);
                                return 1; /* no need to find more than one */
                        }

                        /* skip to next rule */
                        goto nomatch;
                }
                case TK_END:
                        return 0;
                }

                cur++;
                continue;
        nomatch:
                /* fast-forward to next rule */
                cur = rule + rule->rule.token_count;
        }
}
#endif

