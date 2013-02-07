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

#include "udev.h"
#include "path-util.h"
#include "conf-files.h"
#include "strbuf.h"

#define PREALLOC_TOKEN          2048

struct uid_gid {
        unsigned int name_off;
        union {
                uid_t uid;
                gid_t gid;
        };
};

struct udev_rules {
        struct udev *udev;
        char **dirs;
        usec_t *dirs_ts_usec;
        int resolve_names;

        /* every key in the rules file becomes a token */
        struct token *tokens;
        unsigned int token_cur;
        unsigned int token_max;

        /* all key strings are copied and de-duplicated in a single continous string buffer */
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

static unsigned int rules_add_string(struct udev_rules *rules, const char *s) {
        return strbuf_add_string(rules->strbuf, s, strlen(s));
}

/* KEY=="", KEY!="", KEY+="", KEY="", KEY:="" */
enum operation_type {
        OP_UNSET,

        OP_MATCH,
        OP_NOMATCH,
        OP_MATCH_MAX,

        OP_ADD,
        OP_ASSIGN,
        OP_ASSIGN_FINAL,
};

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
        TK_M_WAITFOR,                   /* val */
        TK_M_ATTR,                      /* val, attr */

        TK_M_PARENTS_MIN,
        TK_M_KERNELS,                   /* val */
        TK_M_SUBSYSTEMS,                /* val */
        TK_M_DRIVERS,                   /* val */
        TK_M_ATTRS,                     /* val, attr */
        TK_M_TAGS,                      /* val */
        TK_M_PARENTS_MAX,

        TK_M_TEST,                      /* val, mode_t */
        TK_M_EVENT_TIMEOUT,             /* int */
        TK_M_PROGRAM,                   /* val */
        TK_M_IMPORT_FILE,               /* val */
        TK_M_IMPORT_PROG,               /* val */
        TK_M_IMPORT_BUILTIN,            /* val */
        TK_M_IMPORT_DB,                 /* val */
        TK_M_IMPORT_CMDLINE,            /* val */
        TK_M_IMPORT_PARENT,             /* val */
        TK_M_RESULT,                    /* val */
        TK_M_MAX,

        TK_A_STRING_ESCAPE_NONE,
        TK_A_STRING_ESCAPE_REPLACE,
        TK_A_DB_PERSIST,
        TK_A_INOTIFY_WATCH,             /* int */
        TK_A_DEVLINK_PRIO,              /* int */
        TK_A_OWNER,                     /* val */
        TK_A_GROUP,                     /* val */
        TK_A_MODE,                      /* val */
        TK_A_OWNER_ID,                  /* uid_t */
        TK_A_GROUP_ID,                  /* gid_t */
        TK_A_MODE_ID,                   /* mode_t */
        TK_A_STATIC_NODE,               /* val */
        TK_A_ENV,                       /* val, attr */
        TK_A_TAG,                       /* val */
        TK_A_NAME,                      /* val */
        TK_A_DEVLINK,                   /* val */
        TK_A_ATTR,                      /* val, attr */
        TK_A_RUN_BUILTIN,               /* val, bool */
        TK_A_RUN_PROGRAM,               /* val, bool */
        TK_A_GOTO,                      /* size_t */

        TK_END,
};

/* we try to pack stuff in a way that we take only 12 bytes per token */
struct token {
        union {
                unsigned char type;                /* same in rule and key */
                struct {
                        enum token_type type:8;
                        bool can_set_name:1;
                        bool has_static_node:1;
                        unsigned int unused:6;
                        unsigned short token_count;
                        unsigned int label_off;
                        unsigned short filename_off;
                        unsigned short filename_line;
                } rule;
                struct {
                        enum token_type type:8;
                        enum operation_type op:8;
                        enum string_glob_type glob:8;
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
                                int event_timeout;
                                int watch;
                                enum udev_builtin_cmd builtin_cmd;
                        };
                } key;
        };
};

#define MAX_TK                64
struct rule_tmp {
        struct udev_rules *rules;
        struct token rule;
        struct token token[MAX_TK];
        unsigned int token_cur;
};

#ifdef DEBUG
static const char *operation_str(enum operation_type type)
{
        static const char *operation_strs[] = {
                [OP_UNSET] =            "UNSET",
                [OP_MATCH] =            "match",
                [OP_NOMATCH] =          "nomatch",
                [OP_MATCH_MAX] =        "MATCH_MAX",

                [OP_ADD] =              "add",
                [OP_ASSIGN] =           "assign",
                [OP_ASSIGN_FINAL] =     "assign-final",
}        ;

        return operation_strs[type];
}

static const char *string_glob_str(enum string_glob_type type)
{
        static const char *string_glob_strs[] = {
                [GL_UNSET] =            "UNSET",
                [GL_PLAIN] =            "plain",
                [GL_GLOB] =             "glob",
                [GL_SPLIT] =            "split",
                [GL_SPLIT_GLOB] =       "split-glob",
                [GL_SOMETHING] =        "split-glob",
        };

        return string_glob_strs[type];
}

static const char *token_str(enum token_type type)
{
        static const char *token_strs[] = {
                [TK_UNSET] =                    "UNSET",
                [TK_RULE] =                     "RULE",

                [TK_M_ACTION] =                 "M ACTION",
                [TK_M_DEVPATH] =                "M DEVPATH",
                [TK_M_KERNEL] =                 "M KERNEL",
                [TK_M_DEVLINK] =                "M DEVLINK",
                [TK_M_NAME] =                   "M NAME",
                [TK_M_ENV] =                    "M ENV",
                [TK_M_TAG] =                    "M TAG",
                [TK_M_SUBSYSTEM] =              "M SUBSYSTEM",
                [TK_M_DRIVER] =                 "M DRIVER",
                [TK_M_WAITFOR] =                "M WAITFOR",
                [TK_M_ATTR] =                   "M ATTR",

                [TK_M_PARENTS_MIN] =            "M PARENTS_MIN",
                [TK_M_KERNELS] =                "M KERNELS",
                [TK_M_SUBSYSTEMS] =             "M SUBSYSTEMS",
                [TK_M_DRIVERS] =                "M DRIVERS",
                [TK_M_ATTRS] =                  "M ATTRS",
                [TK_M_TAGS] =                   "M TAGS",
                [TK_M_PARENTS_MAX] =            "M PARENTS_MAX",

                [TK_M_TEST] =                   "M TEST",
                [TK_M_EVENT_TIMEOUT] =          "M EVENT_TIMEOUT",
                [TK_M_PROGRAM] =                "M PROGRAM",
                [TK_M_IMPORT_FILE] =            "M IMPORT_FILE",
                [TK_M_IMPORT_PROG] =            "M IMPORT_PROG",
                [TK_M_IMPORT_BUILTIN] =         "M IMPORT_BUILTIN",
                [TK_M_IMPORT_DB] =              "M IMPORT_DB",
                [TK_M_IMPORT_CMDLINE] =         "M IMPORT_CMDLINE",
                [TK_M_IMPORT_PARENT] =          "M IMPORT_PARENT",
                [TK_M_RESULT] =                 "M RESULT",
                [TK_M_MAX] =                    "M MAX",

                [TK_A_STRING_ESCAPE_NONE] =     "A STRING_ESCAPE_NONE",
                [TK_A_STRING_ESCAPE_REPLACE] =  "A STRING_ESCAPE_REPLACE",
                [TK_A_DB_PERSIST] =             "A DB_PERSIST",
                [TK_A_INOTIFY_WATCH] =          "A INOTIFY_WATCH",
                [TK_A_DEVLINK_PRIO] =           "A DEVLINK_PRIO",
                [TK_A_OWNER] =                  "A OWNER",
                [TK_A_GROUP] =                  "A GROUP",
                [TK_A_MODE] =                   "A MODE",
                [TK_A_OWNER_ID] =               "A OWNER_ID",
                [TK_A_GROUP_ID] =               "A GROUP_ID",
                [TK_A_STATIC_NODE] =            "A STATIC_NODE",
                [TK_A_MODE_ID] =                "A MODE_ID",
                [TK_A_ENV] =                    "A ENV",
                [TK_A_TAG] =                    "A ENV",
                [TK_A_NAME] =                   "A NAME",
                [TK_A_DEVLINK] =                "A DEVLINK",
                [TK_A_ATTR] =                   "A ATTR",
                [TK_A_RUN_BUILTIN] =            "A RUN_BUILTIN",
                [TK_A_RUN_PROGRAM] =            "A RUN_PROGRAM",
                [TK_A_GOTO] =                   "A GOTO",

                [TK_END] =                      "END",
        };

        return token_strs[type];
}

static void dump_token(struct udev_rules *rules, struct token *token)
{
        enum token_type type = token->type;
        enum operation_type op = token->key.op;
        enum string_glob_type glob = token->key.glob;
        const char *value = str(rules, token->key.value_off);
        const char *attr = &rules->buf[token->key.attr_off];

        switch (type) {
        case TK_RULE:
                {
                        const char *tks_ptr = (char *)rules->tokens;
                        const char *tk_ptr = (char *)token;
                        unsigned int idx = (tk_ptr - tks_ptr) / sizeof(struct token);

                        log_debug("* RULE %s:%u, token: %u, count: %u, label: '%s'\n",
                                  &rules->buf[token->rule.filename_off], token->rule.filename_line,
                                  idx, token->rule.token_count,
                                  &rules->buf[token->rule.label_off]);
                        break;
                }
        case TK_M_ACTION:
        case TK_M_DEVPATH:
        case TK_M_KERNEL:
        case TK_M_SUBSYSTEM:
        case TK_M_DRIVER:
        case TK_M_WAITFOR:
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
        case TK_A_NAME:
        case TK_A_DEVLINK:
        case TK_A_OWNER:
        case TK_A_GROUP:
        case TK_A_MODE:
        case TK_A_RUN_BUILTIN:
        case TK_A_RUN_PROGRAM:
                log_debug("%s %s '%s'(%s)\n",
                          token_str(type), operation_str(op), value, string_glob_str(glob));
                break;
        case TK_M_IMPORT_BUILTIN:
                log_debug("%s %i '%s'\n", token_str(type), token->key.builtin_cmd, value);
                break;
        case TK_M_ATTR:
        case TK_M_ATTRS:
        case TK_M_ENV:
        case TK_A_ATTR:
        case TK_A_ENV:
                log_debug("%s %s '%s' '%s'(%s)\n",
                          token_str(type), operation_str(op), attr, value, string_glob_str(glob));
                break;
        case TK_M_TAG:
        case TK_A_TAG:
                log_debug("%s %s '%s'\n", token_str(type), operation_str(op), value);
                break;
        case TK_A_STRING_ESCAPE_NONE:
        case TK_A_STRING_ESCAPE_REPLACE:
        case TK_A_DB_PERSIST:
                log_debug("%s\n", token_str(type));
                break;
        case TK_M_TEST:
                log_debug("%s %s '%s'(%s) %#o\n",
                          token_str(type), operation_str(op), value, string_glob_str(glob), token->key.mode);
                break;
        case TK_A_INOTIFY_WATCH:
                log_debug("%s %u\n", token_str(type), token->key.watch);
                break;
        case TK_A_DEVLINK_PRIO:
                log_debug("%s %u\n", token_str(type), token->key.devlink_prio);
                break;
        case TK_A_OWNER_ID:
                log_debug("%s %s %u\n", token_str(type), operation_str(op), token->key.uid);
                break;
        case TK_A_GROUP_ID:
                log_debug("%s %s %u\n", token_str(type), operation_str(op), token->key.gid);
                break;
        case TK_A_MODE_ID:
                log_debug("%s %s %#o\n", token_str(type), operation_str(op), token->key.mode);
                break;
        case TK_A_STATIC_NODE:
                log_debug("%s '%s'\n", token_str(type), value);
                break;
        case TK_M_EVENT_TIMEOUT:
                log_debug("%s %u\n", token_str(type), token->key.event_timeout);
                break;
        case TK_A_GOTO:
                log_debug("%s '%s' %u\n", token_str(type), value, token->key.rule_goto);
                break;
        case TK_END:
                log_debug("* %s\n", token_str(type));
                break;
        case TK_M_PARENTS_MIN:
        case TK_M_PARENTS_MAX:
        case TK_M_MAX:
        case TK_UNSET:
                log_debug("unknown type %u\n", type);
                break;
        }
}

static void dump_rules(struct udev_rules *rules)
{
        unsigned int i;

        log_debug("dumping %u (%zu bytes) tokens, %u (%zu bytes) strings\n",
                  rules->token_cur,
                  rules->token_cur * sizeof(struct token),
                  rules->buf_count,
                  rules->buf_cur);
        for(i = 0; i < rules->token_cur; i++)
                dump_token(rules, &rules->tokens[i]);
}
#else
static inline const char *operation_str(enum operation_type type) { return NULL; }
static inline const char *token_str(enum token_type type) { return NULL; }
static inline void dump_token(struct udev_rules *rules, struct token *token) {}
static inline void dump_rules(struct udev_rules *rules) {}
#endif /* DEBUG */

static int add_token(struct udev_rules *rules, struct token *token)
{
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

static uid_t add_uid(struct udev_rules *rules, const char *owner)
{
        unsigned int i;
        uid_t uid;
        unsigned int off;

        /* lookup, if we know it already */
        for (i = 0; i < rules->uids_cur; i++) {
                off = rules->uids[i].name_off;
                if (streq(rules_str(rules, off), owner)) {
                        uid = rules->uids[i].uid;
                        return uid;
                }
        }
        uid = util_lookup_user(rules->udev, owner);

        /* grow buffer if needed */
        if (rules->uids_cur+1 >= rules->uids_max) {
                struct uid_gid *uids;
                unsigned int add;

                /* double the buffer size */
                add = rules->uids_max;
                if (add < 1)
                        add = 8;

                uids = realloc(rules->uids, (rules->uids_max + add ) * sizeof(struct uid_gid));
                if (uids == NULL)
                        return uid;
                rules->uids = uids;
                rules->uids_max += add;
        }
        rules->uids[rules->uids_cur].uid = uid;
        off = rules_add_string(rules, owner);
        if (off <= 0)
                return uid;
        rules->uids[rules->uids_cur].name_off = off;
        rules->uids_cur++;
        return uid;
}

static gid_t add_gid(struct udev_rules *rules, const char *group)
{
        unsigned int i;
        gid_t gid;
        unsigned int off;

        /* lookup, if we know it already */
        for (i = 0; i < rules->gids_cur; i++) {
                off = rules->gids[i].name_off;
                if (streq(rules_str(rules, off), group)) {
                        gid = rules->gids[i].gid;
                        return gid;
                }
        }
        gid = util_lookup_group(rules->udev, group);

        /* grow buffer if needed */
        if (rules->gids_cur+1 >= rules->gids_max) {
                struct uid_gid *gids;
                unsigned int add;

                /* double the buffer size */
                add = rules->gids_max;
                if (add < 1)
                        add = 8;

                gids = realloc(rules->gids, (rules->gids_max + add ) * sizeof(struct uid_gid));
                if (gids == NULL)
                        return gid;
                rules->gids = gids;
                rules->gids_max += add;
        }
        rules->gids[rules->gids_cur].gid = gid;
        off = rules_add_string(rules, group);
        if (off <= 0)
                return gid;
        rules->gids[rules->gids_cur].name_off = off;
        rules->gids_cur++;
        return gid;
}

static int import_property_from_string(struct udev_device *dev, char *line)
{
        char *key;
        char *val;
        size_t len;

        /* find key */
        key = line;
        while (isspace(key[0]))
                key++;

        /* comment or empty line */
        if (key[0] == '#' || key[0] == '\0')
                return -1;

        /* split key/value */
        val = strchr(key, '=');
        if (val == NULL)
                return -1;
        val[0] = '\0';
        val++;

        /* find value */
        while (isspace(val[0]))
                val++;

        /* terminate key */
        len = strlen(key);
        if (len == 0)
                return -1;
        while (isspace(key[len-1]))
                len--;
        key[len] = '\0';

        /* terminate value */
        len = strlen(val);
        if (len == 0)
                return -1;
        while (isspace(val[len-1]))
                len--;
        val[len] = '\0';

        if (len == 0)
                return -1;

        /* unquote */
        if (val[0] == '"' || val[0] == '\'') {
                if (val[len-1] != val[0]) {
                        log_debug("inconsistent quoting: '%s', skip\n", line);
                        return -1;
                }
                val[len-1] = '\0';
                val++;
        }

        /* handle device, renamed by external tool, returning new path */
        if (streq(key, "DEVPATH")) {
                char syspath[UTIL_PATH_SIZE];

                log_debug("updating devpath from '%s' to '%s'\n",
                          udev_device_get_devpath(dev), val);
                util_strscpyl(syspath, sizeof(syspath), "/sys", val, NULL);
                udev_device_set_syspath(dev, syspath);
        } else {
                struct udev_list_entry *entry;

                entry = udev_device_add_property(dev, key, val);
                /* store in db, skip private keys */
                if (key[0] != '.')
                        udev_list_entry_set_num(entry, true);
        }
        return 0;
}

static int import_file_into_properties(struct udev_device *dev, const char *filename)
{
        FILE *f;
        char line[UTIL_LINE_SIZE];

        f = fopen(filename, "re");
        if (f == NULL)
                return -1;
        while (fgets(line, sizeof(line), f) != NULL)
                import_property_from_string(dev, line);
        fclose(f);
        return 0;
}

static int import_program_into_properties(struct udev_event *event, const char *program, const sigset_t *sigmask)
{
        struct udev_device *dev = event->dev;
        char **envp;
        char result[UTIL_LINE_SIZE];
        char *line;
        int err;

        envp = udev_device_get_properties_envp(dev);
        err = udev_event_spawn(event, program, envp, sigmask, result, sizeof(result));
        if (err < 0)
                return err;

        line = result;
        while (line != NULL) {
                char *pos;

                pos = strchr(line, '\n');
                if (pos != NULL) {
                        pos[0] = '\0';
                        pos = &pos[1];
                }
                import_property_from_string(dev, line);
                line = pos;
        }
        return 0;
}

static int import_parent_into_properties(struct udev_device *dev, const char *filter)
{
        struct udev_device *dev_parent;
        struct udev_list_entry *list_entry;

        dev_parent = udev_device_get_parent(dev);
        if (dev_parent == NULL)
                return -1;

        udev_list_entry_foreach(list_entry, udev_device_get_properties_list_entry(dev_parent)) {
                const char *key = udev_list_entry_get_name(list_entry);
                const char *val = udev_list_entry_get_value(list_entry);

                if (fnmatch(filter, key, 0) == 0) {
                        struct udev_list_entry *entry;

                        entry = udev_device_add_property(dev, key, val);
                        /* store in db, skip private keys */
                        if (key[0] != '.')
                                udev_list_entry_set_num(entry, true);
                }
        }
        return 0;
}

#define WAIT_LOOP_PER_SECOND                50
static int wait_for_file(struct udev_device *dev, const char *file, int timeout)
{
        char filepath[UTIL_PATH_SIZE];
        char devicepath[UTIL_PATH_SIZE];
        struct stat stats;
        int loop = timeout * WAIT_LOOP_PER_SECOND;

        /* a relative path is a device attribute */
        devicepath[0] = '\0';
        if (file[0] != '/') {
                util_strscpyl(devicepath, sizeof(devicepath), udev_device_get_syspath(dev), NULL);
                util_strscpyl(filepath, sizeof(filepath), devicepath, "/", file, NULL);
                file = filepath;
        }

        while (--loop) {
                const struct timespec duration = { 0, 1000 * 1000 * 1000 / WAIT_LOOP_PER_SECOND };

                /* lookup file */
                if (stat(file, &stats) == 0) {
                        log_debug("file '%s' appeared after %i loops\n", file, (timeout * WAIT_LOOP_PER_SECOND) - loop-1);
                        return 0;
                }
                /* make sure, the device did not disappear in the meantime */
                if (devicepath[0] != '\0' && stat(devicepath, &stats) != 0) {
                        log_debug("device disappeared while waiting for '%s'\n", file);
                        return -2;
                }
                log_debug("wait for '%s' for %i mseconds\n", file, 1000 / WAIT_LOOP_PER_SECOND);
                nanosleep(&duration, NULL);
        }
        log_debug("waiting for '%s' failed\n", file);
        return -1;
}

static int attr_subst_subdir(char *attr, size_t len)
{
        bool found = false;

        if (strstr(attr, "/*/")) {
                char *pos;
                char dirname[UTIL_PATH_SIZE];
                const char *tail;
                DIR *dir;

                util_strscpy(dirname, sizeof(dirname), attr);
                pos = strstr(dirname, "/*/");
                if (pos == NULL)
                        return -1;
                pos[0] = '\0';
                tail = &pos[2];
                dir = opendir(dirname);
                if (dir != NULL) {
                        struct dirent *dent;

                        for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
                                struct stat stats;

                                if (dent->d_name[0] == '.')
                                        continue;
                                util_strscpyl(attr, len, dirname, "/", dent->d_name, tail, NULL);
                                if (stat(attr, &stats) == 0) {
                                        found = true;
                                        break;
                                }
                        }
                        closedir(dir);
                }
        }

        return found;
}

static int get_key(struct udev *udev, char **line, char **key, enum operation_type *op, char **value)
{
        char *linepos;
        char *temp;

        linepos = *line;
        if (linepos == NULL || linepos[0] == '\0')
                return -1;

        /* skip whitespace */
        while (isspace(linepos[0]) || linepos[0] == ',')
                linepos++;

        /* get the key */
        if (linepos[0] == '\0')
                return -1;
        *key = linepos;

        for (;;) {
                linepos++;
                if (linepos[0] == '\0')
                        return -1;
                if (isspace(linepos[0]))
                        break;
                if (linepos[0] == '=')
                        break;
                if ((linepos[0] == '+') || (linepos[0] == '!') || (linepos[0] == ':'))
                        if (linepos[1] == '=')
                                break;
        }

        /* remember end of key */
        temp = linepos;

        /* skip whitespace after key */
        while (isspace(linepos[0]))
                linepos++;
        if (linepos[0] == '\0')
                return -1;

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
        } else if (linepos[0] == '=') {
                *op = OP_ASSIGN;
                linepos++;
        } else if (linepos[0] == ':' && linepos[1] == '=') {
                *op = OP_ASSIGN_FINAL;
                linepos += 2;
        } else
                return -1;

        /* terminate key */
        temp[0] = '\0';

        /* skip whitespace after operator */
        while (isspace(linepos[0]))
                linepos++;
        if (linepos[0] == '\0')
                return -1;

        /* get the value */
        if (linepos[0] == '"')
                linepos++;
        else
                return -1;
        *value = linepos;

        /* terminate */
        temp = strchr(linepos, '"');
        if (!temp)
                return -1;
        temp[0] = '\0';
        temp++;

        /* move line to next key */
        *line = temp;
        return 0;
}

/* extract possible KEY{attr} */
static const char *get_key_attribute(struct udev *udev, char *str)
{
        char *pos;
        char *attr;

        attr = strchr(str, '{');
        if (attr != NULL) {
                attr++;
                pos = strchr(attr, '}');
                if (pos == NULL) {
                        log_error("missing closing brace for format\n");
                        return NULL;
                }
                pos[0] = '\0';
                return attr;
        }
        return NULL;
}

static int rule_add_key(struct rule_tmp *rule_tmp, enum token_type type,
                        enum operation_type op,
                        const char *value, const void *data)
{
        struct token *token = &rule_tmp->token[rule_tmp->token_cur];
        const char *attr = NULL;

        memset(token, 0x00, sizeof(struct token));

        switch (type) {
        case TK_M_ACTION:
        case TK_M_DEVPATH:
        case TK_M_KERNEL:
        case TK_M_SUBSYSTEM:
        case TK_M_DRIVER:
        case TK_M_WAITFOR:
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
                token->key.value_off = rules_add_string(rule_tmp->rules, value);
                break;
        case TK_M_IMPORT_BUILTIN:
                token->key.value_off = rules_add_string(rule_tmp->rules, value);
                token->key.builtin_cmd = *(enum udev_builtin_cmd *)data;
                break;
        case TK_M_ENV:
        case TK_M_ATTR:
        case TK_M_ATTRS:
        case TK_A_ATTR:
        case TK_A_ENV:
                attr = data;
                token->key.value_off = rules_add_string(rule_tmp->rules, value);
                token->key.attr_off = rules_add_string(rule_tmp->rules, attr);
                break;
        case TK_M_TEST:
                token->key.value_off = rules_add_string(rule_tmp->rules, value);
                if (data != NULL)
                        token->key.mode = *(mode_t *)data;
                break;
        case TK_A_STRING_ESCAPE_NONE:
        case TK_A_STRING_ESCAPE_REPLACE:
        case TK_A_DB_PERSIST:
                break;
        case TK_A_RUN_BUILTIN:
        case TK_A_RUN_PROGRAM:
                token->key.builtin_cmd = *(enum udev_builtin_cmd *)data;
                token->key.value_off = rules_add_string(rule_tmp->rules, value);
                break;
        case TK_A_INOTIFY_WATCH:
        case TK_A_DEVLINK_PRIO:
                token->key.devlink_prio = *(int *)data;
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
        case TK_A_STATIC_NODE:
                token->key.value_off = rules_add_string(rule_tmp->rules, value);
                break;
        case TK_M_EVENT_TIMEOUT:
                token->key.event_timeout = *(int *)data;
                break;
        case TK_RULE:
        case TK_M_PARENTS_MIN:
        case TK_M_PARENTS_MAX:
        case TK_M_MAX:
        case TK_END:
        case TK_UNSET:
                log_error("wrong type %u\n", type);
                return -1;
        }

        if (value != NULL && type < TK_M_MAX) {
                /* check if we need to split or call fnmatch() while matching rules */
                enum string_glob_type glob;
                int has_split;
                int has_glob;

                has_split = (strchr(value, '|') != NULL);
                has_glob = (strchr(value, '*') != NULL || strchr(value, '?') != NULL || strchr(value, '[') != NULL);
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
                /* check if property/attribut name has substitution chars */
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
        if (rule_tmp->token_cur >= ELEMENTSOF(rule_tmp->token)) {
                log_error("temporary rule array too small\n");
                return -1;
        }
        return 0;
}

static int sort_token(struct udev_rules *rules, struct rule_tmp *rule_tmp)
{
        unsigned int i;
        unsigned int start = 0;
        unsigned int end = rule_tmp->token_cur;

        for (i = 0; i < rule_tmp->token_cur; i++) {
                enum token_type next_val = TK_UNSET;
                unsigned int next_idx = 0;
                unsigned int j;

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

static int add_rule(struct udev_rules *rules, char *line,
                    const char *filename, unsigned int filename_off, unsigned int lineno)
{
        char *linepos;
        const char *attr;
        struct rule_tmp rule_tmp;

        memset(&rule_tmp, 0x00, sizeof(struct rule_tmp));
        rule_tmp.rules = rules;
        rule_tmp.rule.type = TK_RULE;
        /* the offset in the rule is limited to unsigned short */
        if (filename_off < USHRT_MAX)
                rule_tmp.rule.rule.filename_off = filename_off;
        rule_tmp.rule.rule.filename_line = lineno;

        linepos = line;
        for (;;) {
                char *key;
                char *value;
                enum operation_type op;

                if (get_key(rules->udev, &linepos, &key, &op, &value) != 0)
                        break;

                if (streq(key, "ACTION")) {
                        if (op > OP_MATCH_MAX) {
                                log_error("invalid ACTION operation\n");
                                goto invalid;
                        }
                        rule_add_key(&rule_tmp, TK_M_ACTION, op, value, NULL);
                        continue;
                }

                if (streq(key, "DEVPATH")) {
                        if (op > OP_MATCH_MAX) {
                                log_error("invalid DEVPATH operation\n");
                                goto invalid;
                        }
                        rule_add_key(&rule_tmp, TK_M_DEVPATH, op, value, NULL);
                        continue;
                }

                if (streq(key, "KERNEL")) {
                        if (op > OP_MATCH_MAX) {
                                log_error("invalid KERNEL operation\n");
                                goto invalid;
                        }
                        rule_add_key(&rule_tmp, TK_M_KERNEL, op, value, NULL);
                        continue;
                }

                if (streq(key, "SUBSYSTEM")) {
                        if (op > OP_MATCH_MAX) {
                                log_error("invalid SUBSYSTEM operation\n");
                                goto invalid;
                        }
                        /* bus, class, subsystem events should all be the same */
                        if (streq(value, "subsystem") ||
                            streq(value, "bus") ||
                            streq(value, "class")) {
                                if (streq(value, "bus") || streq(value, "class"))
                                        log_error("'%s' must be specified as 'subsystem' \n"
                                            "please fix it in %s:%u", value, filename, lineno);
                                rule_add_key(&rule_tmp, TK_M_SUBSYSTEM, op, "subsystem|class|bus", NULL);
                        } else
                                rule_add_key(&rule_tmp, TK_M_SUBSYSTEM, op, value, NULL);
                        continue;
                }

                if (streq(key, "DRIVER")) {
                        if (op > OP_MATCH_MAX) {
                                log_error("invalid DRIVER operation\n");
                                goto invalid;
                        }
                        rule_add_key(&rule_tmp, TK_M_DRIVER, op, value, NULL);
                        continue;
                }

                if (startswith(key, "ATTR{")) {
                        attr = get_key_attribute(rules->udev, key + sizeof("ATTR")-1);
                        if (attr == NULL) {
                                log_error("error parsing ATTR attribute\n");
                                goto invalid;
                        }
                        if (op < OP_MATCH_MAX) {
                                rule_add_key(&rule_tmp, TK_M_ATTR, op, value, attr);
                        } else {
                                rule_add_key(&rule_tmp, TK_A_ATTR, op, value, attr);
                        }
                        continue;
                }

                if (streq(key, "KERNELS")) {
                        if (op > OP_MATCH_MAX) {
                                log_error("invalid KERNELS operation\n");
                                goto invalid;
                        }
                        rule_add_key(&rule_tmp, TK_M_KERNELS, op, value, NULL);
                        continue;
                }

                if (streq(key, "SUBSYSTEMS")) {
                        if (op > OP_MATCH_MAX) {
                                log_error("invalid SUBSYSTEMS operation\n");
                                goto invalid;
                        }
                        rule_add_key(&rule_tmp, TK_M_SUBSYSTEMS, op, value, NULL);
                        continue;
                }

                if (streq(key, "DRIVERS")) {
                        if (op > OP_MATCH_MAX) {
                                log_error("invalid DRIVERS operation\n");
                                goto invalid;
                        }
                        rule_add_key(&rule_tmp, TK_M_DRIVERS, op, value, NULL);
                        continue;
                }

                if (startswith(key, "ATTRS{")) {
                        if (op > OP_MATCH_MAX) {
                                log_error("invalid ATTRS operation\n");
                                goto invalid;
                        }
                        attr = get_key_attribute(rules->udev, key + sizeof("ATTRS")-1);
                        if (attr == NULL) {
                                log_error("error parsing ATTRS attribute\n");
                                goto invalid;
                        }
                        if (startswith(attr, "device/"))
                                log_error("the 'device' link may not be available in a future kernel, "
                                    "please fix it in %s:%u", filename, lineno);
                        else if (strstr(attr, "../") != NULL)
                                log_error("do not reference parent sysfs directories directly, "
                                    "it may break with a future kernel, please fix it in %s:%u", filename, lineno);
                        rule_add_key(&rule_tmp, TK_M_ATTRS, op, value, attr);
                        continue;
                }

                if (streq(key, "TAGS")) {
                        if (op > OP_MATCH_MAX) {
                                log_error("invalid TAGS operation\n");
                                goto invalid;
                        }
                        rule_add_key(&rule_tmp, TK_M_TAGS, op, value, NULL);
                        continue;
                }

                if (startswith(key, "ENV{")) {
                        attr = get_key_attribute(rules->udev, key + sizeof("ENV")-1);
                        if (attr == NULL) {
                                log_error("error parsing ENV attribute\n");
                                goto invalid;
                        }
                        if (op < OP_MATCH_MAX) {
                                if (rule_add_key(&rule_tmp, TK_M_ENV, op, value, attr) != 0)
                                        goto invalid;
                        } else {
                                static const char *blacklist[] = {
                                        "ACTION",
                                        "SUBSYSTEM",
                                        "DEVTYPE",
                                        "MAJOR",
                                        "MINOR",
                                        "DRIVER",
                                        "IFINDEX",
                                        "DEVNAME",
                                        "DEVLINKS",
                                        "DEVPATH",
                                        "TAGS",
                                };
                                unsigned int i;

                                for (i = 0; i < ELEMENTSOF(blacklist); i++) {
                                        if (!streq(attr, blacklist[i]))
                                                continue;
                                        log_error("invalid ENV attribute, '%s' can not be set %s:%u\n", attr, filename, lineno);
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
                        rule_add_key(&rule_tmp, TK_M_PROGRAM, op, value, NULL);
                        continue;
                }

                if (streq(key, "RESULT")) {
                        if (op > OP_MATCH_MAX) {
                                log_error("invalid RESULT operation\n");
                                goto invalid;
                        }
                        rule_add_key(&rule_tmp, TK_M_RESULT, op, value, NULL);
                        continue;
                }

                if (startswith(key, "IMPORT")) {
                        attr = get_key_attribute(rules->udev, key + sizeof("IMPORT")-1);
                        if (attr == NULL) {
                                log_error("IMPORT{} type missing, ignoring IMPORT %s:%u\n", filename, lineno);
                                continue;
                        }
                        if (streq(attr, "program")) {
                                /* find known built-in command */
                                if (value[0] != '/') {
                                        enum udev_builtin_cmd cmd;

                                        cmd = udev_builtin_lookup(value);
                                        if (cmd < UDEV_BUILTIN_MAX) {
                                                log_debug("IMPORT found builtin '%s', replacing %s:%u\n",
                                                          value, filename, lineno);
                                                rule_add_key(&rule_tmp, TK_M_IMPORT_BUILTIN, op, value, &cmd);
                                                continue;
                                        }
                                }
                                rule_add_key(&rule_tmp, TK_M_IMPORT_PROG, op, value, NULL);
                        } else if (streq(attr, "builtin")) {
                                enum udev_builtin_cmd cmd = udev_builtin_lookup(value);

                                if (cmd < UDEV_BUILTIN_MAX)
                                        rule_add_key(&rule_tmp, TK_M_IMPORT_BUILTIN, op, value, &cmd);
                                else
                                        log_error("IMPORT{builtin}: '%s' unknown %s:%u\n", value, filename, lineno);
                        } else if (streq(attr, "file")) {
                                rule_add_key(&rule_tmp, TK_M_IMPORT_FILE, op, value, NULL);
                        } else if (streq(attr, "db")) {
                                rule_add_key(&rule_tmp, TK_M_IMPORT_DB, op, value, NULL);
                        } else if (streq(attr, "cmdline")) {
                                rule_add_key(&rule_tmp, TK_M_IMPORT_CMDLINE, op, value, NULL);
                        } else if (streq(attr, "parent")) {
                                rule_add_key(&rule_tmp, TK_M_IMPORT_PARENT, op, value, NULL);
                        } else
                                log_error("IMPORT{} unknown type, ignoring IMPORT %s:%u\n", filename, lineno);
                        continue;
                }

                if (startswith(key, "TEST")) {
                        mode_t mode = 0;

                        if (op > OP_MATCH_MAX) {
                                log_error("invalid TEST operation\n");
                                goto invalid;
                        }
                        attr = get_key_attribute(rules->udev, key + sizeof("TEST")-1);
                        if (attr != NULL) {
                                mode = strtol(attr, NULL, 8);
                                rule_add_key(&rule_tmp, TK_M_TEST, op, value, &mode);
                        } else {
                                rule_add_key(&rule_tmp, TK_M_TEST, op, value, NULL);
                        }
                        continue;
                }

                if (startswith(key, "RUN")) {
                        attr = get_key_attribute(rules->udev, key + sizeof("RUN")-1);
                        if (attr == NULL)
                                attr = "program";

                        if (streq(attr, "builtin")) {
                                enum udev_builtin_cmd cmd = udev_builtin_lookup(value);

                                if (cmd < UDEV_BUILTIN_MAX)
                                        rule_add_key(&rule_tmp, TK_A_RUN_BUILTIN, op, value, &cmd);
                                else
                                        log_error("IMPORT{builtin}: '%s' unknown %s:%u\n", value, filename, lineno);
                        } else if (streq(attr, "program")) {
                                enum udev_builtin_cmd cmd = UDEV_BUILTIN_MAX;

                                rule_add_key(&rule_tmp, TK_A_RUN_PROGRAM, op, value, &cmd);
                        } else {
                                log_error("RUN{} unknown type, ignoring RUN %s:%u\n", filename, lineno);
                        }

                        continue;
                }

                if (streq(key, "WAIT_FOR") || streq(key, "WAIT_FOR_SYSFS")) {
                        rule_add_key(&rule_tmp, TK_M_WAITFOR, 0, value, NULL);
                        continue;
                }

                if (streq(key, "LABEL")) {
                        rule_tmp.rule.rule.label_off = rules_add_string(rules, value);
                        continue;
                }

                if (streq(key, "GOTO")) {
                        rule_add_key(&rule_tmp, TK_A_GOTO, 0, value, NULL);
                        continue;
                }

                if (startswith(key, "NAME")) {
                        if (op < OP_MATCH_MAX) {
                                rule_add_key(&rule_tmp, TK_M_NAME, op, value, NULL);
                        } else {
                                if (streq(value, "%k")) {
                                        log_error("NAME=\"%%k\" is ignored, because it breaks kernel supplied names, "
                                            "please remove it from %s:%u\n", filename, lineno);
                                        continue;
                                }
                                if (value[0] == '\0') {
                                        log_debug("NAME=\"\" is ignored, because udev will not delete any device nodes, "
                                                  "please remove it from %s:%u\n", filename, lineno);
                                        continue;
                                }
                                rule_add_key(&rule_tmp, TK_A_NAME, op, value, NULL);
                        }
                        rule_tmp.rule.rule.can_set_name = true;
                        continue;
                }

                if (streq(key, "SYMLINK")) {
                        if (op < OP_MATCH_MAX)
                                rule_add_key(&rule_tmp, TK_M_DEVLINK, op, value, NULL);
                        else
                                rule_add_key(&rule_tmp, TK_A_DEVLINK, op, value, NULL);
                        rule_tmp.rule.rule.can_set_name = true;
                        continue;
                }

                if (streq(key, "OWNER")) {
                        uid_t uid;
                        char *endptr;

                        uid = strtoul(value, &endptr, 10);
                        if (endptr[0] == '\0') {
                                rule_add_key(&rule_tmp, TK_A_OWNER_ID, op, NULL, &uid);
                        } else if ((rules->resolve_names > 0) && strchr("$%", value[0]) == NULL) {
                                uid = add_uid(rules, value);
                                rule_add_key(&rule_tmp, TK_A_OWNER_ID, op, NULL, &uid);
                        } else if (rules->resolve_names >= 0) {
                                rule_add_key(&rule_tmp, TK_A_OWNER, op, value, NULL);
                        }
                        rule_tmp.rule.rule.can_set_name = true;
                        continue;
                }

                if (streq(key, "GROUP")) {
                        gid_t gid;
                        char *endptr;

                        gid = strtoul(value, &endptr, 10);
                        if (endptr[0] == '\0') {
                                rule_add_key(&rule_tmp, TK_A_GROUP_ID, op, NULL, &gid);
                        } else if ((rules->resolve_names > 0) && strchr("$%", value[0]) == NULL) {
                                gid = add_gid(rules, value);
                                rule_add_key(&rule_tmp, TK_A_GROUP_ID, op, NULL, &gid);
                        } else if (rules->resolve_names >= 0) {
                                rule_add_key(&rule_tmp, TK_A_GROUP, op, value, NULL);
                        }
                        rule_tmp.rule.rule.can_set_name = true;
                        continue;
                }

                if (streq(key, "MODE")) {
                        mode_t mode;
                        char *endptr;

                        mode = strtol(value, &endptr, 8);
                        if (endptr[0] == '\0')
                                rule_add_key(&rule_tmp, TK_A_MODE_ID, op, NULL, &mode);
                        else
                                rule_add_key(&rule_tmp, TK_A_MODE, op, value, NULL);
                        rule_tmp.rule.rule.can_set_name = true;
                        continue;
                }

                if (streq(key, "OPTIONS")) {
                        const char *pos;

                        pos = strstr(value, "link_priority=");
                        if (pos != NULL) {
                                int prio = atoi(&pos[strlen("link_priority=")]);

                                rule_add_key(&rule_tmp, TK_A_DEVLINK_PRIO, op, NULL, &prio);
                        }

                        pos = strstr(value, "event_timeout=");
                        if (pos != NULL) {
                                int tout = atoi(&pos[strlen("event_timeout=")]);

                                rule_add_key(&rule_tmp, TK_M_EVENT_TIMEOUT, op, NULL, &tout);
                        }

                        pos = strstr(value, "string_escape=");
                        if (pos != NULL) {
                                pos = &pos[strlen("string_escape=")];
                                if (startswith(pos, "none"))
                                        rule_add_key(&rule_tmp, TK_A_STRING_ESCAPE_NONE, op, NULL, NULL);
                                else if (startswith(pos, "replace"))
                                        rule_add_key(&rule_tmp, TK_A_STRING_ESCAPE_REPLACE, op, NULL, NULL);
                        }

                        pos = strstr(value, "db_persist");
                        if (pos != NULL)
                                rule_add_key(&rule_tmp, TK_A_DB_PERSIST, op, NULL, NULL);

                        pos = strstr(value, "nowatch");
                        if (pos != NULL) {
                                const int off = 0;

                                rule_add_key(&rule_tmp, TK_A_INOTIFY_WATCH, op, NULL, &off);
                        } else {
                                pos = strstr(value, "watch");
                                if (pos != NULL) {
                                        const int on = 1;

                                        rule_add_key(&rule_tmp, TK_A_INOTIFY_WATCH, op, NULL, &on);
                                }
                        }

                        pos = strstr(value, "static_node=");
                        if (pos != NULL) {
                                rule_add_key(&rule_tmp, TK_A_STATIC_NODE, op, &pos[strlen("static_node=")], NULL);
                                rule_tmp.rule.rule.has_static_node = true;
                        }

                        continue;
                }

                log_error("unknown key '%s' in %s:%u\n", key, filename, lineno);
                goto invalid;
        }

        /* add rule token */
        rule_tmp.rule.rule.token_count = 1 + rule_tmp.token_cur;
        if (add_token(rules, &rule_tmp.rule) != 0)
                goto invalid;

        /* add tokens to list, sorted by type */
        if (sort_token(rules, &rule_tmp) != 0)
                goto invalid;

        return 0;
invalid:
        log_error("invalid rule '%s:%u'\n", filename, lineno);
        return -1;
}

static int parse_file(struct udev_rules *rules, const char *filename)
{
        FILE *f;
        unsigned int first_token;
        unsigned int filename_off;
        char line[UTIL_LINE_SIZE];
        int line_nr = 0;
        unsigned int i;

        if (null_or_empty_path(filename)) {
                log_debug("skip empty file: %s\n", filename);
                return 0;
        }
        log_debug("read rules file: %s\n", filename);

        f = fopen(filename, "re");
        if (f == NULL)
                return -1;

        first_token = rules->token_cur;
        filename_off = rules_add_string(rules, filename);

        while (fgets(line, sizeof(line), f) != NULL) {
                char *key;
                size_t len;

                /* skip whitespace */
                line_nr++;
                key = line;
                while (isspace(key[0]))
                        key++;

                /* comment */
                if (key[0] == '#')
                        continue;

                len = strlen(line);
                if (len < 3)
                        continue;

                /* continue reading if backslash+newline is found */
                while (line[len-2] == '\\') {
                        if (fgets(&line[len-2], (sizeof(line)-len)+2, f) == NULL)
                                break;
                        if (strlen(&line[len-2]) < 2)
                                break;
                        line_nr++;
                        len = strlen(line);
                }

                if (len+1 >= sizeof(line)) {
                        log_error("line too long '%s':%u, ignored\n", filename, line_nr);
                        continue;
                }
                add_rule(rules, key, filename, filename_off, line_nr);
        }
        fclose(f);

        /* link GOTOs to LABEL rules in this file to be able to fast-forward */
        for (i = first_token+1; i < rules->token_cur; i++) {
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
                        if (rules->tokens[i].key.rule_goto == 0)
                                log_error("GOTO '%s' has no matching label in: '%s'\n", label, filename);
                }
        }
        return 0;
}

struct udev_rules *udev_rules_new(struct udev *udev, int resolve_names)
{
        struct udev_rules *rules;
        struct udev_list file_list;
        struct token end_token;
        char **files, **f;
        int r;

        rules = calloc(1, sizeof(struct udev_rules));
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

	/* Note - need a better way to manage these paths:
	 * ie, should have a list of paths we always support, and
	 * do not include the #define vars if they are duplicates
	 *
	 * original - UDEV_RULES_DIR should be /etc/udev/rules.d
	 * ..but we have it set to UDEV_LIBEXEC_DIR "/rules.d" so that
	 * ..the default rules are installed there instead of in /etc
	 * 
	 * original2 - UDEV_LIBEXEC_DIR used to be forced to /usr/lib/udev
	 * ..by default, we have it as /lib/udev (or whatever rootlibdir is)
	 * ..therefore we did not include /usr/lib/udev/rules.d.
	 * 
	 * Reworked code; there are duplicate paths here but at least
	 * everyting is listed.
	 */
        rules->dirs = strv_new(UDEV_CONF_DIR "/rules.d",
                               UDEV_RULES_DIR,
                               "/run/udev/rules.d",
                               UDEV_LIBEXEC_DIR "/rules.d",
#ifdef HAVE_SPLIT_USR
                               "/lib/udev/rules.d",
                               "/usr/lib/udev/rules.d",
#endif
                               NULL);
        if (!rules->dirs) {
                log_error("failed to build config directory array");
                return udev_rules_unref(rules);
        }
        if (!path_strv_canonicalize(rules->dirs)) {
                log_error("failed to canonicalize config directories\n");
                return udev_rules_unref(rules);
        }
        strv_uniq(rules->dirs);

        rules->dirs_ts_usec = calloc(strv_length(rules->dirs), sizeof(long long));
        if(!rules->dirs_ts_usec)
                return udev_rules_unref(rules);
        udev_rules_check_timestamp(rules);

        r = conf_files_list_strv(&files, NULL, ".rules", (const char **)rules->dirs);
        if (r < 0) {
                log_error("failed to enumerate rules files: %s\n", strerror(-r));
                return udev_rules_unref(rules);
        }

        /*
         * The offset value in the rules strct is limited; add all
         * rules file names to the beginning of the string buffer.
         */
        STRV_FOREACH(f, files)
                rules_add_string(rules, *f);

        STRV_FOREACH(f, files)
                parse_file(rules, *f);

        strv_free(files);

        memset(&end_token, 0x00, sizeof(struct token));
        end_token.type = TK_END;
        add_token(rules, &end_token);
        log_debug("rules contain %zu bytes tokens (%u * %zu bytes), %zu bytes strings\n",
                  rules->token_max * sizeof(struct token), rules->token_max, sizeof(struct token), rules->strbuf->len);

        /* cleanup temporary strbuf data */
        log_debug("%zu strings (%zu bytes), %zu de-duplicated (%zu bytes), %zu trie nodes used\n",
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

struct udev_rules *udev_rules_unref(struct udev_rules *rules)
{
        if (rules == NULL)
                return NULL;
        free(rules->tokens);
        strbuf_cleanup(rules->strbuf);
        free(rules->uids);
        free(rules->gids);
        strv_free(rules->dirs);
        free(rules->dirs_ts_usec);
        free(rules);
        return NULL;
}

bool udev_rules_check_timestamp(struct udev_rules *rules)
{
        unsigned int i;
        bool changed = false;

        if (rules == NULL)
                goto out;

        for (i = 0; rules->dirs[i]; i++) {
                struct stat stats;

                if (stat(rules->dirs[i], &stats) < 0)
                        continue;

                if (rules->dirs_ts_usec[i] == timespec_load(&stats.st_mtim))
                        continue;

                /* first check */
                if (rules->dirs_ts_usec[i] != 0) {
                        log_debug("reload - timestamp of '%s' changed\n", rules->dirs[i]);
                        changed = true;
                }

                /* update timestamp */
                rules->dirs_ts_usec[i] = timespec_load(&stats.st_mtim);
        }
out:
        return changed;
}

static int match_key(struct udev_rules *rules, struct token *token, const char *val)
{
        char *key_value = rules_str(rules, token->key.value_off);
        char *pos;
        bool match = false;

        if (val == NULL)
                val = "";

        switch (token->key.glob) {
        case GL_PLAIN:
                match = (streq(key_value, val));
                break;
        case GL_GLOB:
                match = (fnmatch(key_value, val, 0) == 0);
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

                                        match = (matchlen == len && strncmp(s, val, matchlen) == 0);
                                        if (match)
                                                break;
                                } else {
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

                        util_strscpy(value, sizeof(value), rules_str(rules, token->key.value_off));
                        key_value = value;
                        while (key_value != NULL) {
                                pos = strchr(key_value, '|');
                                if (pos != NULL) {
                                        pos[0] = '\0';
                                        pos = &pos[1];
                                }
                                match = (fnmatch(key_value, val, 0) == 0);
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
                return -1;
        }

        if (match && (token->key.op == OP_MATCH))
                return 0;
        if (!match && (token->key.op == OP_NOMATCH))
                return 0;
        return -1;
}

static int match_attr(struct udev_rules *rules, struct udev_device *dev, struct udev_event *event, struct token *cur)
{
        const char *name;
        char nbuf[UTIL_NAME_SIZE];
        const char *value;
        char vbuf[UTIL_NAME_SIZE];
        size_t len;

        name = rules_str(rules, cur->key.attr_off);
        switch (cur->key.attrsubst) {
        case SB_FORMAT:
                udev_event_apply_format(event, name, nbuf, sizeof(nbuf));
                name = nbuf;
                /* fall through */
        case SB_NONE:
                value = udev_device_get_sysattr_value(dev, name);
                if (value == NULL)
                        return -1;
                break;
        case SB_SUBSYS:
                if (util_resolve_subsys_kernel(event->udev, name, vbuf, sizeof(vbuf), 1) != 0)
                        return -1;
                value = vbuf;
                break;
        default:
                return -1;
        }

        /* remove trailing whitespace, if not asked to match for it */
        len = strlen(value);
        if (len > 0 && isspace(value[len-1])) {
                const char *key_value;
                size_t klen;

                key_value = rules_str(rules, cur->key.value_off);
                klen = strlen(key_value);
                if (klen > 0 && !isspace(key_value[klen-1])) {
                        if (value != vbuf) {
                                util_strscpy(vbuf, sizeof(vbuf), value);
                                value = vbuf;
                        }
                        while (len > 0 && isspace(vbuf[--len]))
                                vbuf[len] = '\0';
                }
        }

        return match_key(rules, cur, value);
}

enum escape_type {
        ESCAPE_UNSET,
        ESCAPE_NONE,
        ESCAPE_REPLACE,
};

int udev_rules_apply_to_event(struct udev_rules *rules, struct udev_event *event, const sigset_t *sigmask)
{
        struct token *cur;
        struct token *rule;
        enum escape_type esc = ESCAPE_UNSET;
        bool can_set_name;

        if (rules->tokens == NULL)
                return -1;

        can_set_name = ((!streq(udev_device_get_action(event->dev), "remove")) &&
                        (major(udev_device_get_devnum(event->dev)) > 0 ||
                         udev_device_get_ifindex(event->dev) > 0));

        /* loop through token list, match, run actions or forward to next rule */
        cur = &rules->tokens[0];
        rule = cur;
        for (;;) {
                dump_token(rules, cur);
                switch (cur->type) {
                case TK_RULE:
                        /* current rule */
                        rule = cur;
                        /* possibly skip rules which want to set NAME, SYMLINK, OWNER, GROUP, MODE */
                        if (!can_set_name && rule->rule.can_set_name)
                                goto nomatch;
                        esc = ESCAPE_UNSET;
                        break;
                case TK_M_ACTION:
                        if (match_key(rules, cur, udev_device_get_action(event->dev)) != 0)
                                goto nomatch;
                        break;
                case TK_M_DEVPATH:
                        if (match_key(rules, cur, udev_device_get_devpath(event->dev)) != 0)
                                goto nomatch;
                        break;
                case TK_M_KERNEL:
                        if (match_key(rules, cur, udev_device_get_sysname(event->dev)) != 0)
                                goto nomatch;
                        break;
                case TK_M_DEVLINK: {
                        struct udev_list_entry *list_entry;
                        bool match = false;

                        udev_list_entry_foreach(list_entry, udev_device_get_devlinks_list_entry(event->dev)) {
                                const char *devlink;

                                devlink =  udev_list_entry_get_name(list_entry) + strlen("/dev/");
                                if (match_key(rules, cur, devlink) == 0) {
                                        match = true;
                                        break;
                                }
                        }
                        if (!match)
                                goto nomatch;
                        break;
                }
                case TK_M_NAME:
                        if (match_key(rules, cur, event->name) != 0)
                                goto nomatch;
                        break;
                case TK_M_ENV: {
                        const char *key_name = rules_str(rules, cur->key.attr_off);
                        const char *value;

                        value = udev_device_get_property_value(event->dev, key_name);
                        if (value == NULL)
                                value = "";
                        if (match_key(rules, cur, value))
                                goto nomatch;
                        break;
                }
                case TK_M_TAG: {
                        struct udev_list_entry *list_entry;
                        bool match = false;

                        udev_list_entry_foreach(list_entry, udev_device_get_tags_list_entry(event->dev)) {
                                if (streq(rules_str(rules, cur->key.value_off), udev_list_entry_get_name(list_entry))) {
                                        match = true;
                                        break;
                                }
                        }
                        if (!match && (cur->key.op != OP_NOMATCH))
                                goto nomatch;
                        break;
                }
                case TK_M_SUBSYSTEM:
                        if (match_key(rules, cur, udev_device_get_subsystem(event->dev)) != 0)
                                goto nomatch;
                        break;
                case TK_M_DRIVER:
                        if (match_key(rules, cur, udev_device_get_driver(event->dev)) != 0)
                                goto nomatch;
                        break;
                case TK_M_WAITFOR: {
                        char filename[UTIL_PATH_SIZE];
                        int found;

                        udev_event_apply_format(event, rules_str(rules, cur->key.value_off), filename, sizeof(filename));
                        found = (wait_for_file(event->dev, filename, 10) == 0);
                        if (!found && (cur->key.op != OP_NOMATCH))
                                goto nomatch;
                        break;
                }
                case TK_M_ATTR:
                        if (match_attr(rules, event->dev, event, cur) != 0)
                                goto nomatch;
                        break;
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

                        /* loop over parents */
                        event->dev_parent = event->dev;
                        for (;;) {
                                struct token *key;

                                /* loop over sequence of parent match keys */
                                for (key = cur; key < next; key++ ) {
                                        dump_token(rules, key);
                                        switch(key->type) {
                                        case TK_M_KERNELS:
                                                if (match_key(rules, key, udev_device_get_sysname(event->dev_parent)) != 0)
                                                        goto try_parent;
                                                break;
                                        case TK_M_SUBSYSTEMS:
                                                if (match_key(rules, key, udev_device_get_subsystem(event->dev_parent)) != 0)
                                                        goto try_parent;
                                                break;
                                        case TK_M_DRIVERS:
                                                if (match_key(rules, key, udev_device_get_driver(event->dev_parent)) != 0)
                                                        goto try_parent;
                                                break;
                                        case TK_M_ATTRS:
                                                if (match_attr(rules, event->dev_parent, event, key) != 0)
                                                        goto try_parent;
                                                break;
                                        case TK_M_TAGS: {
                                                bool match = udev_device_has_tag(event->dev_parent, rules_str(rules, cur->key.value_off));

                                                if (match && key->key.op == OP_NOMATCH)
                                                        goto try_parent;
                                                if (!match && key->key.op == OP_MATCH)
                                                        goto try_parent;
                                                break;
                                        }
                                        default:
                                                goto nomatch;
                                        }
                                }
                                break;

                        try_parent:
                                event->dev_parent = udev_device_get_parent(event->dev_parent);
                                if (event->dev_parent == NULL)
                                        goto nomatch;
                        }
                        /* move behind our sequence of parent match keys */
                        cur = next;
                        continue;
                }
                case TK_M_TEST: {
                        char filename[UTIL_PATH_SIZE];
                        struct stat statbuf;
                        int match;

                        udev_event_apply_format(event, rules_str(rules, cur->key.value_off), filename, sizeof(filename));
                        if (util_resolve_subsys_kernel(event->udev, filename, filename, sizeof(filename), 0) != 0) {
                                if (filename[0] != '/') {
                                        char tmp[UTIL_PATH_SIZE];

                                        util_strscpy(tmp, sizeof(tmp), filename);
                                        util_strscpyl(filename, sizeof(filename),
                                                      udev_device_get_syspath(event->dev), "/", tmp, NULL);
                                }
                        }
                        attr_subst_subdir(filename, sizeof(filename));

                        match = (stat(filename, &statbuf) == 0);
                        if (match && cur->key.mode > 0)
                                match = ((statbuf.st_mode & cur->key.mode) > 0);
                        if (match && cur->key.op == OP_NOMATCH)
                                goto nomatch;
                        if (!match && cur->key.op == OP_MATCH)
                                goto nomatch;
                        break;
                }
                case TK_M_EVENT_TIMEOUT:
                        log_debug("OPTIONS event_timeout=%u\n", cur->key.event_timeout);
                        event->timeout_usec = cur->key.event_timeout * 1000 * 1000;
                        break;
                case TK_M_PROGRAM: {
                        char program[UTIL_PATH_SIZE];
                        char **envp;
                        char result[UTIL_PATH_SIZE];

                        free(event->program_result);
                        event->program_result = NULL;
                        udev_event_apply_format(event, rules_str(rules, cur->key.value_off), program, sizeof(program));
                        envp = udev_device_get_properties_envp(event->dev);
                        log_debug("PROGRAM '%s' %s:%u\n",
                                  program,
                                  rules_str(rules, rule->rule.filename_off),
                                  rule->rule.filename_line);

                        if (udev_event_spawn(event, program, envp, sigmask, result, sizeof(result)) < 0) {
                                if (cur->key.op != OP_NOMATCH)
                                        goto nomatch;
                        } else {
                                int count;

                                util_remove_trailing_chars(result, '\n');
                                if (esc == ESCAPE_UNSET || esc == ESCAPE_REPLACE) {
                                        count = util_replace_chars(result, UDEV_ALLOWED_CHARS_INPUT);
                                        if (count > 0)
                                                log_debug("%i character(s) replaced\n" , count);
                                }
                                event->program_result = strdup(result);
                                if (cur->key.op == OP_NOMATCH)
                                        goto nomatch;
                        }
                        break;
                }
                case TK_M_IMPORT_FILE: {
                        char import[UTIL_PATH_SIZE];

                        udev_event_apply_format(event, rules_str(rules, cur->key.value_off), import, sizeof(import));
                        if (import_file_into_properties(event->dev, import) != 0)
                                if (cur->key.op != OP_NOMATCH)
                                        goto nomatch;
                        break;
                }
                case TK_M_IMPORT_PROG: {
                        char import[UTIL_PATH_SIZE];

                        udev_event_apply_format(event, rules_str(rules, cur->key.value_off), import, sizeof(import));
                        log_debug("IMPORT '%s' %s:%u\n",
                                  import,
                                  rules_str(rules, rule->rule.filename_off),
                                  rule->rule.filename_line);

                        if (import_program_into_properties(event, import, sigmask) != 0)
                                if (cur->key.op != OP_NOMATCH)
                                        goto nomatch;
                        break;
                }
                case TK_M_IMPORT_BUILTIN: {
                        char command[UTIL_PATH_SIZE];

                        if (udev_builtin_run_once(cur->key.builtin_cmd)) {
                                /* check if we ran already */
                                if (event->builtin_run & (1 << cur->key.builtin_cmd)) {
                                        log_debug("IMPORT builtin skip '%s' %s:%u\n",
                                                  udev_builtin_name(cur->key.builtin_cmd),
                                                  rules_str(rules, rule->rule.filename_off),
                                                  rule->rule.filename_line);
                                        /* return the result from earlier run */
                                        if (event->builtin_ret & (1 << cur->key.builtin_cmd))
                                        if (cur->key.op != OP_NOMATCH)
                                                        goto nomatch;
                                        break;
                                }
                                /* mark as ran */
                                event->builtin_run |= (1 << cur->key.builtin_cmd);
                        }

                        udev_event_apply_format(event, rules_str(rules, cur->key.value_off), command, sizeof(command));
                        log_debug("IMPORT builtin '%s' %s:%u\n",
                                  udev_builtin_name(cur->key.builtin_cmd),
                                  rules_str(rules, rule->rule.filename_off),
                                  rule->rule.filename_line);

                        if (udev_builtin_run(event->dev, cur->key.builtin_cmd, command, false) != 0) {
                                /* remember failure */
                                log_debug("IMPORT builtin '%s' returned non-zero\n",
                                          udev_builtin_name(cur->key.builtin_cmd));
                                event->builtin_ret |= (1 << cur->key.builtin_cmd);
                                if (cur->key.op != OP_NOMATCH)
                                        goto nomatch;
                        }
                        break;
                }
                case TK_M_IMPORT_DB: {
                        const char *key = rules_str(rules, cur->key.value_off);
                        const char *value;

                        value = udev_device_get_property_value(event->dev_db, key);
                        if (value != NULL) {
                                struct udev_list_entry *entry;

                                entry = udev_device_add_property(event->dev, key, value);
                                udev_list_entry_set_num(entry, true);
                        } else {
                                if (cur->key.op != OP_NOMATCH)
                                        goto nomatch;
                        }
                        break;
                }
                case TK_M_IMPORT_CMDLINE: {
                        FILE *f;
                        bool imported = false;

                        f = fopen("/proc/cmdline", "re");
                        if (f != NULL) {
                                char cmdline[4096];

                                if (fgets(cmdline, sizeof(cmdline), f) != NULL) {
                                        const char *key = rules_str(rules, cur->key.value_off);
                                        char *pos;

                                        pos = strstr(cmdline, key);
                                        if (pos != NULL) {
                                                struct udev_list_entry *entry;

                                                pos += strlen(key);
                                                if (pos[0] == '\0' || isspace(pos[0])) {
                                                        /* we import simple flags as 'FLAG=1' */
                                                        entry = udev_device_add_property(event->dev, key, "1");
                                                        udev_list_entry_set_num(entry, true);
                                                        imported = true;
                                                } else if (pos[0] == '=') {
                                                        const char *value;

                                                        pos++;
                                                        value = pos;
                                                        while (pos[0] != '\0' && !isspace(pos[0]))
                                                                pos++;
                                                        pos[0] = '\0';
                                                        entry = udev_device_add_property(event->dev, key, value);
                                                        udev_list_entry_set_num(entry, true);
                                                        imported = true;
                                                }
                                        }
                                }
                                fclose(f);
                        }
                        if (!imported && cur->key.op != OP_NOMATCH)
                                goto nomatch;
                        break;
                }
                case TK_M_IMPORT_PARENT: {
                        char import[UTIL_PATH_SIZE];

                        udev_event_apply_format(event, rules_str(rules, cur->key.value_off), import, sizeof(import));
                        if (import_parent_into_properties(event->dev, import) != 0)
                                if (cur->key.op != OP_NOMATCH)
                                        goto nomatch;
                        break;
                }
                case TK_M_RESULT:
                        if (match_key(rules, cur, event->program_result) != 0)
                                goto nomatch;
                        break;
                case TK_A_STRING_ESCAPE_NONE:
                        esc = ESCAPE_NONE;
                        break;
                case TK_A_STRING_ESCAPE_REPLACE:
                        esc = ESCAPE_REPLACE;
                        break;
                case TK_A_DB_PERSIST:
                        udev_device_set_db_persist(event->dev);
                        break;
                case TK_A_INOTIFY_WATCH:
                        if (event->inotify_watch_final)
                                break;
                        if (cur->key.op == OP_ASSIGN_FINAL)
                                event->inotify_watch_final = true;
                        event->inotify_watch = cur->key.watch;
                        break;
                case TK_A_DEVLINK_PRIO:
                        udev_device_set_devlink_priority(event->dev, cur->key.devlink_prio);
                        break;
                case TK_A_OWNER: {
                        char owner[UTIL_NAME_SIZE];

                        if (event->owner_final)
                                break;
                        if (cur->key.op == OP_ASSIGN_FINAL)
                                event->owner_final = true;
                        udev_event_apply_format(event, rules_str(rules, cur->key.value_off), owner, sizeof(owner));
                        event->owner_set = true;
                        event->uid = util_lookup_user(event->udev, owner);
                        log_debug("OWNER %u %s:%u\n",
                                  event->uid,
                                  rules_str(rules, rule->rule.filename_off),
                                  rule->rule.filename_line);
                        break;
                }
                case TK_A_GROUP: {
                        char group[UTIL_NAME_SIZE];

                        if (event->group_final)
                                break;
                        if (cur->key.op == OP_ASSIGN_FINAL)
                                event->group_final = true;
                        udev_event_apply_format(event, rules_str(rules, cur->key.value_off), group, sizeof(group));
                        event->group_set = true;
                        event->gid = util_lookup_group(event->udev, group);
                        log_debug("GROUP %u %s:%u\n",
                                  event->gid,
                                  rules_str(rules, rule->rule.filename_off),
                                  rule->rule.filename_line);
                        break;
                }
                case TK_A_MODE: {
                        char mode_str[UTIL_NAME_SIZE];
                        mode_t mode;
                        char *endptr;

                        if (event->mode_final)
                                break;
                        udev_event_apply_format(event, rules_str(rules, cur->key.value_off), mode_str, sizeof(mode_str));
                        mode = strtol(mode_str, &endptr, 8);
                        if (endptr[0] != '\0') {
                                log_error("ignoring invalid mode '%s'\n", mode_str);
                                break;
                        }
                        if (cur->key.op == OP_ASSIGN_FINAL)
                                event->mode_final = true;
                        event->mode_set = true;
                        event->mode = mode;
                        log_debug("MODE %#o %s:%u\n",
                                  event->mode,
                                  rules_str(rules, rule->rule.filename_off),
                                  rule->rule.filename_line);
                        break;
                }
                case TK_A_OWNER_ID:
                        if (event->owner_final)
                                break;
                        if (cur->key.op == OP_ASSIGN_FINAL)
                                event->owner_final = true;
                        event->owner_set = true;
                        event->uid = cur->key.uid;
                        log_debug("OWNER %u %s:%u\n",
                                  event->uid,
                                  rules_str(rules, rule->rule.filename_off),
                                  rule->rule.filename_line);
                        break;
                case TK_A_GROUP_ID:
                        if (event->group_final)
                                break;
                        if (cur->key.op == OP_ASSIGN_FINAL)
                                event->group_final = true;
                        event->group_set = true;
                        event->gid = cur->key.gid;
                        log_debug("GROUP %u %s:%u\n",
                                  event->gid,
                                  rules_str(rules, rule->rule.filename_off),
                                  rule->rule.filename_line);
                        break;
                case TK_A_MODE_ID:
                        if (event->mode_final)
                                break;
                        if (cur->key.op == OP_ASSIGN_FINAL)
                                event->mode_final = true;
                        event->mode_set = true;
                        event->mode = cur->key.mode;
                        log_debug("MODE %#o %s:%u\n",
                                  event->mode,
                                  rules_str(rules, rule->rule.filename_off),
                                  rule->rule.filename_line);
                        break;
                case TK_A_ENV: {
                        const char *name = rules_str(rules, cur->key.attr_off);
                        char *value = rules_str(rules, cur->key.value_off);
                        char value_new[UTIL_NAME_SIZE];
                        const char *value_old = NULL;
                        struct udev_list_entry *entry;

                        if (value[0] == '\0') {
                                if (cur->key.op == OP_ADD)
                                        break;
                                udev_device_add_property(event->dev, name, NULL);
                                break;
                        }

                        if (cur->key.op == OP_ADD)
                                value_old = udev_device_get_property_value(event->dev, name);
                        if (value_old) {
                                char temp[UTIL_NAME_SIZE];

                                /* append value separated by space */
                                udev_event_apply_format(event, value, temp, sizeof(temp));
                                util_strscpyl(value_new, sizeof(value_new), value_old, " ", temp, NULL);
                        } else
                                udev_event_apply_format(event, value, value_new, sizeof(value_new));

                        entry = udev_device_add_property(event->dev, name, value_new);
                        /* store in db, skip private keys */
                        if (name[0] != '.')
                                udev_list_entry_set_num(entry, true);
                        break;
                }
                case TK_A_TAG: {
                        char tag[UTIL_PATH_SIZE];
                        const char *p;

                        udev_event_apply_format(event, rules_str(rules, cur->key.value_off), tag, sizeof(tag));
                        if (cur->key.op == OP_ASSIGN || cur->key.op == OP_ASSIGN_FINAL)
                                udev_device_cleanup_tags_list(event->dev);
                        for (p = tag; *p != '\0'; p++) {
                                if ((*p >= 'a' && *p <= 'z') ||
                                    (*p >= 'A' && *p <= 'Z') ||
                                    (*p >= '0' && *p <= '9') ||
                                    *p == '-' || *p == '_')
                                        continue;
                                log_error("ignoring invalid tag name '%s'\n", tag);
                                break;
                        }
                        udev_device_add_tag(event->dev, tag);
                        break;
                }
                case TK_A_NAME: {
                        const char *name  = rules_str(rules, cur->key.value_off);

                        char name_str[UTIL_PATH_SIZE];
                        int count;

                        if (event->name_final)
                                break;
                        if (cur->key.op == OP_ASSIGN_FINAL)
                                event->name_final = true;
                        udev_event_apply_format(event, name, name_str, sizeof(name_str));
                        if (esc == ESCAPE_UNSET || esc == ESCAPE_REPLACE) {
                                count = util_replace_chars(name_str, "/");
                                if (count > 0)
                                        log_debug("%i character(s) replaced\n", count);
                        }
                        if (major(udev_device_get_devnum(event->dev)) &&
                            (!streq(name_str, udev_device_get_devnode(event->dev) + strlen("/dev/")))) {
                                log_error("NAME=\"%s\" ignored, kernel device nodes "
                                    "can not be renamed; please fix it in %s:%u\n", name,
                                    rules_str(rules, rule->rule.filename_off), rule->rule.filename_line);
                                break;
                        }
                        free(event->name);
                        event->name = strdup(name_str);
                        log_debug("NAME '%s' %s:%u\n",
                                  event->name,
                                  rules_str(rules, rule->rule.filename_off),
                                  rule->rule.filename_line);
                        break;
                }
                case TK_A_DEVLINK: {
                        char temp[UTIL_PATH_SIZE];
                        char filename[UTIL_PATH_SIZE];
                        char *pos, *next;
                        int count = 0;

                        if (event->devlink_final)
                                break;
                        if (major(udev_device_get_devnum(event->dev)) == 0)
                                break;
                        if (cur->key.op == OP_ASSIGN_FINAL)
                                event->devlink_final = true;
                        if (cur->key.op == OP_ASSIGN || cur->key.op == OP_ASSIGN_FINAL)
                                udev_device_cleanup_devlinks_list(event->dev);

                        /* allow  multiple symlinks separated by spaces */
                        udev_event_apply_format(event, rules_str(rules, cur->key.value_off), temp, sizeof(temp));
                        if (esc == ESCAPE_UNSET)
                                count = util_replace_chars(temp, "/ ");
                        else if (esc == ESCAPE_REPLACE)
                                count = util_replace_chars(temp, "/");
                        if (count > 0)
                                log_debug("%i character(s) replaced\n" , count);
                        pos = temp;
                        while (isspace(pos[0]))
                                pos++;
                        next = strchr(pos, ' ');
                        while (next != NULL) {
                                next[0] = '\0';
                                log_debug("LINK '%s' %s:%u\n", pos,
                                          rules_str(rules, rule->rule.filename_off), rule->rule.filename_line);
                                util_strscpyl(filename, sizeof(filename), "/dev/", pos, NULL);
                                udev_device_add_devlink(event->dev, filename);
                                while (isspace(next[1]))
                                        next++;
                                pos = &next[1];
                                next = strchr(pos, ' ');
                        }
                        if (pos[0] != '\0') {
                                log_debug("LINK '%s' %s:%u\n", pos,
                                          rules_str(rules, rule->rule.filename_off), rule->rule.filename_line);
                                util_strscpyl(filename, sizeof(filename), "/dev/", pos, NULL);
                                udev_device_add_devlink(event->dev, filename);
                        }
                        break;
                }
                case TK_A_ATTR: {
                        const char *key_name = rules_str(rules, cur->key.attr_off);
                        char attr[UTIL_PATH_SIZE];
                        char value[UTIL_NAME_SIZE];
                        FILE *f;

                        if (util_resolve_subsys_kernel(event->udev, key_name, attr, sizeof(attr), 0) != 0)
                                util_strscpyl(attr, sizeof(attr), udev_device_get_syspath(event->dev), "/", key_name, NULL);
                        attr_subst_subdir(attr, sizeof(attr));

                        udev_event_apply_format(event, rules_str(rules, cur->key.value_off), value, sizeof(value));
                        log_debug("ATTR '%s' writing '%s' %s:%u\n", attr, value,
                                  rules_str(rules, rule->rule.filename_off),
                                  rule->rule.filename_line);
                        f = fopen(attr, "we");
                        if (f != NULL) {
                                if (fprintf(f, "%s", value) <= 0)
                                        log_error("error writing ATTR{%s}: %m\n", attr);
                                fclose(f);
                        } else {
                                log_error("error opening ATTR{%s} for writing: %m\n", attr);
                        }
                        break;
                }
                case TK_A_RUN_BUILTIN:
                case TK_A_RUN_PROGRAM: {
                        struct udev_list_entry *entry;

                        if (cur->key.op == OP_ASSIGN || cur->key.op == OP_ASSIGN_FINAL)
                                udev_list_cleanup(&event->run_list);
                        log_debug("RUN '%s' %s:%u\n",
                                  rules_str(rules, cur->key.value_off),
                                  rules_str(rules, rule->rule.filename_off),
                                  rule->rule.filename_line);
                        entry = udev_list_entry_add(&event->run_list, rules_str(rules, cur->key.value_off), NULL);
                        udev_list_entry_set_num(entry, cur->key.builtin_cmd);
                        break;
                }
                case TK_A_GOTO:
                        if (cur->key.rule_goto == 0)
                                break;
                        cur = &rules->tokens[cur->key.rule_goto];
                        continue;
                case TK_END:
                        return 0;

                case TK_M_PARENTS_MIN:
                case TK_M_PARENTS_MAX:
                case TK_M_MAX:
                case TK_UNSET:
                        log_error("wrong type %u\n", cur->type);
                        goto nomatch;
                }

                cur++;
                continue;
        nomatch:
                /* fast-forward to next rule */
                cur = rule + rule->rule.token_count;
        }
}

void udev_rules_apply_static_dev_perms(struct udev_rules *rules)
{
        struct token *cur;
        struct token *rule;
        uid_t uid = 0;
        gid_t gid = 0;
        mode_t mode = 0;

        if (rules->tokens == NULL)
                return;

        cur = &rules->tokens[0];
        rule = cur;
        for (;;) {
                switch (cur->type) {
                case TK_RULE:
                        /* current rule */
                        rule = cur;

                        /* skip rules without a static_node tag */
                        if (!rule->rule.has_static_node)
                                goto next;

                        uid = 0;
                        gid = 0;
                        mode = 0;
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
                case TK_A_STATIC_NODE: {
                        char filename[UTIL_PATH_SIZE];
                        struct stat stats;

                        /* we assure, that the permissions tokens are sorted before the static token */
                        if (mode == 0 && uid == 0 && gid == 0)
                                goto next;
                        util_strscpyl(filename, sizeof(filename), "/dev/", rules_str(rules, cur->key.value_off), NULL);
                        if (stat(filename, &stats) != 0)
                                goto next;
                        if (!S_ISBLK(stats.st_mode) && !S_ISCHR(stats.st_mode))
                                goto next;
                        if (mode == 0) {
                                if (gid > 0)
                                        mode = 0660;
                                else
                                        mode = 0600;
                        }
                        if (mode != (stats.st_mode & 01777)) {
                                chmod(filename, mode);
                                log_debug("chmod '%s' %#o\n", filename, mode);
                        }

                        if ((uid != 0 && uid != stats.st_uid) || (gid != 0 && gid != stats.st_gid)) {
                                if (chown(filename, uid, gid) < 0)
                                        log_debug("Following chown failed!");
                                log_debug("chown '%s' %u %u\n", filename, uid, gid);
                        }

                        utimensat(AT_FDCWD, filename, NULL, 0);
                        break;
                }
                case TK_END:
                        return;
                }

                cur++;
                continue;
next:
                /* fast-forward to next rule */
                cur = rule + rule->rule.token_count;
                continue;
        }
}
