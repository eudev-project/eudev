/*
 * Copyright (C) 2003 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2003-2010 Kay Sievers <kay@vrfy.org>
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

#pragma once

#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/param.h>
#include <signal.h>

#include "macro.h"
#include "json-writer.h"
#include "libudev.h"
#include "libudev-private.h"
#include "util.h"
#include "label.h"
#include "log.h"
#include "strv.h"
#include "utf8.h"

/* For the messages about an event: s, e.g. a value substituted into a key of a rule, escaped like the values
 * in the other messages, with utf8_escape_non_printable(), i.e. control characters and invalid UTF-8 as \xNN,
 * if a message at the given level is logged; NULL otherwise, and without memory, where the message shows s as
 * it is: "escaped ?: s". */
static inline char *log_escape(int level, const char *s) {
        return s && log_get_max_level() >= LOG_PRI(level) ? utf8_escape_non_printable(s) : NULL;
}

/* The context an event is processed in: a udevd worker, 'udevadm test', 'udevadm test-builtin'
 * or the rule runner of the test suite (test/test-udev). */
enum udev_event_mode {
        EVENT_UDEV_WORKER,
        EVENT_UDEVADM_TEST,
        EVENT_UDEVADM_TEST_BUILTIN,
        EVENT_TEST_RULE_RUNNER,
};

struct udev_event {
        struct udev *udev;
        struct udev_device *dev;
        struct udev_device *dev_parent;
        struct udev_device *dev_db;
        char *name;
        char *program_result;
        mode_t mode;
        uid_t uid;
        gid_t gid;
        struct udev_list seclabel_list;
        struct udev_list run_list;
        struct udev_list written_sysattr_list;
        struct udev_list written_sysctl_list;
        /* the alternative names requested with OPTIONS+="net_altnames", see event_generate_altnames() */
        char **altnames;
        usec_t exec_delay_usec;
        /* the signal sent to programs on a timeout, see udev.timeout_signal */
        int timeout_signal;
        usec_t birth_usec;
        int fd_signal;
        /* the netlink socket of udev-netlink.h, opened when needed; a udevd worker passes its own socket to
         * each event and takes it back, so that it is reused, like the rtnl of systemd's udev workers */
        int rtnl_fd;
        /* the alternative names the network interface has, read once, see event_get_ifaltnames() */
        char **ifaltnames;
        bool ifaltnames_read;
        unsigned int builtin_run;
        unsigned int builtin_ret;
        bool sigterm;
        bool inotify_watch;
        bool inotify_watch_final;
        bool group_set;
        bool group_final;
        bool owner_set;
        bool owner_final;
        bool mode_set;
        bool mode_final;
        bool name_final;
        bool devlink_final;
        bool run_final;
        /* the database entry was written with ID_PROCESSING=1 before the rules, see udev_event_restore_db() */
        bool dev_db_written;
        /* the tag index was updated with the tags of the device, see udev_event_restore_db() */
        bool tags_indexed;
        /* trace logging, i.e. log the processing of each rule: udevd's trace mode (udev.trace,
         * udevadm control --trace=) and 'udevadm test --verbose' */
        bool trace;
        bool log_level_was_debug;
        int default_log_level;
        bool net_altnames;
        /* do not rename network interfaces and do not assign alternative names to them, like in the test
         * modes, see EVENT_MODE_NETIF_DESTRUCTIVE() */
        bool keep_netifs;
        enum udev_event_mode event_mode;
};

void udev_event_check_config(struct udev *udev);

static inline bool EVENT_MODE_DESTRUCTIVE(struct udev_event *event) {
        assert(event);
        return IN_SET(event->event_mode, EVENT_UDEV_WORKER, EVENT_TEST_RULE_RUNNER);
}

/* Whether network interfaces are renamed and get their alternative names: by udevd, and by test-udev unless it
 * has no network namespace of its own, where it would change the network interfaces of the host. */
static inline bool EVENT_MODE_NETIF_DESTRUCTIVE(struct udev_event *event) {
        return EVENT_MODE_DESTRUCTIVE(event) && !event->keep_netifs;
}

struct udev_watch {
        struct udev_list_node node;
        int handle;
        char *name;
};

/* udev-rules.c */
struct udev_rules;
struct udev_rules *udev_rules_new(struct udev *udev, int resolve_names);
/* Also loads the rules files in extra_dirs, which override the files with the same name in the rules
 * directories, for 'udevadm test --extra-rules-dir='. */
struct udev_rules *udev_rules_new_full(struct udev *udev, int resolve_names, char * const *extra_dirs);
struct udev_rules *udev_rules_unref(struct udev_rules *rules);
bool udev_rules_should_reload(struct udev_rules *rules);
int udev_rules_apply_to_event(struct udev_rules *rules, struct udev_event *event,
                              usec_t timeout_usec,
                              struct udev_list *properties_list);
int udev_rules_apply_static_dev_perms(struct udev_rules *rules);

/* udev-event.c */
struct udev_event *udev_event_new(struct udev_device *dev, enum udev_event_mode mode);
void udev_event_unref(struct udev_event *event);
void event_cache_written_sysattr(struct udev_event *event, const char *attr, const char *value);
void event_cache_written_sysctl(struct udev_event *event, const char *attr, const char *value);
const char *udev_event_get_property_value_with_fallback(struct udev_device *dev, const char *key,
                                                        struct udev_list *global_props);
int safe_atou_optional_plus(const char *s, unsigned *ret);
int udev_check_format(const char *value, size_t *offset, const char **hint);
size_t udev_event_apply_format(struct udev_event *event,
                               const char *src, char *dest, size_t size,
                               bool replace_whitespace, struct udev_list *global_props,
                               bool *ret_truncated);
int udev_event_spawn(struct udev_event *event,
                     usec_t timeout_usec,
                     bool accept_failure,
                     const char *cmd, char **envp,
                     char *result, size_t result_size, bool *ret_truncated);
int udev_event_execute_rules(struct udev_event *event,
                              usec_t timeout_usec,
                              struct udev_list *properties_list,
                              struct udev_rules *rules);
void udev_event_execute_run(struct udev_event *event, usec_t timeout_usec);
void udev_event_restore_db(struct udev_event *event);
#define UDEV_ARGV_MAX 128
int udev_build_argv(struct udev *udev, char *cmd, int *argc, char *argv[]);

/* udev-dump.c */
int dump_event(struct udev_event *event, JsonFormatFlags flags, FILE *f);

/* udev-watch.c */
int udev_watch_init(struct udev *udev);
void udev_watch_restore(struct udev *udev);
void udev_watch_begin(struct udev *udev, struct udev_device *dev);
void udev_watch_end(struct udev *udev, struct udev_device *dev);
struct udev_device *udev_watch_lookup(struct udev *udev, int wd);

/* udev-node.c */
int udev_node_apply_permissions(struct udev_device *dev, bool apply_mac,
                                mode_t mode, uid_t uid, gid_t gid,
                                struct udev_list *seclabel_list);
int static_node_apply_permissions(const char *name, mode_t mode, uid_t uid, gid_t gid, char **tags);
int udev_node_remove(struct udev_device *dev);
int udev_node_update(struct udev_device *dev, struct udev_device *dev_old);

/* udev-ctrl.c */
enum udev_ctrl_msg_type {
        /* like systemd v261: ends the messages of a connection, see udev_ctrl_wait(); 0 was
         * UDEV_CTRL_UNKNOWN, which udevd refused */
        _UDEV_CTRL_END_MESSAGES,
        UDEV_CTRL_SET_LOG_LEVEL,
        UDEV_CTRL_STOP_EXEC_QUEUE,
        UDEV_CTRL_START_EXEC_QUEUE,
        UDEV_CTRL_RELOAD,
        UDEV_CTRL_SET_ENV,
        UDEV_CTRL_SET_CHILDREN_MAX,
        UDEV_CTRL_PING,
        UDEV_CTRL_EXIT,
        UDEV_CTRL_SET_TRACE,
        UDEV_CTRL_REVERT,
        /* eudev: starts a connection with several messages, see udev_ctrl_send() */
        UDEV_CTRL_BEGIN_MESSAGES,
        _UDEV_CTRL_MSG_TYPE_MAX,
};

struct udev_ctrl;
struct udev_ctrl *udev_ctrl_new(struct udev *udev);
struct udev_ctrl *udev_ctrl_new_from_fd(struct udev *udev, int fd);
int udev_ctrl_enable_receiving(struct udev_ctrl *uctrl);
struct udev_ctrl *udev_ctrl_unref(struct udev_ctrl *uctrl);
int udev_ctrl_cleanup(struct udev_ctrl *uctrl);
struct udev *udev_ctrl_get_udev(struct udev_ctrl *uctrl);
int udev_ctrl_get_fd(struct udev_ctrl *uctrl);
int udev_ctrl_send(struct udev_ctrl *uctrl, enum udev_ctrl_msg_type type, int intval, const char *buf);
int udev_ctrl_wait(struct udev_ctrl *uctrl, int timeout);
int udev_ctrl_send_one(struct udev_ctrl *uctrl, enum udev_ctrl_msg_type type, int intval, const char *buf, int timeout,
                       bool *ret_sent);
int udev_ctrl_send_ping_full(struct udev_ctrl *uctrl, int timeout, bool *ret_sent);
int udev_ctrl_send_exit(struct udev_ctrl *uctrl, int timeout);
struct udev_ctrl_connection;
struct udev_ctrl_connection *udev_ctrl_get_connection(struct udev_ctrl *uctrl);
struct udev_ctrl_connection *udev_ctrl_connection_ref(struct udev_ctrl_connection *conn);
struct udev_ctrl_connection *udev_ctrl_connection_unref(struct udev_ctrl_connection *conn);
struct udev_ctrl_msg;
struct udev_ctrl_msg *udev_ctrl_receive_msg(struct udev_ctrl_connection *conn, int timeout_msec);
bool udev_ctrl_msg_is_begin(struct udev_ctrl_msg *ctrl_msg);
bool udev_ctrl_msg_is_end(struct udev_ctrl_msg *ctrl_msg);
struct udev_ctrl_msg *udev_ctrl_msg_unref(struct udev_ctrl_msg *ctrl_msg);
int udev_ctrl_msg_reply(struct udev_ctrl_msg *ctrl_msg);
int udev_ctrl_get_set_log_level(struct udev_ctrl_msg *ctrl_msg, int *ret);
int udev_ctrl_get_stop_exec_queue(struct udev_ctrl_msg *ctrl_msg);
int udev_ctrl_get_start_exec_queue(struct udev_ctrl_msg *ctrl_msg);
int udev_ctrl_get_reload(struct udev_ctrl_msg *ctrl_msg);
int udev_ctrl_get_ping(struct udev_ctrl_msg *ctrl_msg);
int udev_ctrl_get_exit(struct udev_ctrl_msg *ctrl_msg);
const char *udev_ctrl_get_set_env(struct udev_ctrl_msg *ctrl_msg);
int udev_ctrl_get_set_children_max(struct udev_ctrl_msg *ctrl_msg, int *ret);
int udev_ctrl_get_set_trace(struct udev_ctrl_msg *ctrl_msg);
int udev_ctrl_get_revert(struct udev_ctrl_msg *ctrl_msg);

/* Like log_device_*() of systemd: the message is prefixed with the sysname of the device and ": ", e.g.
 * "sda: ", or with nothing if there is no device or it has no sysname. Like there, the error is evaluated
 * before the sysname is looked up, which may change errno. */
#define log_device_full_errno(device, level, error, format, ...)                                        \
        ({                                                                                              \
                int _err = (error);                                                                     \
                struct udev_device *_dev = (device);                                                    \
                const char *_sys = _dev ? udev_device_get_sysname(_dev) : NULL;                         \
                log_full_errno(level, _err, "%s%s" format, _sys ?: "", _sys ? ": " : "", ##__VA_ARGS__); \
        })
#define log_device_full(device, level, ...) log_device_full_errno(device, level, 0, __VA_ARGS__)

#define log_device_debug(device, ...)   log_device_full(device, LOG_DEBUG, __VA_ARGS__)
#define log_device_info(device, ...)    log_device_full(device, LOG_INFO, __VA_ARGS__)
#define log_device_notice(device, ...)  log_device_full(device, LOG_NOTICE, __VA_ARGS__)
#define log_device_warning(device, ...) log_device_full(device, LOG_WARNING, __VA_ARGS__)
#define log_device_error(device, ...)   log_device_full(device, LOG_ERR, __VA_ARGS__)

#define log_device_debug_errno(device, error, ...)   log_device_full_errno(device, LOG_DEBUG, error, __VA_ARGS__)
#define log_device_info_errno(device, error, ...)    log_device_full_errno(device, LOG_INFO, error, __VA_ARGS__)
#define log_device_notice_errno(device, error, ...)  log_device_full_errno(device, LOG_NOTICE, error, __VA_ARGS__)
#define log_device_warning_errno(device, error, ...) log_device_full_errno(device, LOG_WARNING, error, __VA_ARGS__)
#define log_device_error_errno(device, error, ...)   log_device_full_errno(device, LOG_ERR, error, __VA_ARGS__)

/* built-in commands */
enum udev_builtin_cmd {
#ifdef HAVE_BLKID
        UDEV_BUILTIN_BLKID,
#endif
        UDEV_BUILTIN_BTRFS,
        UDEV_BUILTIN_FACTORY_RESET,
        UDEV_BUILTIN_HWDB,
        UDEV_BUILTIN_INPUT_ID,
        UDEV_BUILTIN_KEYBOARD,
#ifdef HAVE_KMOD
        UDEV_BUILTIN_KMOD,
#endif
        UDEV_BUILTIN_NET_DRIVER,
        UDEV_BUILTIN_NET_ID,
        UDEV_BUILTIN_PATH_ID,
#ifdef ENABLE_TPM2
        UDEV_BUILTIN_TPM2_ID,
#endif
        UDEV_BUILTIN_USB_ID,
        UDEV_BUILTIN_MAX
};
struct udev_builtin {
        const char *name;
        int (*cmd)(struct udev_device *dev, int argc, char *argv[], enum udev_event_mode mode);
        const char *help;
        int (*init)(struct udev *udev);
        void (*exit)(struct udev *udev);
        bool (*validate)(struct udev *udev);
        bool run_once;
};
#ifdef HAVE_BLKID
extern const struct udev_builtin udev_builtin_blkid;
#endif
extern const struct udev_builtin udev_builtin_btrfs;
extern const struct udev_builtin udev_builtin_factory_reset;
extern const struct udev_builtin udev_builtin_hwdb;
extern const struct udev_builtin udev_builtin_input_id;
extern const struct udev_builtin udev_builtin_keyboard;
#ifdef HAVE_KMOD
extern const struct udev_builtin udev_builtin_kmod;
#endif
extern const struct udev_builtin udev_builtin_net_driver;
extern const struct udev_builtin udev_builtin_net_id;
extern const struct udev_builtin udev_builtin_path_id;
#ifdef ENABLE_TPM2
extern const struct udev_builtin udev_builtin_tpm2_id;
#endif
extern const struct udev_builtin udev_builtin_usb_id;
void udev_builtin_init(struct udev *udev);
void udev_builtin_exit(struct udev *udev);
enum udev_builtin_cmd udev_builtin_lookup(const char *command);
const char *udev_builtin_name(enum udev_builtin_cmd cmd);
bool udev_builtin_run_once(enum udev_builtin_cmd cmd);
int udev_builtin_run(struct udev_device *dev, enum udev_builtin_cmd cmd, const char *command, enum udev_event_mode mode);
void udev_builtin_list(struct udev *udev);
bool udev_builtin_validate(struct udev *udev);
int udev_builtin_add_property(struct udev_device *dev, enum udev_event_mode mode, const char *key, const char *val);
int udev_builtin_hwdb_lookup(struct udev_device *dev, const char *prefix, const char *modalias,
                             const char *filter, enum udev_event_mode mode);
int udev_builtin_net_id_eudev(struct udev_device *dev, enum udev_event_mode mode);

/* udevadm commands */
struct udevadm_cmd {
        const char *name;
        int (*cmd)(struct udev *udev, int argc, char *argv[]);
        const char *help;
        int debug;
};
extern const struct udevadm_cmd udevadm_info;
extern const struct udevadm_cmd udevadm_trigger;
extern const struct udevadm_cmd udevadm_settle;
extern const struct udevadm_cmd udevadm_control;
extern const struct udevadm_cmd udevadm_monitor;
extern const struct udevadm_cmd udevadm_hwdb;
extern const struct udevadm_cmd udevadm_test;
extern const struct udevadm_cmd udevadm_test_builtin;
extern const struct udevadm_cmd udevadm_verify;
extern const struct udevadm_cmd udevadm_cat;
extern const struct udevadm_cmd udevadm_wait;
extern const struct udevadm_cmd udevadm_lock;
