/*
 * Copyright (C) 2004-2012 Kay Sievers <kay@vrfy.org>
 * Copyright (C) 2004 Chris Friesen <chris_friesen@sympatico.ca>
 * Copyright (C) 2009 Canonical Ltd.
 * Copyright (C) 2009 Scott James Remnant <scott@netsplit.com>
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
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <fcntl.h>
#include <time.h>
#include <getopt.h>
#include <dirent.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/signalfd.h>
#include <sys/epoll.h>
#include <sys/mount.h>
#include <poll.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/inotify.h>
#include <sys/sysmacros.h>

#include "udev.h"
#include "udev-util.h"
#include "blockdev-util.h"
#include "def.h"
#include "dev-setup.h"
#include "fileio.h"
#include "hashmap.h"
#include "id128-util.h"
#include "reread-partition-table.h"
#include "set.h"

#define WORKER_NUM_MAX UINT64_C(2048)

#define DEFAULT_EVENT_TIMEOUT_USEC (180 * USEC_PER_SEC)
#define MIN_EVENT_TIMEOUT_USEC     (1 * USEC_PER_MSEC)

#define EVENT_REQUEUE_INTERVAL_USEC (200 * USEC_PER_MSEC)
#define EVENT_REQUEUE_TIMEOUT_USEC  (3 * USEC_PER_MINUTE)

static struct udev_rules *rules;
static struct udev_ctrl *udev_ctrl;
static struct udev_ctrl_connection *udev_ctrl_conn;
static struct udev_monitor *monitor;
static int worker_watch[2] = { -1, -1 };
static int fd_signal = -1;
static int fd_ep = -1;
static int fd_inotify = -1;
static int fd_ready = -1;
static bool stop_exec_queue;
/* START_EXEC_QUEUE was received: start the queued events without waiting for the next timeout */
static bool start_exec_queue;
static bool reload;
static int arg_daemonize = false;
/* the merged setting of resolve_names, see udev_parse_resolve_names() */
static int arg_resolve_names = 1;
/* udev.trace on the kernel command line */
static bool arg_trace = false;

/* Like UdevConfig of systemd: the settings of udev.conf, the command line and the kernel command line, which
 * are merged by manager_merge_config(). A negative log level and 0 for the other settings mean that the
 * setting is not given. */
struct udev_config {
        int log_level;
        unsigned children_max;
        usec_t exec_delay_usec;
        usec_t timeout_usec;
        int timeout_signal;
        bool blockdev_read_only;
        /* see udev_parse_resolve_names(), RESOLVE_NAMES_UNSET if not given */
        int resolve_names;
};

#define RESOLVE_NAMES_UNSET INT_MIN
#define UDEV_CONFIG_INIT { .log_level = -1, .resolve_names = RESOLVE_NAMES_UNSET, }

/* udev_new() reads udev.conf and applies its log level, the other settings are taken from there */
static struct udev_config config_by_udev_conf = UDEV_CONFIG_INIT;
static struct udev_config config_by_command = UDEV_CONFIG_INIT;
static struct udev_config config_by_kernel = UDEV_CONFIG_INIT;

/* the log level of the kernel command line, --debug or udev.conf, in this order */
static int default_log_level;
/* the log level set with udevadm control, or -1 */
static int control_log_level = -1;
/* trace logging set with udevadm control */
static bool control_trace = false;
/* trace logging is enabled, then the log level is debug */
static bool trace = false;
/* the merged settings, see manager_merge_config() */
static unsigned arg_children_max;
/* the maximum number of workers before udevadm control changes it */
static unsigned default_children_max;
static usec_t arg_exec_delay_usec;
static usec_t arg_event_timeout_usec = DEFAULT_EVENT_TIMEOUT_USEC;
static usec_t arg_event_timeout_warn_usec = DEFAULT_EVENT_TIMEOUT_USEC / 3;
static int arg_timeout_signal = SIGKILL;
static bool arg_blockdev_read_only = false;
static sigset_t sigmask_orig;
static UDEV_LIST(event_list);
Hashmap *workers;
/* the processes that re-read the partition table of a disk, see synthesize_change() */
static Set *synthesize_change_children;
/* the UUIDs of the synthetic change events that udevd triggered and did not receive yet, and when to stop
 * waiting for them, see synthesize_change_one() */
static Set *synthesized_events;
static usec_t synthesized_events_clear_usec;
static struct udev_list properties_list;
static bool udev_exit;
static char udevd_ready_string[] = "udevd ready\n";

enum event_state {
        EVENT_UNDEF,
        EVENT_QUEUED,
        EVENT_RUNNING,
        EVENT_LOCKED,
};

struct event {
        struct udev_list_node node;
        struct udev *udev;
        struct udev_device *dev;
        struct worker *worker;
        enum event_state state;
        unsigned long long int delaying_seqnum;
        unsigned long long int seqnum;
        const char *devpath;
        const char *devpath_old;
        const char *devnode;
        dev_t devnum;
        int ifindex;
        bool is_block;
        usec_t start_usec;
        bool warned;

        /* Used when the device is locked by another program. */
        usec_t requeue_next_usec;
        usec_t requeue_timeout_usec;
        char *whole_disk;
};

/* the number of events in state EVENT_LOCKED */
static unsigned n_locked_events;

static inline struct event *node_to_event(struct udev_list_node *node) {
        return container_of(node, struct event, node);
}

static void event_queue_cleanup(struct udev *udev, enum event_state type);

enum worker_state {
        WORKER_UNDEF,
        WORKER_RUNNING,
        WORKER_IDLE,
        WORKER_KILLED,
        WORKER_KILLING,
};

struct worker {
        struct udev_list_node node;
        struct udev *udev;
        int refcount;
        pid_t pid;
        struct udev_monitor *monitor;
        enum worker_state state;
        struct event *event;
};

/* passed from worker to main process */
enum event_result {
        EVENT_RESULT_SUCCESS,
        EVENT_RESULT_FAILED,
        EVENT_RESULT_TRY_AGAIN, /* when the block device is locked by another process. */
};

struct worker_message {
        enum event_result result;
        /* with EVENT_RESULT_TRY_AGAIN, the device node of the locked whole disk */
        char whole_disk[UTIL_PATH_SIZE];
};

static void event_unset_whole_disk(struct event *event) {
        if (event->state == EVENT_LOCKED) {
                assert(n_locked_events > 0);
                n_locked_events--;
        }

        free(event->whole_disk);
        event->whole_disk = NULL;
}

static void event_free(struct event *event) {
        if (!event)
                return;

        event_unset_whole_disk(event);
        udev_list_node_remove(&event->node);
        udev_device_unref(event->dev);

        if (event->worker)
                event->worker->event = NULL;

        free(event);
}

static void worker_free(struct worker *worker) {
        if (!worker)
                return;

        hashmap_remove(workers, UINT_TO_PTR(worker->pid));
        udev_monitor_unref(worker->monitor);
        udev_unref(worker->udev);
        event_free(worker->event);

        free(worker);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(struct worker *, worker_free);

static void workers_free(void) {
        struct worker *worker;
        Iterator i;

        HASHMAP_FOREACH(worker, workers, i)
                worker_free(worker);

        hashmap_free(workers);
        workers = NULL;
}

static int worker_new(struct worker **ret, struct udev *udev, struct udev_monitor *worker_monitor, pid_t pid) {
        _cleanup_(worker_freep) struct worker *worker = NULL;
        int r;

        assert(ret);
        assert(udev);
        assert(worker_monitor);
        assert(pid > 1);

        worker = new0(struct worker, 1);
        if (!worker)
                return -ENOMEM;

        worker->refcount = 1;
        worker->udev = udev_ref(udev);
        /* close monitor, but keep address around */
        udev_monitor_disconnect(worker_monitor);
        worker->monitor = udev_monitor_ref(worker_monitor);
        worker->pid = pid;

        r = hashmap_ensure_allocated(&workers, NULL);
        if (r < 0)
                return r;

        r = hashmap_put(workers, UINT_TO_PTR(pid), worker);
        if (r < 0)
                return r;

        *ret = worker;
        worker = NULL;

        return 0;
}

static void worker_attach_event(struct worker *worker, struct event *event) {
        assert(worker);
        assert(event);
        assert(!event->worker);
        assert(!worker->event);

        worker->state = WORKER_RUNNING;
        worker->event = event;
        event->state = EVENT_RUNNING;
        event->start_usec = now(CLOCK_MONOTONIC);
        event->warned = false;
        event->worker = worker;
}

static int worker_send_message(int fd, enum event_result result, const char *whole_disk) {
        struct worker_message message = {
                .result = result,
        };

        if (whole_disk)
                strscpy(message.whole_disk, sizeof(message.whole_disk), whole_disk);

        return loop_write(fd, &message, sizeof(message), false);
}

/* Like udev_get_whole_disk() of systemd: returns 1 and the whole disk device and its device node, if the
 * events of the device are processed with a lock on the whole disk, otherwise 0. */
static int udev_get_whole_disk(struct udev_device *dev, struct udev_device **ret_device, const char **ret_devname) {
        struct udev_device *whole_disk;
        const char *val;
        int r;

        assert(dev);

        if (streq_ptr(udev_device_get_action(dev), "remove"))
                goto irrelevant;

        /* Exclude the following devices:
         * For "dm-", see the comment added by e918a1b5a94f270186dca59156354acd2a596494.
         * For "md", see the commit message of 2e5b17d01347d3c3118be2b8ad63d20415dbb1f0,
         * but not sure the assumption is still valid even when partitions are created on the md
         * devices, surprisingly which seems to be possible, see PR #22973.
         * For "drbd", see the commit message of fee854ee8ccde0cd28e0f925dea18cce35f3993d. */
        val = udev_device_get_sysname(dev);
        if (!val)
                return log_debug_errno(ENOENT, "%s: Failed to check sysname: %m", udev_device_get_devpath(dev));
        if (startswith(val, "dm-") || startswith(val, "md") || startswith(val, "drbd"))
                goto irrelevant;

        r = block_device_get_whole_disk(dev, &whole_disk);
        if (IN_SET(r,
                   -ENOTBLK, /* The device is not a block device. */
                   -ENODEV   /* The whole disk device was not found, it may already be removed. */))
                goto irrelevant;
        if (r < 0)
                return log_debug_errno(r, "%s: Failed to get whole disk device: %m", udev_device_get_devpath(dev));

        val = udev_device_get_devnode(whole_disk);
        if (!val)
                return log_debug_errno(ENOENT, "%s: Failed to get devname: %m", udev_device_get_devpath(dev));

        if (ret_device)
                *ret_device = whole_disk;
        if (ret_devname)
                *ret_devname = val;
        return 1;

irrelevant:
        if (ret_device)
                *ret_device = NULL;
        if (ret_devname)
                *ret_devname = NULL;
        return 0;
}

/* Like sd_device_open() of systemd: opens the device node of the block device, and checks that it is the
 * block device node with the device number of the device. */
static int device_open_block(struct udev_device *dev, int flags) {
        _cleanup_close_ int fd = -1;
        struct stat st;

        fd = open(udev_device_get_devnode(dev), flags);
        if (fd < 0)
                return -errno;

        if (fstat(fd, &st) < 0)
                return -errno;

        if (!S_ISBLK(st.st_mode) || st.st_rdev != udev_device_get_devnum(dev))
                return -ENXIO;

        return TAKE_FD(fd);
}

/* Takes a shared lock on the whole disk of a block device. Returns 1 and the file descriptor of the whole
 * disk that holds the lock, 0 and -1 if the event is processed without a lock, and -EAGAIN and the device
 * node of the whole disk, if another process holds a lock on it. */
static int worker_lock_whole_disk(struct udev_device *dev, int *ret_fd, const char **ret_whole_disk) {
        _cleanup_close_ int fd = -1;
        struct udev_device *dev_whole_disk;
        const char *whole_disk;
        int r;

        assert(dev);
        assert(ret_fd);
        assert(ret_whole_disk);

        /* Take a shared lock on the device node; this establishes a concept of device "ownership" to
         * serialize device access. External processes holding an exclusive lock will cause udev to skip the
         * event handling; in the case udev acquired the lock, the external process can block until udev has
         * finished its event handling. */

        /* Do not try to lock device on remove event, as the device node specified by DEVNAME= has already
         * been removed, and may already be assigned to another device. Consider the case e.g. a USB stick
         * memory was unplugged and then another one is plugged. */
        if (streq_ptr(udev_device_get_action(dev), "remove"))
                goto nolock;

        r = udev_get_whole_disk(dev, &dev_whole_disk, &whole_disk);
        if (r < 0)
                return r;
        if (r == 0)
                goto nolock;

        fd = device_open_block(dev_whole_disk, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY|O_NOFOLLOW);
        if (fd < 0) {
                bool ignore = ERRNO_IS_DEVICE_ABSENT_OR_EMPTY(fd);

                log_debug_errno(fd, "%s: Failed to open '%s'%s: %m", udev_device_get_devpath(dev), whole_disk,
                                ignore ? ", ignoring" : "");
                if (!ignore)
                        return fd;

                goto nolock;
        }

        if (flock(fd, LOCK_SH|LOCK_NB) < 0) {
                if (errno != EAGAIN)
                        return log_debug_errno(errno, "%s: Failed to flock(%s): %m", udev_device_get_devpath(dev), whole_disk);

                log_debug_errno(errno, "%s: Block device %s is currently locked, requeuing the event.",
                                udev_device_get_devpath(dev), whole_disk);

                *ret_fd = -1;
                *ret_whole_disk = whole_disk;
                return -EAGAIN;
        }

        log_debug("%s: Successfully took flock(LOCK_SH) for %s, it will be released after the event has been processed.",
                  udev_device_get_devpath(dev), whole_disk);
        *ret_fd = TAKE_FD(fd);
        *ret_whole_disk = NULL;
        return 1;

nolock:
        *ret_fd = -1;
        *ret_whole_disk = NULL;
        return 0;
}

static int worker_mark_block_device_read_only(struct udev_device *dev) {
        _cleanup_close_ int fd = -1;
        const char *node, *val;
        int state = 1;

        assert(dev);

        /* Do this only once, when the block device is new. If the device is later retriggered let's not
         * toggle the bit again, so that people can boot up with full read-only mode and then unset the bit
         * for specific devices only. */
        if (!streq_ptr(udev_device_get_action(dev), "add"))
                return 0;

        if (!streq_ptr(udev_device_get_subsystem(dev), "block"))
                return 0;

        /* Exclude synthetic devices for now, this is supposed to be a safety feature to avoid modification
         * of physical devices, and what sits on top of those doesn't really matter if we don't allow the
         * underlying block devices to receive changes. */
        val = udev_device_get_sysname(dev);
        if (!val)
                return log_debug_errno(ENOENT, "%s: Failed to check sysname: %m", udev_device_get_devpath(dev));
        if (startswith(val, "dm-") || startswith(val, "md") || startswith(val, "drbd") ||
            startswith(val, "loop") || startswith(val, "nbd") || startswith(val, "zram"))
                return 0;

        node = udev_device_get_devnode(dev);
        if (!node)
                return log_debug_errno(ENOENT, "%s: Failed to get device node: %m", udev_device_get_devpath(dev));

        fd = device_open_block(dev, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (fd < 0) {
                bool ignore = ERRNO_IS_DEVICE_ABSENT_OR_EMPTY(fd);

                log_full_errno(ignore ? LOG_DEBUG : LOG_WARNING, fd,
                               "%s: Failed to open device node '%s'%s: %m",
                               udev_device_get_devpath(dev), node, ignore ? ", ignoring" : "");
                return ignore ? 0 : fd;
        }

        if (ioctl(fd, BLKROSET, &state) < 0)
                return log_warning_errno(errno, "%s: Failed to mark block device '%s' read-only: %m",
                                         udev_device_get_devpath(dev), node);

        log_info("%s: Successfully marked block device '%s' read-only.", udev_device_get_devpath(dev), node);
        return 0;
}

static void worker_spawn(struct event *event) {
        struct udev *udev = event->udev;
        _cleanup_udev_monitor_unref_ struct udev_monitor *worker_monitor = NULL;
        pid_t pid;
        int k;

        /* listen for new events */
        worker_monitor = udev_monitor_new_from_netlink(udev, NULL);
        if (worker_monitor == NULL)
                return;
        /* allow the main daemon netlink address to send devices to the worker */
        udev_monitor_allow_unicast_sender(worker_monitor, monitor);
        /* Like systemd, do not start a worker that cannot receive the devices that udevd sends it, e.g. as
         * SO_PASSCRED could not be set, without which it ignores them; the event stays queued. */
        k = udev_monitor_enable_receiving(worker_monitor);
        if (k < 0) {
                log_error_errno(k, "Worker: Failed to enable receiving of devices: %m");
                return;
        }

        pid = fork();
        switch (pid) {
        case 0: {
                struct udev_device *dev = NULL;
                int fd_monitor;
                /* the netlink socket to rename network interfaces and assign alternative names, see udev_event */
                int rtnl_fd = -1;
                struct epoll_event ep_signal, ep_monitor;
                sigset_t mask;
                int r = 0;

                /* take initial device from queue */
                dev = event->dev;
                event->dev = NULL;

                workers_free();
                set_free(synthesize_change_children);
                synthesize_change_children = NULL;
                set_free_free(synthesized_events);
                synthesized_events = NULL;
                event_queue_cleanup(udev, EVENT_UNDEF);
                udev_monitor_unref(monitor);
                udev_ctrl_unref(udev_ctrl);
                close(fd_signal);
                close(fd_ep);
                close(worker_watch[READ_END]);

                sigfillset(&mask);
                fd_signal = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC);
                if (fd_signal < 0) {
                        r = log_error_errno(errno, "error creating signalfd %m");
                        goto out;
                }

                fd_ep = epoll_create1(EPOLL_CLOEXEC);
                if (fd_ep < 0) {
                        r = log_error_errno(errno, "error creating epoll fd: %m");
                        goto out;
                }

                memzero(&ep_signal, sizeof(struct epoll_event));
                ep_signal.events = EPOLLIN;
                ep_signal.data.fd = fd_signal;

                fd_monitor = udev_monitor_get_fd(worker_monitor);
                memzero(&ep_monitor, sizeof(struct epoll_event));
                ep_monitor.events = EPOLLIN;
                ep_monitor.data.fd = fd_monitor;

                if (epoll_ctl(fd_ep, EPOLL_CTL_ADD, fd_signal, &ep_signal) < 0 ||
                    epoll_ctl(fd_ep, EPOLL_CTL_ADD, fd_monitor, &ep_monitor) < 0) {
                        r = log_error_errno(errno, "fail to add fds to epoll: %m");
                        goto out;
                }

                /* request TERM signal if parent exits */
                prctl(PR_SET_PDEATHSIG, SIGTERM);

                /* The worker blocks all signals, and reads SIGTERM and SIGCHLD from the signalfd. Like the
                 * workers of systemd, let another signal that udevd sends on a timeout take its default
                 * action, e.g. dump core with SIGABRT. SIGCHLD cannot be the timeout signal, as it does not
                 * terminate a process, see signal_terminates(). */
                if (arg_timeout_signal != SIGTERM) {
                        sigset_t timeout_mask;

                        (void) signal(arg_timeout_signal, SIG_DFL);
                        sigemptyset(&timeout_mask);
                        sigaddset(&timeout_mask, arg_timeout_signal);
                        (void) sigprocmask(SIG_UNBLOCK, &timeout_mask, NULL);
                }

                /* reset OOM score, we only protect the main daemon */
                write_string_file("/proc/self/oom_score_adj", "0");

                for (;;) {
                        struct udev_event *udev_event;
                        enum event_result result = EVENT_RESULT_SUCCESS;
                        const char *whole_disk = NULL;
                        int fd_lock = -1;

                        log_debug("seq %llu running", udev_device_get_seqnum(dev));
                        udev_event = udev_event_new(dev, EVENT_UDEV_WORKER);
                        if (udev_event == NULL) {
                                r = -ENOMEM;
                                goto out;
                        }

                        udev_event->trace = trace;

                        /* needed for SIGCHLD/SIGTERM in spawn() */
                        udev_event->fd_signal = fd_signal;

                        /* reuse the netlink socket for all events */
                        udev_event->rtnl_fd = rtnl_fd;

                        udev_event->exec_delay_usec = arg_exec_delay_usec;
                        udev_event->timeout_signal = arg_timeout_signal;

                        /*
                         * If this is a block device and the device is locked currently via the BSD advisory locks,
                         * someone else is using it exclusively. We don't run our udev rules now to not interfere.
                         * Instead of processing the event, we requeue the event and will try again after a delay.
                         *
                         * The user-facing side of this: https://systemd.io/BLOCK_DEVICE_LOCKING
                         */
                        r = worker_lock_whole_disk(dev, &fd_lock, &whole_disk);
                        if (r == -EAGAIN) {
                                result = EVENT_RESULT_TRY_AGAIN;
                                goto skip;
                        }
                        if (r < 0) {
                                log_warning_errno(r, "seq %llu: Failed to process device, ignoring: %m",
                                                  udev_device_get_seqnum(dev));
                                result = EVENT_RESULT_FAILED;

                                /* broadcast the (unprocessed) event to libudev listeners */
                                udev_monitor_send_device(worker_monitor, NULL, dev);
                                goto skip;
                        }

                        if (arg_blockdev_read_only)
                                (void) worker_mark_block_device_read_only(dev);

                        /* apply rules, create node, symlinks */
                        r = udev_event_execute_rules(udev_event,
                                                     arg_event_timeout_usec,
                                                     &properties_list,
                                                     rules,
                                                     &sigmask_orig);
                        if (r < 0)
                                /* Like systemd a446e8ff2c, when the rules fail, e.g. on an error of
                                 * IMPORT{}, or the database cannot be written, RUN is not run and the
                                 * inotify watch is not restored, but the (partially processed) event is
                                 * still sent to the listeners. */
                                log_warning_errno(r, "%s: Failed to process device, ignoring: %m",
                                                  udev_device_get_sysname(dev));
                        else {
                                udev_event_execute_run(udev_event,
                                                       arg_event_timeout_usec,
                                                       &sigmask_orig);

                                /* apply/restore inotify watch; some udev rule may erroneously set
                                 * inotify watch on remove event, silently ignore it for safety */
                                if (!streq_ptr(udev_device_get_action(dev), "remove") &&
                                    udev_device_get_devnode(dev) != NULL) {
                                        if (udev_event->inotify_watch)
                                                udev_watch_begin(udev, dev);
                                        else
                                                udev_watch_end(udev, dev);
                                }

                                /* Finalize database. But do not re-create database on remove, which has been already
                                 * removed in udev_event_execute_rules(). Unlike systemd, which also logs "Failed to
                                 * process device" then, log only the specific error when this fails: RUN has run
                                 * already, and the event is sent to the listeners. */
                                if (!streq_ptr(udev_device_get_action(dev), "remove")) {
                                        r = udev_device_add_property(dev, "ID_PROCESSING", NULL);
                                        if (r < 0)
                                                log_warning_errno(r, "%s: Failed to remove 'ID_PROCESSING' property: %m",
                                                                  udev_device_get_sysname(dev));
                                        else {
                                                r = udev_device_update_db(dev);
                                                if (r < 0)
                                                        log_warning_errno(r, "%s: Failed to update database under " UDEV_ROOT_RUN "/udev/data/: %m",
                                                                          udev_device_get_sysname(dev));
                                        }
                                }
                        }

                        safe_close(fd_lock);

                        /* send processed event back to libudev listeners */
                        udev_monitor_send_device(worker_monitor, NULL, dev);

skip:
                        /* take the netlink socket back, in case the event opened it */
                        rtnl_fd = udev_event->rtnl_fd;
                        udev_event->rtnl_fd = -1;

                        log_debug("seq %llu processed", udev_device_get_seqnum(dev));

                        /* Reset the log level, as it might be changed by "OPTIONS=log_level=". */
                        log_set_max_level(udev_event->default_log_level);

                        /* send udevd the result of the event execution */
                        r = worker_send_message(worker_watch[WRITE_END], result, whole_disk);
                        if (r < 0)
                                log_error_errno(r, "failed to send result of seq %llu to main daemon: %m",
                                                udev_device_get_seqnum(dev));

                        udev_device_unref(dev);
                        dev = NULL;

                        if (udev_event->sigterm) {
                                udev_event_unref(udev_event);
                                goto out;
                        }

                        udev_event_unref(udev_event);

                        /* wait for more device messages from main udevd, or term signal */
                        while (dev == NULL) {
                                struct epoll_event ev[4];
                                int fdcount;
                                int i;

                                fdcount = epoll_wait(fd_ep, ev, ELEMENTSOF(ev), -1);
                                if (fdcount < 0) {
                                        if (errno == EINTR)
                                                continue;
                                        r = log_error_errno(errno, "failed to poll: %m");
                                        goto out;
                                }

                                for (i = 0; i < fdcount; i++) {
                                        if (ev[i].data.fd == fd_monitor && ev[i].events & EPOLLIN) {
                                                dev = udev_monitor_receive_device(worker_monitor);
                                                break;
                                        } else if (ev[i].data.fd == fd_signal && ev[i].events & EPOLLIN) {
                                                struct signalfd_siginfo fdsi;
                                                ssize_t size;

                                                size = read(fd_signal, &fdsi, sizeof(struct signalfd_siginfo));
                                                if (size != sizeof(struct signalfd_siginfo))
                                                        continue;
                                                switch (fdsi.ssi_signo) {
                                                case SIGTERM:
                                                        goto out;
                                                }
                                        }
                                }
                        }
                }
out:
                udev_device_unref(dev);
                safe_close(rtnl_fd);
                safe_close(fd_signal);
                safe_close(fd_ep);
                close(fd_inotify);
                close(worker_watch[WRITE_END]);
                udev_rules_unref(rules);
                udev_builtin_exit(udev);
                udev_unref(udev);
                log_close();
                _exit(r < 0 ? EXIT_FAILURE : EXIT_SUCCESS);
        }
        case -1:
                event->state = EVENT_QUEUED;
                log_error_errno(errno, "fork of child failed: %m");
                break;
        default:
        {
                struct worker *worker;
                int r;

                r = worker_new(&worker, udev, worker_monitor, pid);
                if (r < 0)
                        return;

                worker_attach_event(worker, event);

                log_debug("seq %llu forked new worker ["PID_FMT"]", udev_device_get_seqnum(event->dev), pid);
                break;
        }
        }
}

static void event_run(struct event *event) {
        struct worker *worker;
        Iterator i;

        HASHMAP_FOREACH(worker, workers, i) {
                ssize_t count;

                if (worker->state != WORKER_IDLE)
                        continue;

                count = udev_monitor_send_device(monitor, worker->monitor, event->dev);
                if (count < 0) {
                        log_error_errno(errno, "worker ["PID_FMT"] did not accept message %zi (%m), kill it",
                                        worker->pid, count);
                        kill(worker->pid, SIGKILL);
                        worker->state = WORKER_KILLED;
                        continue;
                }
                worker_attach_event(worker, event);
                return;
        }

        if (hashmap_size(workers) >= arg_children_max) {
                if (arg_children_max > 1)
                        log_debug("maximum number (%i) of children reached", hashmap_size(workers));
                return;
        }

        /* start new worker and pass initial device */
        worker_spawn(event);
}

static int event_queue_insert(struct udev_device *dev) {
        struct event *event;

        event = new0(struct event, 1);
        if (event == NULL)
                return -1;

        event->udev = udev_device_get_udev(dev);
        event->dev = dev;
        event->seqnum = udev_device_get_seqnum(dev);
        event->devpath = udev_device_get_devpath(dev);
        event->devpath_old = udev_device_get_devpath_old(dev);
        event->devnode = udev_device_get_devnode(dev);
        event->devnum = udev_device_get_devnum(dev);
        event->is_block = streq("block", udev_device_get_subsystem(dev));
        event->ifindex = udev_device_get_ifindex(dev);

        log_debug("seq %llu queued, '%s' '%s'", udev_device_get_seqnum(dev),
             udev_device_get_action(dev), udev_device_get_subsystem(dev));

        event->state = EVENT_QUEUED;
        udev_list_node_append(&event->node, &event_list);
        return 0;
}

static void worker_kill(bool force) {
        struct worker *worker;
        Iterator i;

        HASHMAP_FOREACH(worker, workers, i) {
                if (worker->state == WORKER_KILLED)
                        continue;

                /* do not interrupt a running worker, kill it when it has finished its event */
                if (worker->state == WORKER_RUNNING && !force) {
                        worker->state = WORKER_KILLING;
                        continue;
                }

                worker->state = WORKER_KILLED;
                kill(worker->pid, SIGTERM);
        }
}

static bool devpath_conflict(const char *a, const char *b) {
        /* This returns true when two paths are equivalent, or one is a child of another. */

        if (!a || !b)
                return false;

        for (; *a != '\0' && *b != '\0'; a++, b++)
                if (*a != *b)
                        return false;

        return *a == '/' || *b == '/' || *a == *b;
}

/* lookup event for identical, parent, child device */
static bool is_devpath_busy(struct event *event) {
        struct udev_list_node *loop;

        /* check if queue contains events we depend on */
        udev_list_node_foreach(loop, &event_list) {
                struct event *loop_event = node_to_event(loop);

                /* we already found a later event, earlier can not block us, no need to check again */
                if (loop_event->seqnum < event->delaying_seqnum)
                        continue;

                /* event we checked earlier still exists, no need to check again */
                if (loop_event->seqnum == event->delaying_seqnum)
                        return true;

                /* found ourself, no later event can block us */
                if (loop_event->seqnum >= event->seqnum)
                        break;

                /* check major/minor */
                if (major(event->devnum) != 0 && event->devnum == loop_event->devnum && event->is_block == loop_event->is_block)
                        goto set_delaying_seqnum;

                /* check network device ifindex */
                if (event->ifindex != 0 && event->ifindex == loop_event->ifindex)
                        goto set_delaying_seqnum;

                /* check for identical, parent, or child device, also with the old names */
                if (devpath_conflict(event->devpath, loop_event->devpath) ||
                    devpath_conflict(event->devpath, loop_event->devpath_old) ||
                    devpath_conflict(event->devpath_old, loop_event->devpath))
                        goto set_delaying_seqnum;

                /* check device node, the devnum and the devpath may be different for the same node */
                if (event->devnode != NULL && streq_ptr(event->devnode, loop_event->devnode))
                        goto set_delaying_seqnum;

                /* no matching device */
                continue;

        set_delaying_seqnum:
                event->delaying_seqnum = loop_event->seqnum;
                return true;
        }

        return false;
}

static void event_queue_start(struct udev *udev __attribute__((unused))) {
        struct udev_list_node *loop;

        udev_list_node_foreach(loop, &event_list) {
                struct event *event = node_to_event(loop);

                if (event->state != EVENT_QUEUED)
                        continue;

                /* do not start event if parent or child event is still running */
                if (is_devpath_busy(event))
                        continue;

                event_run(event);
        }
}

static void event_queue_cleanup(struct udev *udev __attribute__((unused)), enum event_state match_type) {
        struct udev_list_node *loop, *tmp;

        udev_list_node_foreach_safe(loop, tmp, &event_list) {
                struct event *event = node_to_event(loop);

                if (match_type != EVENT_UNDEF && match_type != event->state)
                        continue;

                event_free(event);
        }
}

/* Like device_broadcast_on_error() of systemd: when the event failed, delete the state of the device from
 * disk and forward the kernel event without amending it. */
static void event_broadcast_on_error(struct event *event) {
        /* delete state from disk */
        udev_device_delete_db(event->dev);
        udev_device_tag_index(event->dev, false);
        /* forward kernel event without amending it, the manager does not change the device of the event;
         * on exit, the monitor is already closed */
        if (monitor)
                udev_monitor_send_device(monitor, NULL, event->dev);
}

/* Returns the time in milliseconds until the next locked event is to be requeued, 0 if one is due now, or -1
 * if there are no locked events. */
static int locked_events_timeout(void) {
        struct udev_list_node *loop;
        usec_t now_usec, next_usec = USEC_INFINITY;

        if (n_locked_events == 0)
                return -1;

        udev_list_node_foreach(loop, &event_list) {
                struct event *event = node_to_event(loop);

                if (event->state == EVENT_LOCKED && event->requeue_next_usec < next_usec)
                        next_usec = event->requeue_next_usec;
        }

        if (next_usec == USEC_INFINITY)
                return -1;

        now_usec = now(CLOCK_MONOTONIC);
        if (next_usec <= now_usec)
                return 0;

        /* round up, the events are due when the timeout expires */
        next_usec = (next_usec - now_usec + USEC_PER_MSEC - 1) / USEC_PER_MSEC;
        return next_usec > INT_MAX ? INT_MAX : (int) next_usec;
}

static void manager_requeue_locked_events(void) {
        struct udev_list_node *loop;
        usec_t now_usec;

        if (n_locked_events == 0)
                return;

        now_usec = now(CLOCK_MONOTONIC);

        udev_list_node_foreach(loop, &event_list) {
                struct event *event = node_to_event(loop);

                if (event->state != EVENT_LOCKED || event->requeue_next_usec > now_usec)
                        continue;

                event_unset_whole_disk(event);
                event->state = EVENT_QUEUED;
        }
}

static void manager_requeue_locked_events_by_device(struct udev_device *dev) {
        struct udev_list_node *loop;
        const char *devname;

        /* When a new event for a block device is queued or we get an inotify event, assume that the
         * device is not locked anymore. The assumption may not be true, but that should not cause any
         * issues, as in that case events will be requeued soon. */

        if (n_locked_events == 0)
                return;

        if (udev_get_whole_disk(dev, NULL, &devname) <= 0)
                return;

        udev_list_node_foreach(loop, &event_list) {
                struct event *event = node_to_event(loop);

                if (event->state != EVENT_LOCKED || !streq(event->whole_disk, devname))
                        continue;

                event_unset_whole_disk(event);
                event->state = EVENT_QUEUED;
        }
}

static int event_enter_locked(struct event *event, const char *whole_disk) {
        char buf[FORMAT_TIMESPAN_MAX];
        usec_t now_usec;
        char *copy;

        assert(event);
        assert(event->state == EVENT_RUNNING);

        /* add a short delay to suppress busy loop */
        now_usec = now(CLOCK_MONOTONIC);

        if (event->requeue_timeout_usec > 0 && event->requeue_timeout_usec <= now_usec)
                return log_warning_errno(ETIMEDOUT,
                                         "%s: The underlying block device is locked by a process more than %s, skipping event (SEQNUM=%llu, ACTION=%s).",
                                         event->devpath,
                                         format_timespan(buf, sizeof(buf), EVENT_REQUEUE_TIMEOUT_USEC, USEC_PER_MINUTE),
                                         event->seqnum, strna(udev_device_get_action(event->dev)));

        event->requeue_next_usec = usec_add(now_usec, EVENT_REQUEUE_INTERVAL_USEC);
        if (event->requeue_timeout_usec == 0)
                event->requeue_timeout_usec = usec_add(now_usec, EVENT_REQUEUE_TIMEOUT_USEC);

        if (isempty(whole_disk))
                return log_warning_errno(EBADMSG,
                                         "%s: Unexpected message from worker received, skipping event (SEQNUM=%llu, ACTION=%s).",
                                         event->devpath, event->seqnum, strna(udev_device_get_action(event->dev)));

        copy = strdup(whole_disk);
        if (!copy)
                return log_oom();

        free(event->whole_disk);
        event->whole_disk = copy;
        event->state = EVENT_LOCKED;
        n_locked_events++;
        return 0;
}

static void worker_returned(int fd_worker) {
        assert(fd_worker >= 0);

        for (;;) {
                struct worker_message msg;
                struct iovec iovec;
                union {
                        struct cmsghdr cmsghdr;
                        uint8_t buf[CMSG_SPACE(sizeof(struct ucred))];
                } control = {};
                struct msghdr msghdr;
                struct cmsghdr *cmsg;
                ssize_t size;
                struct ucred *ucred = NULL;
                struct worker *worker;
                struct event *event;

                memzero(&iovec, sizeof(struct iovec));
                iovec.iov_base = &msg;
                iovec.iov_len = sizeof(msg);

                memzero(&msghdr, sizeof(struct msghdr));
                msghdr.msg_iov = &iovec;
                msghdr.msg_iovlen = 1;
                msghdr.msg_control = &control;
                msghdr.msg_controllen = sizeof(control);

                size = recvmsg(fd_worker, &msghdr, MSG_DONTWAIT);
                if (size < 0) {
                        if (errno == EINTR)
                                continue;
                        else if (errno == EAGAIN)
                                /* nothing more to read */
                                break;

                        log_error_errno(errno, "failed to receive message: %m");
                        return;
                } else if (size != sizeof(struct worker_message)) {
                        log_warning_errno(EIO, "ignoring worker message with invalid size %zi bytes", size);
                        return;
                }

                for (cmsg = CMSG_FIRSTHDR(&msghdr); cmsg; cmsg = CMSG_NXTHDR(&msghdr, cmsg)) {
                        if (cmsg->cmsg_level == SOL_SOCKET &&
                            cmsg->cmsg_type == SCM_CREDENTIALS &&
                            cmsg->cmsg_len == CMSG_LEN(sizeof(struct ucred)))
                                ucred = (struct ucred*) CMSG_DATA(cmsg);
                }

                if (!ucred || ucred->pid <= 0) {
                        log_warning_errno(EIO, "ignoring worker message without valid PID");
                        continue;
                }

                /* lookup worker who sent the signal */
                worker = hashmap_get(workers, UINT_TO_PTR(ucred->pid));
                if (!worker) {
                        log_debug("worker ["PID_FMT"] returned, but is no longer tracked", ucred->pid);
                        continue;
                }

                if (worker->state == WORKER_KILLING) {
                        worker->state = WORKER_KILLED;
                        kill(worker->pid, SIGTERM);
                } else if (worker->state != WORKER_KILLED)
                        worker->state = WORKER_IDLE;

                /* worker returned */
                event = worker->event;
                if (event && msg.result == EVENT_RESULT_TRY_AGAIN) {
                        /* The worker cannot lock the device, keep the event until the device is unlocked. */
                        worker->event = NULL;
                        event->worker = NULL;

                        msg.whole_disk[sizeof(msg.whole_disk) - 1] = '\0';
                        if (event_enter_locked(event, msg.whole_disk) < 0) {
                                /* eudev: the rules did not run for this event, so the database and the tag
                                 * index still describe the device as of its previous event. Keep them, and
                                 * only pass the skipped event on to listeners, as systemd did before
                                 * v258; on exit, the monitor is already closed. */
                                if (monitor)
                                        udev_monitor_send_device(monitor, NULL, event->dev);
                                event_free(event);
                        }
                } else
                        event_free(event);
        }
}

static void event_queue_update(void) {
        int r;

        /* keep /run/udev/queue also while child processes are re-reading partition tables, which trigger
         * events, and until udevd received the change events it triggered itself */
        if (!udev_list_node_is_empty(&event_list) || !set_isempty(synthesize_change_children) ||
            !set_isempty(synthesized_events)) {
                r = touch("/run/udev/queue");
                if (r < 0)
                        log_warning_errno(r, "could not touch /run/udev/queue: %m");
        } else {
                r = unlink("/run/udev/queue");
                if (r < 0 && errno != ENOENT)
                        log_warning("could not unlink /run/udev/queue: %m");
        }
}

/* Like manager_merge_config_log_level() of systemd: with trace logging, the log level is debug, otherwise it is
 * the one set with udevadm control, or the default one. udev.conf has the lowest priority, then followed by
 * --debug, the kernel command line, and udevadm control. */
static int manager_merge_config_log_level(void) {
        trace = control_trace || arg_trace;

        if (trace)
                return LOG_DEBUG;

        return control_log_level >= 0 ? control_log_level : default_log_level;
}

/* Like manager_merge_config() of systemd: the kernel command line takes precedence over the command line,
 * which takes precedence over udev.conf, and 0 means that the setting is not given, so that e.g.
 * udev.children-max=0 does not override --children-max=. The log level is merged as described above; this
 * is called once at startup, when the current log level is the one of udev.conf, which udev_new() applied. */
static void manager_merge_config(void) {
        default_log_level = config_by_kernel.log_level >= 0 ? config_by_kernel.log_level :
                            config_by_command.log_level >= 0 ? config_by_command.log_level :
                            log_get_max_level();

        arg_children_max = config_by_kernel.children_max ?: config_by_command.children_max ?:
                           config_by_udev_conf.children_max;
        arg_exec_delay_usec = config_by_kernel.exec_delay_usec ?: config_by_command.exec_delay_usec ?:
                              config_by_udev_conf.exec_delay_usec;
        arg_event_timeout_usec = config_by_kernel.timeout_usec ?: config_by_command.timeout_usec ?:
                                 config_by_udev_conf.timeout_usec ?: DEFAULT_EVENT_TIMEOUT_USEC;
        /* like MERGE_NON_NEGATIVE() of systemd, the kernel command line has no such option */
        arg_resolve_names = config_by_command.resolve_names != RESOLVE_NAMES_UNSET ? config_by_command.resolve_names :
                            config_by_udev_conf.resolve_names != RESOLVE_NAMES_UNSET ? config_by_udev_conf.resolve_names :
                            1;
        arg_timeout_signal = config_by_kernel.timeout_signal ?: config_by_command.timeout_signal ?:
                             config_by_udev_conf.timeout_signal ?: SIGKILL;
        arg_blockdev_read_only = config_by_kernel.blockdev_read_only;
}

/* Like manager_adjust_config() of systemd: refuses a too short event timeout, and a delay of RUN that is not
 * shorter than the timeout. */
static void manager_adjust_config(void) {
        char buf[FORMAT_TIMESPAN_MAX], buf2[FORMAT_TIMESPAN_MAX];

        if (arg_event_timeout_usec < MIN_EVENT_TIMEOUT_USEC) {
                log_debug("Timeout (%s) for processing event is too small, using the default: %s",
                          format_timespan(buf, sizeof(buf), arg_event_timeout_usec, 1),
                          format_timespan(buf2, sizeof(buf2), DEFAULT_EVENT_TIMEOUT_USEC, 1));

                arg_event_timeout_usec = DEFAULT_EVENT_TIMEOUT_USEC;
        }

        if (arg_exec_delay_usec >= arg_event_timeout_usec) {
                log_debug("Delay (%s) for executing RUN= commands is too large compared with the timeout (%s) for event execution, ignoring the delay.",
                          format_timespan(buf, sizeof(buf), arg_exec_delay_usec, 1),
                          format_timespan(buf2, sizeof(buf2), arg_event_timeout_usec, 1));

                arg_exec_delay_usec = 0;
        }

        arg_event_timeout_warn_usec = (arg_event_timeout_usec / 3) ? : 1;
}

/* Like extra_timeout_usec() of systemd: the time that udevd waits after the event timeout before it kills a
 * worker, 10 seconds, or the value of $UDEV_EXTRA_TIMEOUT_SEC, or $SYSTEMD_UDEV_EXTRA_TIMEOUT_SEC when that is
 * not set, up to 5 hours. */
static usec_t extra_timeout_usec(void) {
        static usec_t saved = 10 * USEC_PER_SEC;
        static bool parsed = false;
        const char *name = "UDEV_EXTRA_TIMEOUT_SEC", *e;
        usec_t timeout;
        int r;

        if (parsed)
                return saved;

        parsed = true;

        e = secure_getenv(name);
        if (!e) {
                name = "SYSTEMD_UDEV_EXTRA_TIMEOUT_SEC";
                e = secure_getenv(name);
        }
        if (!e)
                return saved;

        r = parse_sec(e, &timeout);
        if (r < 0)
                log_debug_errno(r, "Failed to parse $%s=%s, ignoring: %m", name, e);
        else if (timeout > 5 * USEC_PER_HOUR) /* Add an arbitrary upper bound */
                log_debug("Parsed $%s=%s is too large, ignoring.", name, e);
        else
                saved = timeout;

        return saved;
}

/* Like manager_kill_worker_timeout() of systemd: the event timeout is also used as the timeout for running
 * programs specified in IMPORT{program}=, PROGRAM=, or RUN=. Here, let's add an extra time before the manager
 * kills a worker, to make it possible that the worker detects timed out of spawned programs, kills them, and
 * finalizes the event. */
static usec_t manager_kill_worker_timeout(void) {
        return usec_add(arg_event_timeout_usec, extra_timeout_usec());
}

/* Like the timers of systemd's worker_attach_event(), on_worker_timeout_warning() and on_worker_timeout_kill():
 * warns when the event of a worker takes a third of the event timeout, and sends the timeout signal to the worker
 * after the event timeout and the extra time. Called on every iteration of the main loop, and not only when it
 * times out, so that a hanging worker is also killed when the loop never waits that long, e.g. as uevents or
 * messages keep arriving. Returns the time in milliseconds until the next of these is due, rounded up, or -1 if
 * there is none. */
static int manager_check_worker_timeouts(void) {
        struct worker *worker;
        usec_t now_usec, next_usec = USEC_INFINITY;
        Iterator i;

        if (hashmap_isempty(workers))
                return -1;

        now_usec = now(CLOCK_MONOTONIC);

        HASHMAP_FOREACH(worker, workers, i) {
                struct event *event = worker->event;
                usec_t usec;

                if (worker->state != WORKER_RUNNING && worker->state != WORKER_KILLING)
                        continue;

                assert(event);

                usec = usec_add(event->start_usec, manager_kill_worker_timeout());
                if (usec <= now_usec) {
                        log_error("worker ["PID_FMT"] %s timeout; kill it", worker->pid, event->devpath);
                        (void) kill_and_sigcont(worker->pid, arg_timeout_signal);
                        worker->state = WORKER_KILLED;

                        log_error("seq %llu '%s' killed", udev_device_get_seqnum(event->dev), event->devpath);
                        continue;
                }
                next_usec = MIN(next_usec, usec);

                if (event->warned)
                        continue;

                usec = usec_add(event->start_usec, arg_event_timeout_warn_usec);
                if (usec <= now_usec) {
                        log_warning("worker ["PID_FMT"] %s is taking a long time", worker->pid, event->devpath);
                        event->warned = true;
                } else
                        next_usec = MIN(next_usec, usec);
        }

        if (next_usec == USEC_INFINITY)
                return -1;

        next_usec = DIV_ROUND_UP(next_usec - now_usec, USEC_PER_MSEC);
        return next_usec > INT_MAX ? INT_MAX : (int) next_usec;
}

static void manager_set_log_level(int log_level) {
        int old = log_get_max_level(), new;

        control_log_level = log_level;
        new = manager_merge_config_log_level();

        if (new == old)
                return;

        log_set_max_level(new);
        worker_kill(false);
}

static void manager_set_trace(bool enable) {
        bool old = trace;
        int log_level;

        control_trace = enable;
        log_level = manager_merge_config_log_level();

        if (trace == old)
                return;

        log_set_max_level(log_level);
        worker_kill(false);
}

/* Like manager_revert() of systemd: reverts the settings of udevadm control. */
static void manager_revert(void) {
        int old_log_level = log_get_max_level(), log_level;
        bool old_trace = trace, kill = false;

        if (udev_list_get_entry(&properties_list)) {
                udev_list_cleanup(&properties_list);
                kill = true;
        }

        control_log_level = -1;
        control_trace = false;
        log_level = manager_merge_config_log_level();
        arg_children_max = default_children_max;

        if (log_level != old_log_level || trace != old_trace) {
                log_set_max_level(log_level);
                kill = true;
        }

        if (kill)
                worker_kill(false);
}

static void manager_set_default_children_max(void) {
        uint64_t cpu_limit, mem_limit, cpu_count = 1;
        int r;

        if (arg_children_max != 0)
                return;

        r = cpus_in_affinity_mask();
        if (r < 0)
                log_warning_errno(r, "Failed to determine number of local CPUs, ignoring: %m");
        else
                cpu_count = r;

        cpu_limit = cpu_count * 2 + 16;
        /* the MAX() of sys/param.h evaluates its arguments twice */
        mem_limit = physical_memory() / (128*1024*1024);
        mem_limit = MAX(mem_limit, UINT64_C(10));

        arg_children_max = MIN(MIN(cpu_limit, mem_limit), WORKER_NUM_MAX);
        log_debug("Set children_max to %u", arg_children_max);
}

/* receive the udevd message from userspace */
static void handle_ctrl_msg(struct udev_ctrl *uctrl) {
        _cleanup_udev_ctrl_connection_unref_ struct udev_ctrl_connection *ctrl_conn = NULL;
        _cleanup_udev_ctrl_msg_unref_ struct udev_ctrl_msg *ctrl_msg = NULL;
        const char *str;
        int i;

        assert(uctrl);

        ctrl_conn = udev_ctrl_get_connection(uctrl);
        if (!ctrl_conn)
                return;

        ctrl_msg = udev_ctrl_receive_msg(ctrl_conn);
        if (!ctrl_msg)
                return;

        if (udev_ctrl_get_set_log_level(ctrl_msg, &i) > 0) {
                /* this also refuses a negative level, which was ignored silently */
                if ((i & LOG_PRIMASK) != i)
                        log_warning("udevd message (SET_LOG_LEVEL) received with invalid log_level=%i, ignoring", i);
                else {
                        log_debug("udevd message (SET_LOG_LEVEL) received, log_level=%i", i);
                        manager_set_log_level(i);
                }
        }

        if (udev_ctrl_get_stop_exec_queue(ctrl_msg) > 0) {
                log_debug("udevd message (STOP_EXEC_QUEUE) received");
                stop_exec_queue = true;
        }

        if (udev_ctrl_get_start_exec_queue(ctrl_msg) > 0) {
                log_debug("udevd message (START_EXEC_QUEUE) received");
                stop_exec_queue = false;
                start_exec_queue = true;
        }

        if (udev_ctrl_get_reload(ctrl_msg) > 0) {
                log_debug("udevd message (RELOAD) received");
                reload = true;
        }

        str = udev_ctrl_get_set_env(ctrl_msg);
        if (str != NULL) {
                char *key;

                key = strdup(str);
                if (key != NULL) {
                        char *val;

                        val = strchr(key, '=');
                        if (val != NULL) {
                                val[0] = '\0';
                                val = &val[1];
                                if (val[0] == '\0') {
                                        log_debug("udevd message (ENV) received, unset '%s'", key);
                                        udev_list_entry_add(&properties_list, key, NULL);
                                } else {
                                        log_debug("udevd message (ENV) received, set '%s=%s'", key, val);
                                        udev_list_entry_add(&properties_list, key, val);
                                }
                        } else {
                                log_error("wrong key format '%s'", key);
                        }
                        free(key);
                }
                worker_kill(false);
        }

        if (udev_ctrl_get_revert(ctrl_msg) > 0) {
                log_debug("udevd message (REVERT) received");
                manager_revert();
                (void) udev_ctrl_msg_reply(ctrl_msg);
        }

        i = udev_ctrl_get_set_trace(ctrl_msg);
        if (i >= 0) {
                log_debug("udevd message (SET_TRACE) received, %s", i ? "yes" : "no");
                manager_set_trace(i);
                (void) udev_ctrl_msg_reply(ctrl_msg);
        }

        if (udev_ctrl_get_set_children_max(ctrl_msg, &i) > 0) {
                if (i < 0)
                        log_warning("udevd message (SET_MAX_CHILDREN) received with invalid children_max=%i, ignoring", i);
                else {
                        log_debug("udevd message (SET_MAX_CHILDREN) received, children_max=%i", i);
                        arg_children_max = i;

                        /* When 0 is specified, determine the maximum based on the system resources. */
                        manager_set_default_children_max();
                }
        }

        if (udev_ctrl_get_ping(ctrl_msg) > 0) {
                log_debug("udevd message (SYNC) received");
                /* tell settle that we are busy or idle, this needs to be before the
                 * PING handling
                 */
                event_queue_update();
        }

        if (udev_ctrl_get_exit(ctrl_msg) > 0) {
                log_debug("udevd message (EXIT) received");
                udev_exit = true;
                /* keep reference to block the client until we exit */
                udev_ctrl_conn = udev_ctrl_connection_ref(ctrl_conn);
        }

        return;
}

static void synthesized_events_clear(void) {
        for (;;) {
                _cleanup_free_ char *uuid = set_steal_first(synthesized_events);
                if (!uuid)
                        return;

                log_warning("Could not receive synthesized event with UUID %s, ignoring.", uuid);
        }
}

/* Returns the time in milliseconds until udevd stops waiting for the synthetic change events it triggered, 0
 * if that is due now, or -1 if it does not wait for any. */
static int synthesized_events_timeout(void) {
        usec_t now_usec, t;

        if (set_isempty(synthesized_events))
                return -1;

        now_usec = now(CLOCK_MONOTONIC);
        if (synthesized_events_clear_usec <= now_usec)
                return 0;

        /* round up, the events are due when the timeout expires */
        t = (synthesized_events_clear_usec - now_usec + USEC_PER_MSEC - 1) / USEC_PER_MSEC;
        return t > INT_MAX ? INT_MAX : (int) t;
}

/* If the event is one udevd triggered, forget its UUID. */
static void synthesized_event_received(struct udev_device *dev) {
        char uuid[ID128_UUID_STRING_MAX];
        const char *s;
        id128_t id;

        if (set_isempty(synthesized_events))
                return;

        /* SYNTH_UUID=0 is set whenever a device is triggered by userspace without specifying a UUID */
        s = udev_device_get_property_value(dev, "SYNTH_UUID");
        if (!s || id128_from_string(s, &id) < 0)
                return;

        free(set_remove(synthesized_events, id128_to_uuid_string(id, uuid)));
}

/* Like synthesize_change_one() of systemd: triggers a change event of the device, and remembers its UUID, so
 * that /run/udev/queue is kept until udevd received the event. */
static int synthesize_change_one(struct udev_device *dev) {
        char uuid[ID128_UUID_STRING_MAX];
        id128_t id;
        char *copy;
        int r;

        log_debug("device %s closed, synthesising 'change' on %s",
                  udev_device_get_devnode(dev), udev_device_get_syspath(dev));

        id128_randomize(&id);
        id128_to_uuid_string(id, uuid);

        /* Synthetic uevents with a UUID, which the kernel passes on as SYNTH_UUID=, need Linux 4.13 or newer.
         * This finds out whether the kernel supports them, and triggers the uevent without the UUID when it
         * does not, see there. */
        r = uevent_trigger_with_uuid(udev_device_get_udev(dev), udev_device_get_syspath(dev), "change", uuid);
        if (r < 0)
                return log_debug_errno(r, "%s: Failed to trigger 'change' uevent: %m", udev_device_get_devpath(dev));
        if (r == 0)
                /* without a UUID, there is nothing to wait for */
                return 0;

        /* Avoid /run/udev/queue file being removed by event_queue_update(). */
        copy = strdup(uuid);
        if (!copy)
                return log_oom_debug();

        /* Let's not wait for too many events, to make not udevd consume huge amount of memory.
         * Typically (but unfortunately, not always), the kernel provides events in the order we triggered.
         * Hence, remembering the newest UUID should be mostly enough. */
        while (set_size(synthesized_events) >= 1024) {
                _cleanup_free_ char *old = set_steal_first(synthesized_events);

                log_debug("Too many synthesized events are waiting, forgetting synthesized event with UUID %s.", old);
        }

        r = set_ensure_allocated(&synthesized_events, &string_hash_ops);
        if (r < 0) {
                free(copy);
                return log_oom_debug();
        }

        r = set_consume(synthesized_events, copy);
        if (r < 0)
                return log_oom_debug();

        synthesized_events_clear_usec = usec_add(now(CLOCK_MONOTONIC), USEC_PER_MINUTE);
        return 0;
}

static int synthesize_change(struct udev_device *dev) {
        pid_t pid;
        int r;

        if (streq_ptr("block", udev_device_get_subsystem(dev)) &&
            streq_ptr("disk", udev_device_get_devtype(dev)) &&
            !startswith(udev_device_get_sysname(dev), "dm-")) {
                /* Make room for the PID before forking, so that it can be stored; without it, the queue
                 * file would not be kept while the process runs, so then re-read the partition table
                 * synchronously, as before. */
                r = set_ensure_allocated(&synthesize_change_children, NULL);
                if (r >= 0)
                        r = set_reserve(synthesize_change_children, 1);
                if (r < 0) {
                        log_warning_errno(r, "Failed to allocate memory to remember the process re-reading the partition table of %s, re-reading it synchronously: %m",
                                          udev_device_get_devnode(dev));
                        (void) reread_partition_table(dev, REREADPT_FORCE_UEVENT|REREADPT_BSD_LOCK);
                        return 0;
                }

                pid = fork();
                if (pid < 0) {
                        /* Unlike systemd, which then sends no change event at all, re-read the partition
                         * table synchronously, as before the child was introduced. */
                        log_warning_errno(errno, "Failed to fork process to re-read the partition table of %s, re-reading it synchronously: %m",
                                          udev_device_get_devnode(dev));
                        (void) reread_partition_table(dev, REREADPT_FORCE_UEVENT|REREADPT_BSD_LOCK);
                        return 0;
                }
                if (pid == 0) {
                        /* child */
                        (void) prctl(PR_SET_NAME, "(udev-synth)");
                        (void) prctl(PR_SET_PDEATHSIG, SIGTERM);
                        (void) sigprocmask(SIG_SETMASK, &sigmask_orig, NULL);

                        /* Like FORK_CLOSE_ALL_FDS and FORK_REOPEN_LOG of systemd: close all file descriptors
                         * above stderr, and open the log again, which is closed first, as its descriptor is
                         * closed too. */
                        log_close();
                        (void) close_all_fds();
                        log_open();

                        /* Like the workers, do not keep the OOM protection of the main process, which
                         * systemd's child does. */
                        r = write_string_file("/proc/self/oom_score_adj", "0");
                        if (r < 0)
                                log_debug_errno(r, "Failed to reset OOM score, ignoring: %m");

                        (void) reread_partition_table(dev, REREADPT_FORCE_UEVENT|REREADPT_BSD_LOCK);
                        _exit(EXIT_SUCCESS);
                }

                /* This does not fail, the room was made above. */
                r = set_put(synthesize_change_children, UINT_TO_PTR(pid));
                if (r < 0)
                        log_warning_errno(r, "Failed to remember process ["PID_FMT"], ignoring: %m", pid);

                return 0;
        }

        return synthesize_change_one(dev);
}

static int handle_inotify(struct udev *udev) {
        union inotify_event_buffer buffer;
        struct inotify_event *e;
        ssize_t l;

        l = read(fd_inotify, &buffer, sizeof(buffer));
        if (l < 0) {
                if (errno == EAGAIN || errno == EINTR)
                        return 0;

                return log_error_errno(errno, "Failed to read inotify fd: %m");
        }

        FOREACH_INOTIFY_EVENT(e, buffer, l) {
                struct udev_device *dev;

                dev = udev_watch_lookup(udev, e->wd);
                if (!dev)
                        continue;

                log_debug("inotify event: %x for %s", e->mask, udev_device_get_devnode(dev));
                if (e->mask & IN_CLOSE_WRITE) {
                        manager_requeue_locked_events_by_device(dev);
                        synthesize_change(dev);
                }

                /* Do not handle IN_IGNORED here. It should be handled by worker in 'remove' uevent;
                 * udev_event_execute_rules() -> udev_watch_end(). */

                udev_device_unref(dev);
        }

        return 0;
}

static void handle_signal(struct udev *udev __attribute__((unused)), int signo) {
        switch (signo) {
        case SIGINT:
        case SIGTERM:
                udev_exit = true;
                break;
        case SIGCHLD:
                for (;;) {
                        pid_t pid;
                        int status;
                        struct worker *worker;

                        pid = waitpid(-1, &status, WNOHANG);
                        if (pid <= 0)
                                break;

                        if (set_remove(synthesize_change_children, UINT_TO_PTR(pid))) {
                                log_debug("process ["PID_FMT"] re-reading the partition table exited", pid);
                                continue;
                        }

                        worker = hashmap_get(workers, UINT_TO_PTR(pid));
                        if (!worker) {
                                log_warning("worker ["PID_FMT"] is unknown, ignoring", pid);
                                continue;
                        }

                        if (WIFEXITED(status)) {
                                if (WEXITSTATUS(status) == 0)
                                        log_debug("worker ["PID_FMT"] exited", pid);
                                else
                                        log_warning("worker ["PID_FMT"] exited with return code %i", pid, WEXITSTATUS(status));
                        } else if (WIFSIGNALED(status)) {
                                log_warning("worker ["PID_FMT"] terminated by signal %i (%s)",
                                            pid, WTERMSIG(status), strsignal(WTERMSIG(status)));
                        } else if (WIFSTOPPED(status)) {
                                log_info("worker ["PID_FMT"] stopped", pid);
                                break;
                        } else if (WIFCONTINUED(status)) {
                                log_info("worker ["PID_FMT"] continued", pid);
                                break;
                        } else {
                                log_warning("worker ["PID_FMT"] exit with status 0x%04x", pid, status);
                        }

                        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
                                if (worker->event) {
                                        log_error("worker ["PID_FMT"] failed while handling '%s'", pid, worker->event->devpath);
                                        event_broadcast_on_error(worker->event);
                                }
                        }

                        worker_free(worker);
                }
                break;
        case SIGHUP:
                reload = true;
                break;
        }
}

/* parse_proc_cmdline_item() runs before the log level is merged, which the kernel command line can change,
 * so it keeps its messages here, and main() logs them with the merged level, see cmdline_log_flush(). Each
 * message starts with the digit of its log level. */
static char **cmdline_messages = NULL;

static void cmdline_log(int level, int error, const char *format, ...) _printf_(3, 4);
static void cmdline_log(int level, int error, const char *format, ...) {
        _cleanup_free_ char *m = NULL;
        va_list ap;
        char *s;
        int r;

        assert(level >= 0 && level <= LOG_DEBUG);

        /* for %m */
        errno = abs(error);

        va_start(ap, format);
        r = vasprintf(&m, format, ap);
        va_end(ap);
        if (r < 0) {
                log_oom();
                return;
        }

        if (asprintf(&s, "%i%s", level, m) < 0 || strv_consume(&cmdline_messages, s) < 0)
                log_oom();
}

static void cmdline_log_flush(void) {
        char **m;

        STRV_FOREACH(m, cmdline_messages)
                log_full(**m - '0', "%s", *m + 1);

        strv_free(cmdline_messages);
        cmdline_messages = NULL;
}

/* Like proc_cmdline_value_missing() of systemd: warns and returns true if the key has no value, with the message
 * kept for cmdline_log_flush(). */
static bool cmdline_value_missing(const char *key, const char *value) {
        if (value)
                return false;

        cmdline_log(LOG_WARNING, 0, "Missing argument for %s= kernel command line switch, ignoring.", key);
        return true;
}

/*
 * read the kernel command line, in case we need to get into debug mode
 *   udev.log_level=<level>                    syslog priority
 *   udev.trace[=<bool>]                       trace logging, with debug level
 *   udev.children_max=<number of workers>     events are fully serialized if set to 1
 *   udev.exec_delay=<number of seconds>       delay execution of every executed program
 *   udev.event_timeout=<number of seconds>    seconds to wait before terminating an event
 *   udev.timeout_signal=<signal>              signal sent to workers and programs on a timeout
 *   udev.blockdev_read_only[=<bool>]          mark all block devices read-only when they appear
 * "-" and "_" are the same in the keys, e.g. udev.children-max= is udev.children_max=.
 * The messages are logged later, see cmdline_log().
 */
static int parse_proc_cmdline_item(const char *key, const char *value) {
        int r = 0;

        assert(key);

        /* Like PROC_CMDLINE_STRIP_RD_PREFIX of systemd; parse_proc_cmdline() passes the parameters starting
         * with "rd." only in an initrd. */
        if (startswith(key, "rd."))
                key += strlen("rd.");

        if (proc_cmdline_key_streq(key, "udev.log_level") ||
            proc_cmdline_key_streq(key, "udev.log_priority")) { /* kept for backward compatibility */

                if (cmdline_value_missing(key, value))
                        return 0;

                r = util_log_priority(value);
                if (r >= 0)
                        config_by_kernel.log_level = r;
                else if (r != -ERANGE)
                        r = -EINVAL; /* not an errno from log_level_from_string() */

        } else if (proc_cmdline_key_streq(key, "udev.event_timeout")) {

                if (cmdline_value_missing(key, value))
                        return 0;

                r = parse_sec(value, &config_by_kernel.timeout_usec);

        } else if (proc_cmdline_key_streq(key, "udev.children_max")) {

                if (cmdline_value_missing(key, value))
                        return 0;

                r = safe_atou(value, &config_by_kernel.children_max);

        } else if (proc_cmdline_key_streq(key, "udev.exec_delay")) {

                if (cmdline_value_missing(key, value))
                        return 0;

                r = parse_sec(value, &config_by_kernel.exec_delay_usec);

        } else if (proc_cmdline_key_streq(key, "udev.timeout_signal")) {

                if (cmdline_value_missing(key, value))
                        return 0;

                r = signal_from_string(value);
                if (r > 0 && !signal_terminates(r)) {
                        /* e.g. SIGCHLD, with which the timeout would not stop anything */
                        cmdline_log(LOG_WARNING, 0, "%s=%s cannot terminate a process, ignoring.", key, value);
                        return 0;
                }
                if (r > 0)
                        config_by_kernel.timeout_signal = r;

        } else if (proc_cmdline_key_streq(key, "udev.blockdev_read_only")) {

                if (!value)
                        config_by_kernel.blockdev_read_only = true;
                else {
                        r = parse_boolean(value);
                        if (r < 0)
                                cmdline_log(LOG_WARNING, r, "Failed to parse udev.blockdev-read-only argument, ignoring: %s", value);
                        else
                                config_by_kernel.blockdev_read_only = r;
                }

                if (config_by_kernel.blockdev_read_only)
                        cmdline_log(LOG_NOTICE, 0, "All physical block devices will be marked read-only.");

                return 0;

        } else if (proc_cmdline_key_streq(key, "udev.trace")) {

                if (!value)
                        arg_trace = true;
                else {
                        r = parse_boolean(value);
                        if (r < 0)
                                cmdline_log(LOG_WARNING, r, "Failed to parse udev.trace argument, ignoring: %s", value);
                        else
                                arg_trace = r;
                }

                return 0;
        }

        if (r < 0)
                cmdline_log(LOG_WARNING, r, "Failed to parse \"%s=%s\", ignoring: %m", key, value);

        return 0;
}

static void help(void) {
        printf("%s [OPTIONS...]\n\n"
               "Manages devices.\n\n"
               "  -h --help                   Print this message\n"
               "  -V --version                Print version of the program\n"
               "  -d --daemon                 Detach and run in the background\n"
               "  -D --debug                  Enable debug output\n"
               "  -r --ready-notify=FD        Notify readiness via file descriptor\n"
               "  -c --children-max=INT       Set maximum number of workers\n"
               "  -e --exec-delay=SECONDS     Seconds to wait before executing RUN=\n"
               "  -t --event-timeout=SECONDS  Seconds to wait before terminating an event\n"
               "  -N --resolve-names=early|late|never\n"
               "                              When to resolve users and groups\n"
               "     --timeout-signal=SIGNAL  Signal used when terminating an event\n"
               , program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_TIMEOUT_SIGNAL = 0x100,
        };

        static const struct option options[] = {
                { "daemon",             no_argument,            NULL, 'd' },
                { "debug",              no_argument,            NULL, 'D' },
                { "ready-notify",       required_argument,      NULL, 'r' },
                { "children-max",       required_argument,      NULL, 'c' },
                { "exec-delay",         required_argument,      NULL, 'e' },
                { "event-timeout",      required_argument,      NULL, 't' },
                { "resolve-names",      required_argument,      NULL, 'N' },
                { "help",               no_argument,            NULL, 'h' },
                { "version",            no_argument,            NULL, 'V' },
                { "timeout-signal",     required_argument,      NULL, ARG_TIMEOUT_SIGNAL },
                {}
        };

        static const char optstring[] = "c:de:Dt:N:hVr:";
        int c;
        unsigned fd_ready_u;

        assert(argc >= 0);
        assert(argv);

        /* Unlike systemd, which logs to the console with --debug only after parsing all options and the
         * kernel command line, find -D/--debug before the other options, so that the warnings about all of
         * them, also about those that come before it, go to the console, and with the debug level, also
         * when udev_log= in udev.conf, which udev_new() applied already, is lower. The final log level is
         * set when the settings are merged, see main(). getopt_long() reports invalid options only in the
         * second pass, and starts again with optind set to 0. */
        opterr = 0;
        while ((c = getopt_long(argc, argv, optstring, options, NULL)) >= 0)
                if (c == 'D') {
                        config_by_command.log_level = LOG_DEBUG;
                        log_set_target(LOG_TARGET_CONSOLE);
                        log_set_max_level(LOG_DEBUG);
                }
        opterr = 1;
        optind = 0;

        while ((c = getopt_long(argc, argv, optstring, options, NULL)) >= 0) {
                int r;

                switch (c) {

                case 'd':
                        arg_daemonize = true;
                        break;
                case 'c':
                        r = safe_atou(optarg, &config_by_command.children_max);
                        if (r < 0)
                                log_warning("Invalid --children-max ignored: %s", optarg);
                        break;
                case 'e':
                        r = parse_sec(optarg, &config_by_command.exec_delay_usec);
                        if (r < 0)
                                log_warning_errno(r, "Failed to parse --exec-delay= value '%s', ignoring: %m", optarg);
                        break;
                case 't':
                        r = parse_sec(optarg, &config_by_command.timeout_usec);
                        if (r < 0)
                                log_warning_errno(r, "Failed to parse --event-timeout= value '%s', ignoring: %m", optarg);
                        break;
                case ARG_TIMEOUT_SIGNAL:
                        r = signal_from_string(optarg);
                        if (r <= 0)
                                log_warning_errno(r, "Failed to parse --timeout-signal= value '%s', ignoring: %m", optarg);
                        else if (!signal_terminates(r))
                                /* e.g. SIGCHLD, with which the timeout would not stop anything */
                                log_warning("--timeout-signal=%s cannot terminate a process, ignoring.", optarg);
                        else
                                config_by_command.timeout_signal = r;
                        break;
                case 'D':
                        /* handled above */
                        break;
                case 'N':
                        /* like systemd, warn and keep the setting of udev.conf, or the default */
                        r = udev_parse_resolve_names(optarg, &config_by_command.resolve_names);
                        if (r < 0)
                                log_warning("Invalid --resolve-names= value '%s', ignoring.", optarg);
                        break;
                case 'r':
                        r = safe_atou(optarg, &fd_ready_u);
                        if (r < 0 || fd_ready_u > INT_MAX) {
                                log_warning("Invalid --ready-notify ignored: %s", optarg);
                        } else {
                                fd_ready = fd_ready_u;
                        }
                        break;
                case 'h':
                        help();
                        return 0;
                case 'V':
                        printf("%s\n", UDEV_VERSION);
                        return 0;
                case '?':
                        return -EINVAL;
                default:
                        assert_not_reached("Unhandled option");

                }
        }

        return 1;
}

int main(int argc, char *argv[]) {
        struct udev *udev;
        sigset_t mask;
        FILE *f;
        int fd_ctrl = -1;
        int fd_netlink = -1;
        int fd_worker = -1;
        struct epoll_event ep_ctrl = { .events = EPOLLIN };
        struct epoll_event ep_inotify = { .events = EPOLLIN };
        struct epoll_event ep_signal = { .events = EPOLLIN };
        struct epoll_event ep_netlink = { .events = EPOLLIN };
        struct epoll_event ep_worker = { .events = EPOLLIN };
        int r = 0, one = 1;
        char **w;

        /*
         * Ensure no file descriptor unwillingly falls in the 0..2 range
         * Warning: DO NOT OPEN FILES BEFORE THE 3 OPENS BELOW
         */
        int fd_stdi = open("/dev/null", O_RDWR);
        int fd_stdo = open("/dev/null", O_RDWR);
        int fd_stde = open("/dev/null", O_RDWR);

        /* Close only the ones that are safe to close */
        if (fd_stdi > STDERR_FILENO)
                close(fd_stdi);
        if (fd_stdo > STDERR_FILENO)
                close(fd_stdo);
        if (fd_stde > STDERR_FILENO)
                close(fd_stde);

        /* Like log_setup() of systemd-udevd, before udev.conf is read, so that its udev_log= takes
         * precedence over $SYSTEMD_LOG_LEVEL, as in systemd. */
        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        udev = udev_new();
        if (!udev) {
                r = log_error_errno(errno, "could not allocate udev context: %m");
                goto exit;
        }

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto exit;

        config_by_udev_conf.children_max = udev_get_children_max(udev);
        config_by_udev_conf.exec_delay_usec = udev_get_exec_delay_usec(udev);
        config_by_udev_conf.timeout_usec = udev_get_event_timeout_usec(udev);
        (void) udev_get_resolve_names(udev, &config_by_udev_conf.resolve_names);
        config_by_udev_conf.timeout_signal = udev_get_timeout_signal(udev);

        r = parse_proc_cmdline(parse_proc_cmdline_item);
        if (r < 0)
                cmdline_log(LOG_WARNING, r, "failed to parse kernel command line, ignoring: %m");

        manager_merge_config();
        log_set_max_level(manager_merge_config_log_level());

        /* udev_new() read udev.conf, but only udevd warns about its invalid settings; with the merged log
         * level, as udev_new() applied udev_log= right away, so that e.g. --debug shows them too */
        STRV_FOREACH(w, udev_get_conf_warnings(udev))
                log_warning("%s", *w);

        /* the same for the kernel command line, e.g. so that udev_log=err in udev.conf does not hide its
         * warnings when --debug or udev.log_level= sets a higher level */
        cmdline_log_flush();

        manager_adjust_config();

        if (getuid() != 0) {
                r = log_error_errno(EPERM, "root privileges required");
                goto exit;
        }

        r = mac_selinux_init("/dev");
        if (r < 0) {
                log_error_errno(r, "could not initialize labelling: %m");
                goto exit;
        }

        /* set umask before creating any file/directory */
        r = chdir("/");
        if (r < 0) {
                r = log_error_errno(errno, "could not change dir to /: %m");
                goto exit;
        }

        umask(022);

        udev_list_init(udev, &properties_list, true);

        r = mkdir(UDEV_ROOT_RUN "/udev", 0755);
        if (r < 0 && errno != EEXIST) {
                r = log_error_errno(errno, "could not create " UDEV_ROOT_RUN "/udev: %m");
                goto exit;
        }

        dev_setup(NULL, UID_INVALID, GID_INVALID);

        /* before opening new files, make sure std{in,out,err} fds are in a sane state */
        if (arg_daemonize) {
                int fd;

                fd = open("/dev/null", O_RDWR);
                if (fd >= 0) {
                        if (write(STDOUT_FILENO, 0, 0) < 0)
                                dup2(fd, STDOUT_FILENO);
                        if (write(STDERR_FILENO, 0, 0) < 0)
                                dup2(fd, STDERR_FILENO);
                        if (fd > STDERR_FILENO)
                                close(fd);
                } else {
                        log_error("cannot open /dev/null");
                }
        }

        /* open control and netlink socket */
        udev_ctrl = udev_ctrl_new(udev);
        if (!udev_ctrl) {
                r = log_error_errno(EINVAL, "error initializing udev control socket");
                goto exit;
        }
        fd_ctrl = udev_ctrl_get_fd(udev_ctrl);

        monitor = udev_monitor_new_from_netlink(udev, "kernel");
        if (!monitor) {
                r = log_error_errno(EINVAL, "error initializing netlink socket");
                goto exit;
        }
        fd_netlink = udev_monitor_get_fd(monitor);

        r = udev_monitor_enable_receiving(monitor);
        if (r < 0) {
                log_error_errno(r, "error binding netlink socket: %m");
                goto exit;
        }

        if (udev_ctrl_enable_receiving(udev_ctrl) < 0) {
                r = log_error_errno(EINVAL, "error binding udev control socket");
                goto exit;
        }

        udev_monitor_set_receive_buffer_size(monitor, 128 * 1024 * 1024);

        log_info("starting version " VERSION " (udev " UDEV_VERSION ")");

        udev_event_check_config(udev);

        udev_builtin_init(udev);

        rules = udev_rules_new(udev, arg_resolve_names);
        if (!rules) {
                r = log_error_errno(ENOMEM, "error reading rules");
                goto exit;
        }

        r = udev_rules_apply_static_dev_perms(rules);
        if (r < 0)
                log_error_errno(r, "failed to apply permissions on static device nodes: %m");

        if (arg_daemonize) {
                pid_t pid;

                /* connect /dev/null to stdin, stdout, stderr */
                if (log_get_max_level() < LOG_DEBUG) {
                        int fd;

                        fd = open("/dev/null", O_RDWR|O_NOCTTY|O_CLOEXEC);
                        if (fd < 0)
                                log_warning_errno(errno, "Failed to redirect standard streams to /dev/null: %m");
                        else {
                                (void) dup2(fd, STDIN_FILENO);
                                (void) dup2(fd, STDOUT_FILENO);
                                (void) dup2(fd, STDERR_FILENO);
                                if (fd > STDERR_FILENO)
                                        close(fd);
                        }
                }

                pid = fork();
                switch (pid) {
                case 0:
                        break;
                case -1:
                        r = log_error_errno(errno, "fork of daemon failed: %m");
                        goto exit;
                default:
                        mac_selinux_finish();
                        log_close();
                        _exit(EXIT_SUCCESS);
                }

                setsid();

                write_string_file("/proc/self/oom_score_adj", "-1000");
        }

        manager_set_default_children_max();
        default_children_max = arg_children_max;

        udev_list_node_init(&event_list);

        f = fopen("/dev/kmsg", "w");
        if (f != NULL) {
                fprintf(f, "<30>udevd[%u]: starting eudev-" VERSION " (udev " UDEV_VERSION ")\n", getpid());
                fclose(f);
        }

        fd_inotify = udev_watch_init(udev);
        if (fd_inotify < 0) {
                r = log_error_errno(ENOMEM, "error initializing inotify");
                goto exit;
        }
        /* watch rules.d paths for changes */
        inotify_add_watch(fd_inotify, UDEV_RULES_DIR,
                          IN_DELETE | IN_MOVE | IN_CLOSE_WRITE);
        inotify_add_watch(fd_inotify, UDEV_CONF_DIR "/rules.d",
                          IN_DELETE | IN_MOVE | IN_CLOSE_WRITE);

        if (access(UDEV_ROOT_RUN "/udev/rules.d", F_OK) < 0) {
                udev_mkdir_p(UDEV_ROOT_RUN "/udev/rules.d", 0755);
        }
        inotify_add_watch(fd_inotify, UDEV_ROOT_RUN "/udev/rules.d",
                          IN_DELETE | IN_MOVE | IN_CLOSE_WRITE);

        udev_watch_restore(udev);

        /* block and listen to all signals on signalfd */
        sigfillset(&mask);
        sigprocmask(SIG_SETMASK, &mask, &sigmask_orig);
        fd_signal = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC);
        if (fd_signal < 0) {
                r = log_error_errno(errno, "error creating signalfd");
                goto exit;
        }

        /* unnamed socket from workers to the main daemon */
        if (socketpair(AF_LOCAL, SOCK_DGRAM|SOCK_CLOEXEC, 0, worker_watch) < 0) {
                r = log_error_errno(errno, "error creating socketpair");
                goto exit;
        }
        fd_worker = worker_watch[READ_END];

        r = setsockopt(fd_worker, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one));
        if (r < 0)
                return log_error_errno(errno, "could not enable SO_PASSCRED: %m");

        ep_ctrl.data.fd = fd_ctrl;
        ep_inotify.data.fd = fd_inotify;
        ep_signal.data.fd = fd_signal;
        ep_netlink.data.fd = fd_netlink;
        ep_worker.data.fd = fd_worker;

        fd_ep = epoll_create1(EPOLL_CLOEXEC);
        if (fd_ep < 0) {
                log_error_errno(errno, "error creating epoll fd: %m");
                goto exit;
        }
        if (epoll_ctl(fd_ep, EPOLL_CTL_ADD, fd_ctrl, &ep_ctrl) < 0 ||
            epoll_ctl(fd_ep, EPOLL_CTL_ADD, fd_inotify, &ep_inotify) < 0 ||
            epoll_ctl(fd_ep, EPOLL_CTL_ADD, fd_signal, &ep_signal) < 0 ||
            epoll_ctl(fd_ep, EPOLL_CTL_ADD, fd_netlink, &ep_netlink) < 0 ||
            epoll_ctl(fd_ep, EPOLL_CTL_ADD, fd_worker, &ep_worker) < 0) {
                log_error_errno(errno, "fail to add fds to epoll: %m");
                goto exit;
        }

        if (fd_ready != -1) {
                size_t to_write = sizeof(udevd_ready_string) - 1;
                char *wptr = udevd_ready_string;
                do {
                        int r = write(fd_ready, wptr, to_write);
                        if (r < 0) {
                                if (errno == EINTR)
                                        continue;
                                log_error_errno(errno, "failed to write to readiness fd: %m");
                                break;
                        }
                        to_write -= r;
                        wptr += r;
                } while (to_write > 0);
                close(fd_ready);
        }

        for (;;) {
                static usec_t last_usec;
                struct epoll_event ev[8];
                int fdcount;
                int timeout, worker_timeout;
                bool is_worker, is_signal, is_inotify, is_netlink, is_ctrl;
                /* the timeout of the main loop is the next deadline of a worker, see below */
                bool worker_wakeup = false;
                int i;

                if (udev_exit) {
                        /* close sources of new events and discard buffered events */
                        if (fd_ctrl >= 0) {
                                epoll_ctl(fd_ep, EPOLL_CTL_DEL, fd_ctrl, NULL);
                                fd_ctrl = -1;
                        }
                        if (monitor != NULL) {
                                epoll_ctl(fd_ep, EPOLL_CTL_DEL, fd_netlink, NULL);
                                udev_monitor_unref(monitor);
                                monitor = NULL;
                        }
                        if (fd_inotify >= 0) {
                                epoll_ctl(fd_ep, EPOLL_CTL_DEL, fd_inotify, NULL);
                                close(fd_inotify);
                                fd_inotify = -1;
                        }

                        /* discard queued and locked events and kill workers */
                        event_queue_cleanup(udev, EVENT_QUEUED);
                        event_queue_cleanup(udev, EVENT_LOCKED);
                        worker_kill(true);

                        /* exit after all has cleaned up */
                        if (udev_list_node_is_empty(&event_list) && hashmap_isempty(workers))
                                break;

                        /* timeout at exit for workers to finish */
                        timeout = 30 * MSEC_PER_SEC;
                } else if (udev_list_node_is_empty(&event_list) && hashmap_isempty(workers)) {
                        /* we are idle */
                        timeout = -1;
                } else {
                        int requeue_timeout;

                        /* kill idle workers */
                        timeout = 3 * MSEC_PER_SEC;

                        /* requeue the events of locked block devices after a delay */
                        requeue_timeout = locked_events_timeout();
                        if (requeue_timeout >= 0 && requeue_timeout < timeout)
                                timeout = requeue_timeout;
                }

                /* Like systemd, which starts the queued events after every event source it dispatched, start
                 * them right away when processing was started again, and not only at the next wakeup of the
                 * main loop, which may be up to 3 seconds away. */
                if (start_exec_queue) {
                        start_exec_queue = false;
                        if (!udev_exit && !udev_list_node_is_empty(&event_list))
                                timeout = 0;
                }

                if (!udev_exit) {
                        int synthesized_timeout;

                        /* stop waiting for the change events udevd triggered, after a minute without them */
                        synthesized_timeout = synthesized_events_timeout();
                        if (synthesized_timeout == 0)
                                synthesized_events_clear();
                        else if (synthesized_timeout > 0 && (timeout < 0 || synthesized_timeout < timeout))
                                timeout = synthesized_timeout;
                }

                /* warn about and kill hanging workers, and wake up when that is due next */
                worker_timeout = manager_check_worker_timeouts();
                if (worker_timeout >= 0 && (timeout < 0 || worker_timeout < timeout)) {
                        timeout = worker_timeout;
                        worker_wakeup = true;
                }

                /* tell settle that we are busy or idle */
                event_queue_update();

                fdcount = epoll_wait(fd_ep, ev, ELEMENTSOF(ev), timeout);
                if (fdcount < 0)
                        continue;

                /* timeout, unless only a deadline of a worker is due, which manager_check_worker_timeouts()
                 * handles in the next iteration */
                if (fdcount == 0 && !worker_wakeup) {
                        if (udev_exit) {
                                log_error("timeout, giving up waiting for workers to finish");
                                break;
                        }

                        /* kill idle workers */
                        if (udev_list_node_is_empty(&event_list)) {
                                log_debug("cleanup idle workers");
                                worker_kill(false);
                        }
                }

                is_worker = is_signal = is_inotify = is_netlink = is_ctrl = false;
                for (i = 0; i < fdcount; i++) {
                        if (ev[i].data.fd == fd_worker && ev[i].events & EPOLLIN)
                                is_worker = true;
                        else if (ev[i].data.fd == fd_netlink && ev[i].events & EPOLLIN)
                                is_netlink = true;
                        else if (ev[i].data.fd == fd_signal && ev[i].events & EPOLLIN)
                                is_signal = true;
                        else if (ev[i].data.fd == fd_inotify && ev[i].events & EPOLLIN)
                                is_inotify = true;
                        else if (ev[i].data.fd == fd_ctrl && ev[i].events & EPOLLIN)
                                is_ctrl = true;
                }

                /* check for changed config, every 3 seconds at most */
                if ((now(CLOCK_MONOTONIC) - last_usec) > 3 * USEC_PER_SEC) {
                        if (udev_rules_check_timestamp(rules))
                                reload = true;
                        if (udev_builtin_validate(udev))
                                reload = true;

                        last_usec = now(CLOCK_MONOTONIC);
                }

                /* reload requested, HUP signal received, rules changed, builtin changed */
                if (reload) {
                        worker_kill(false);
                        rules = udev_rules_unref(rules);
                        udev_builtin_exit(udev);
                        reload = false;
                }

                /* event has finished */
                if (is_worker)
                        worker_returned(fd_worker);

                if (is_netlink) {
                        struct udev_device *dev;

                        dev = udev_monitor_receive_device(monitor);
                        if (dev) {
                                synthesized_event_received(dev);
                                udev_device_ensure_usec_initialized(dev, NULL);
                                if (event_queue_insert(dev) < 0)
                                        udev_device_unref(dev);
                                else
                                        manager_requeue_locked_events_by_device(dev);
                        }
                }

                /* requeue the events of locked block devices, whose delay passed */
                if (!udev_exit)
                        manager_requeue_locked_events();

                /* start new events */
                if (!udev_list_node_is_empty(&event_list) && !udev_exit && !stop_exec_queue) {
                        udev_builtin_init(udev);
                        if (rules == NULL)
                                rules = udev_rules_new(udev, arg_resolve_names);
                        if (rules != NULL)
                                event_queue_start(udev);
                }

                if (is_signal) {
                        struct signalfd_siginfo fdsi;
                        ssize_t size;

                        size = read(fd_signal, &fdsi, sizeof(struct signalfd_siginfo));
                        if (size == sizeof(struct signalfd_siginfo))
                                handle_signal(udev, fdsi.ssi_signo);
                }

                /* we are shutting down, the events below are not handled anymore */
                if (udev_exit)
                        continue;

                /* device node watch */
                if (is_inotify) {
                        handle_inotify(udev);

                        /*
                         * settle might be waiting on us to determine the queue
                         * state. If we just handled an inotify event, we might have
                         * generated a "change" event, but we won't have queued up
                         * the resultant uevent yet.
                         *
                         * Before we go ahead and potentially tell settle that the
                         * queue is empty, lets loop one more time to update the
                         * queue state again before deciding.
                         */
                        continue;
                }

                /*
                 * This needs to be after the inotify handling, to make sure,
                 * that the ping is send back after the possibly generated
                 * "change" events by the inotify device node watch.
                 */
                if (is_ctrl)
                        handle_ctrl_msg(udev_ctrl);
        }

exit:
        udev_ctrl_cleanup(udev_ctrl);
        unlink(UDEV_ROOT_RUN "/udev/queue");

        if (fd_ep >= 0)
                close(fd_ep);
        workers_free();
        set_free(synthesize_change_children);
        set_free_free(synthesized_events);
        event_queue_cleanup(udev, EVENT_UNDEF);
        udev_rules_unref(rules);
        udev_builtin_exit(udev);
        if (fd_signal >= 0)
                close(fd_signal);
        if (worker_watch[READ_END] >= 0)
                close(worker_watch[READ_END]);
        if (worker_watch[WRITE_END] >= 0)
                close(worker_watch[WRITE_END]);
        udev_monitor_unref(monitor);
        udev_ctrl_connection_unref(udev_ctrl_conn);
        udev_ctrl_unref(udev_ctrl);
        mac_selinux_finish();
        udev_unref(udev);
        log_close();
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
