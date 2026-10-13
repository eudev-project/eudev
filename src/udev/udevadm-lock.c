/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include "blockdev-util.h"
#include "fileio.h"
#include "pager.h"
#include "path-util.h"
#include "process-util.h"
#include "strv.h"
#include "udev.h"
#include "udev-util.h"
#include "udevadm-util.h"

static usec_t arg_timeout_usec = USEC_INFINITY;
static char **arg_devices = NULL;
static char **arg_backing = NULL;
static char **arg_cmdline = NULL;
static bool arg_print = false;

static void help(void) {
        pager_open(0);

        printf("%s lock [OPTIONS...] COMMAND\n"
               "%s lock [OPTIONS...] --print\n"
               "\n%sLock a block device and run a command.%s\n\n"
               "  -h --help            Print this message\n"
               "  -V --version         Print version of the program\n"
               "  -d --device=DEVICE   Block device to lock\n"
               "  -b --backing=FILE    File whose backing block device to lock\n"
               "  -t --timeout=SECS    Block at most the specified time waiting for lock\n"
               "  -p --print           Only show which block device the lock would be taken on\n",
               program_invocation_short_name,
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal());
        print_man_page_link();
}

static int parse_argv(int argc, char *argv[]) {
        _cleanup_free_ char *lesc1 = NULL;

        static const struct option options[] = {
                { "help",    no_argument,       NULL, 'h'      },
                { "version", no_argument,       NULL, 'V'      },
                { "device",  required_argument, NULL, 'd'      },
                { "backing", required_argument, NULL, 'b'      },
                { "timeout", required_argument, NULL, 't'      },
                { "print",   no_argument,       NULL, 'p'      },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        /* Resetting to 0 forces the invocation of an internal initialization routine of getopt_long()
         * that checks for GNU extensions in optstring ('-' or '+' at the beginning). */
        optind = 0;
        while ((c = getopt_long_log(argc, argv, arg_print ? "hVd:b:t:p" : "+hVd:b:t:p", options)) >= 0)

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case 'V':
                        printf("%s\n", UDEV_VERSION);
                        return 0;

                case 'd':
                case 'b': {
                        char ***l = c == 'd' ? &arg_devices : &arg_backing;
                        char *s;

                        s = path_make_absolute_cwd(optarg);
                        if (!s)
                                return log_error_errno(ENOMEM, "Failed to make path '%s' absolute: %m",
                                                       utf8_escape_for_log(optarg, &lesc1));

                        path_kill_slashes(s);

                        if (strv_consume(l, s) < 0)
                                return log_oom();

                        strv_uniq(*l);
                        break;
                }

                case 't':
                        r = parse_sec(optarg, &arg_timeout_usec);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --timeout= parameter: %s",
                                                       utf8_escape_for_log(optarg, &lesc1));
                        break;

                case 'p':
                        arg_print = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unknown option");
                }

        if (arg_print) {
                if (optind != argc) {
                        log_error("No arguments expected.");
                        return -EINVAL;
                }
        } else {
                if (optind + 1 > argc) {
                        log_error("Too few arguments, command to execute.");
                        return -EINVAL;
                }

                arg_cmdline = strv_copy(argv + optind);
                if (!arg_cmdline)
                        return log_oom();
        }

        if (strv_isempty(arg_devices) && strv_isempty(arg_backing)) {
                log_error("No devices to lock specified, refusing.");
                return -EINVAL;
        }

        return 1;
}

static int fd_get_devnum(int fd, bool backing, dev_t *ret) {
        struct stat st;
        dev_t devnum = 0;
        int r;

        if (fstat(fd, &st) < 0)
                return -errno;

        if (S_ISBLK(st.st_mode))
                devnum = st.st_rdev;
        else if (!backing)
                return -ENOTBLK;
        else if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode))
                return -ENOTBLK;
        else if (major(st.st_dev) != 0)
                devnum = st.st_dev;
        else {
                _cleanup_close_ int real_fd = -1;

                /* If major(st.st_dev) is zero, this might mean we are backed by btrfs, which needs special
                 * handing, to get the backing device node. */

                /* fd is an O_PATH fd, on which the ioctls of btrfs_get_block_device_fd() fail with EBADF:
                 * open the file or directory again, like btrfs_get_block_device_at() of systemd does with
                 * fd_reopen(). */
                real_fd = open(FORMAT_PROC_FD_PATH(fd), O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
                if (real_fd < 0)
                        return -errno;

                r = btrfs_get_block_device_fd(real_fd, &devnum);
                if (r == -ENOTTY) /* not btrfs */
                        return -ENOTBLK;
                if (r < 0)
                        return r;
        }

        *ret = devnum;
        return 0;
}

static int path_get_whole_disk(const char *path, bool backing, dev_t *ret) {
        _cleanup_close_ int fd = -1;
        dev_t devt = 0;
        int r;

        fd = open(path, O_CLOEXEC|O_PATH);
        if (fd < 0)
                return -errno;

        r = fd_get_devnum(fd, backing, &devt);
        if (r < 0)
                return r;

        return block_get_whole_disk(devt, ret);
}

static int devt_compare_func(const void *a, const void *b) {
        const dev_t *x = a, *y = b;

        if (major(*x) != major(*y))
                return major(*x) < major(*y) ? -1 : 1;
        if (minor(*x) != minor(*y))
                return minor(*x) < minor(*y) ? -1 : 1;
        return 0;
}

static int find_devno(
                dev_t **devnos,
                size_t *n_devnos,
                const char *device,
                bool backing) {
        _cleanup_free_ char *lesc1 = NULL;

        dev_t devt = 0, *p;
        int r;

        r = path_get_whole_disk(device, backing, &devt);
        if (r < 0)
                return log_error_errno(r, "Failed to find whole block device for '%s': %m",
                                       utf8_escape_for_log(device, &lesc1));

        if (*n_devnos > 0 && bsearch(&devt, *devnos, *n_devnos, sizeof(dev_t), devt_compare_func)) {
                log_debug("Device %u:%u already listed for locking, ignoring.", major(devt), minor(devt));
                return 0;
        }

        p = realloc(*devnos, (*n_devnos + 1) * sizeof(dev_t));
        if (!p)
                return log_oom();
        *devnos = p;

        (*devnos)[(*n_devnos)++] = devt;

        /* Immediately sort again, to ensure the binary search above will work for the next device we add */
        qsort(*devnos, *n_devnos, sizeof(dev_t), devt_compare_func);
        return 1;
}

static void sigalrm_handler(int sig __attribute__((unused))) {
}

/* Like lock_generic_with_timeout() of systemd, but with an interval timer instead of a child
 * process: flock() is interrupted by SIGALRM when the timeout is hit. The timer fires again
 * every 10ms after that, so that flock() is interrupted even if the first signal comes before
 * flock() is entered. */
static int flock_with_timeout(int fd, usec_t timeout) {
        struct sigaction sa = {
                .sa_handler = sigalrm_handler,
        }, old_sa;
        struct itimerval it = {
                .it_value.tv_sec = timeout / USEC_PER_SEC,
                .it_value.tv_usec = timeout % USEC_PER_SEC,
                .it_interval.tv_usec = 10 * USEC_PER_MSEC,
        }, off = {};
        usec_t deadline;
        int r = 0;

        if (timeout == 0)
                return -ETIMEDOUT;

        /* More than 68 years do not fit into the timer everywhere, wait without a timeout. */
        if (timeout / USEC_PER_SEC > INT32_MAX)
                return flock(fd, LOCK_EX) < 0 ? -errno : 0;

        deadline = now(CLOCK_MONOTONIC) + timeout;

        /* no SA_RESTART, so that flock() fails with EINTR */
        if (sigaction(SIGALRM, &sa, &old_sa) < 0)
                return -errno;

        if (setitimer(ITIMER_REAL, &it, NULL) < 0)
                r = -errno;
        else
                for (;;) {
                        if (flock(fd, LOCK_EX) >= 0)
                                break;
                        if (errno != EINTR) {
                                r = -errno;
                                break;
                        }
                        if (now(CLOCK_MONOTONIC) >= deadline) {
                                r = -ETIMEDOUT;
                                break;
                        }
                }

        (void) setitimer(ITIMER_REAL, &off, NULL);
        (void) sigaction(SIGALRM, &old_sa, NULL);
        return r;
}

static int lock_device(
                const char *path,
                dev_t devno,
                usec_t deadline) {
        _cleanup_free_ char *lesc1 = NULL;

        _cleanup_close_ int fd = -1;
        struct stat st;
        int r;

        /* We open in O_WRONLY mode here, to trigger a rescan in udev once we are done */
        fd = open(path, O_WRONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open '%s': %m", utf8_escape_for_log(path, &lesc1));

        if (fstat(fd, &st) < 0)
                return log_error_errno(errno, "Failed to stat '%s': %m", utf8_escape_for_log(path, &lesc1));

        /* Extra safety: check that the device still refers to what we think it refers to */
        if (!S_ISBLK(st.st_mode) || st.st_rdev != devno)
                return log_error_errno(ENXIO, "Path '%s' no longer refers to specified block device %u:%u.",
                                       utf8_escape_for_log(path, &lesc1), major(devno), minor(devno));

        if (flock(fd, LOCK_EX|LOCK_NB) < 0) {
                if (errno != EAGAIN)
                        return log_error_errno(errno, "Failed to lock device '%s': %m",
                                               utf8_escape_for_log(path, &lesc1));

                if (deadline == 0)
                        return log_error_errno(EBUSY, "Device '%s' is currently locked.",
                                               utf8_escape_for_log(path, &lesc1));

                if (deadline == USEC_INFINITY)  {
                        log_info("Device '%s' is currently locked, waiting%s",
                                 utf8_escape_for_log(path, &lesc1), glyph(GLYPH_ELLIPSIS));

                        r = flock(fd, LOCK_EX) < 0 ? -errno : 0;
                } else {
                        char buf[FORMAT_TIMESPAN_MAX];
                        usec_t n = now(CLOCK_MONOTONIC);
                        usec_t left = deadline > n ? deadline - n : 0;

                        log_info("Device '%s' is currently locked, waiting %s%s",
                                 utf8_escape_for_log(path, &lesc1), format_timespan(buf, sizeof(buf), left, 0),
                                 glyph(GLYPH_ELLIPSIS));

                        r = flock_with_timeout(fd, left);
                        if (r == -ETIMEDOUT)
                                return log_error_errno(r, "Timeout reached.");
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to lock device '%s': %m", utf8_escape_for_log(path, &lesc1));
        }

        log_debug("Successfully locked %s (%u:%u)%s",
                  utf8_escape_for_log(path, &lesc1), major(devno), minor(devno), glyph(GLYPH_ELLIPSIS));

        r = fd;
        fd = -1;
        return r;
}

static int devname_from_devnum(struct udev *udev, dev_t devnum, char **ret) {
        _cleanup_udev_device_unref_ struct udev_device *dev = NULL;
        const char *devname;
        char *s;

        dev = udev_device_new_from_devnum(udev, 'b', devnum);
        if (!dev)
                return errno > 0 ? -errno : -ENODEV;

        devname = udev_device_get_devnode(dev);
        if (!devname)
                return -ENOENT;

        s = strdup(devname);
        if (!s)
                return -ENOMEM;

        *ret = s;
        return 0;
}

static int run_command(void) {
        _cleanup_free_ char *lesc1 = NULL;
        struct sigaction sa = {
                .sa_handler = SIG_IGN,
        };
        pid_t parent = getpid(), pid;
        int status, r;

        /* Ignore SIGINT and allow the forked process to receive it */
        (void) sigaction(SIGINT, &sa, NULL);

        pid = fork();
        if (pid < 0)
                return log_error_errno(errno, "Failed to fork off (lock): %m");
        if (pid == 0) {
                /* Child */

                (void) reset_all_signal_handlers();
                (void) reset_signal_mask();

                if (prctl(PR_SET_PDEATHSIG, SIGTERM) < 0 || getppid() != parent)
                        _exit(EXIT_FAILURE);

                /* Like FORK_CLOSE_ALL_FDS of systemd: close the log first, as its descriptors are closed
                 * too, and, like systemd, open it again only when the command cannot be run. */
                log_close();
                close_all_fds();

                /* like FORK_RLIMIT_NOFILE_SAFE of systemd */
                r = rlimit_nofile_safe();
                if (r < 0) {
                        log_open();
                        log_error_errno(r, "Failed to lower RLIMIT_NOFILE's soft limit to 1K: %m");
                        _exit(EXIT_FAILURE);
                }

                execvp(arg_cmdline[0], arg_cmdline);
                log_open();
                log_error_errno(errno, "Failed to execute %s: %m", utf8_escape_for_log(arg_cmdline[0], &lesc1));
                _exit(EXIT_FAILURE);
        }

        for (;;) {
                if (waitpid(pid, &status, 0) >= 0)
                        break;
                if (errno != EINTR)
                        return log_error_errno(errno, "Failed to wait for %s: %m",
                                               utf8_escape_for_log(arg_cmdline[0], &lesc1));
        }

        if (WIFEXITED(status))
                return WEXITSTATUS(status);

        log_debug("%s terminated by signal %s.", utf8_escape_for_log(arg_cmdline[0], &lesc1),
                  WIFSIGNALED(status) ? strsignal(WTERMSIG(status)) : "unknown");
        return -EPROTO;
}

static int lock_main(struct udev *udev) {
        _cleanup_free_ dev_t *devnos = NULL;
        size_t n_devnos = 0, i;
        int *fds = NULL;
        usec_t deadline;
        char **d;
        int r;

        STRV_FOREACH(d, arg_devices) {
                r = find_devno(&devnos, &n_devnos, *d, /* backing= */ false);
                if (r < 0)
                        return r;
        }

        STRV_FOREACH(d, arg_backing) {
                r = find_devno(&devnos, &n_devnos, *d, /* backing= */ true);
                if (r < 0)
                        return r;
        }

        assert(n_devnos > 0);

        fds = new(int, n_devnos);
        if (!fds)
                return log_oom();
        for (i = 0; i < n_devnos; i++)
                fds[i] = -1;

        if (arg_timeout_usec == 0 || arg_timeout_usec == USEC_INFINITY)
                deadline = arg_timeout_usec;
        else
                deadline = usec_add(now(CLOCK_MONOTONIC), arg_timeout_usec);

        for (i = 0; i < n_devnos; i++) {
                _cleanup_free_ char *node = NULL;

                r = devname_from_devnum(udev, devnos[i], &node);
                if (r < 0) {
                        log_error_errno(r, "Failed to format block device path: %m");
                        goto finish;
                }

                if (arg_print)
                        printf("%s\n", node);
                else {
                        fds[i] = lock_device(node, devnos[i], deadline);
                        if (fds[i] < 0) {
                                r = fds[i];
                                goto finish;
                        }
                }
        }

        if (arg_print)
                r = EXIT_SUCCESS;
        else
                r = run_command();

finish:
        for (i = 0; i < n_devnos; i++)
                safe_close(fds[i]);
        free(fds);
        return r;
}

static int adm_lock(struct udev *udev, int argc, char *argv[]) {
        int r;

        r = parse_argv(argc, argv);
        if (r > 0) {
                log_command_call(&udevadm_lock);
                r = lock_main(udev);
        }

        arg_devices = strv_free(arg_devices);
        arg_backing = strv_free(arg_backing);
        arg_cmdline = strv_free(arg_cmdline);

        return r < 0 ? EXIT_FAILURE : r;
}

const struct udevadm_cmd udevadm_lock = {
        .name = "lock",
        .cmd = adm_lock,
        .help = "Lock a block device",
};
