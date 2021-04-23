/*
 * Copyright (C) 2003-2013 Kay Sievers <kay@vrfy.org>
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

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/signalfd.h>
#include <linux/sockios.h>
#include <sys/sysmacros.h>

#include "udev.h"

struct udev_event *udev_event_new(struct udev_device *dev) {
        struct udev *udev = udev_device_get_udev(dev);
        struct udev_event *event;

        event = new0(struct udev_event, 1);
        if (event == NULL)
                return NULL;
        event->dev = dev;
        event->udev = udev;
        udev_list_init(udev, &event->run_list, false);
        udev_list_init(udev, &event->seclabel_list, false);
        event->fd_signal = -1;
        event->birth_usec = now(CLOCK_MONOTONIC);
        return event;
}

void udev_event_unref(struct udev_event *event) {
        if (event == NULL)
                return;
        udev_list_cleanup(&event->run_list);
        udev_list_cleanup(&event->seclabel_list);
        free(event->program_result);
        free(event->name);
        free(event);
}

size_t udev_event_apply_format(struct udev_event *event,
                               const char *src, char *dest, size_t size,
                               bool replace_whitespace) {
        struct udev_device *dev = event->dev;
        enum subst_type {
                SUBST_UNKNOWN,
                SUBST_DEVNODE,
                SUBST_ATTR,
                SUBST_ENV,
                SUBST_KERNEL,
                SUBST_KERNEL_NUMBER,
                SUBST_DRIVER,
                SUBST_DEVPATH,
                SUBST_ID,
                SUBST_MAJOR,
                SUBST_MINOR,
                SUBST_RESULT,
                SUBST_PARENT,
                SUBST_NAME,
                SUBST_LINKS,
                SUBST_ROOT,
                SUBST_SYS,
        };
        static const struct subst_map {
                const char *name;
                const char fmt;
                enum subst_type type;
        } map[] = {
                { .name = "devnode",  .fmt = 'N', .type = SUBST_DEVNODE },
                { .name = "tempnode", .fmt = 'N', .type = SUBST_DEVNODE },
                { .name = "attr",     .fmt = 's', .type = SUBST_ATTR },
                { .name = "sysfs",    .fmt = 's', .type = SUBST_ATTR },
                { .name = "env",      .fmt = 'E', .type = SUBST_ENV },
                { .name = "kernel",   .fmt = 'k', .type = SUBST_KERNEL },
                { .name = "number",   .fmt = 'n', .type = SUBST_KERNEL_NUMBER },
                { .name = "driver",   .fmt = 'd', .type = SUBST_DRIVER },
                { .name = "devpath",  .fmt = 'p', .type = SUBST_DEVPATH },
                { .name = "id",       .fmt = 'b', .type = SUBST_ID },
                { .name = "major",    .fmt = 'M', .type = SUBST_MAJOR },
                { .name = "minor",    .fmt = 'm', .type = SUBST_MINOR },
                { .name = "result",   .fmt = 'c', .type = SUBST_RESULT },
                { .name = "parent",   .fmt = 'P', .type = SUBST_PARENT },
                { .name = "name",     .fmt = 'D', .type = SUBST_NAME },
                { .name = "links",    .fmt = 'L', .type = SUBST_LINKS },
                { .name = "root",     .fmt = 'r', .type = SUBST_ROOT },
                { .name = "sys",      .fmt = 'S', .type = SUBST_SYS },
        };
        const char *from;
        char *s;
        size_t l;

        from = src;
        s = dest;
        l = size;

        for (;;) {
                enum subst_type type = SUBST_UNKNOWN;
                char attrbuf[UTIL_PATH_SIZE], sbuf[UTIL_PATH_SIZE];
                char *attr = NULL, *_s;
                size_t _l;
                bool replws = replace_whitespace;

                while (from[0] != '\0') {
                        if (from[0] == '$') {
                                /* substitute named variable */
                                unsigned int i;

                                if (from[1] == '$') {
                                        from++;
                                        goto copy;
                                }

                                for (i = 0; i < ELEMENTSOF(map); i++) {
                                        if (startswith(&from[1], map[i].name)) {
                                                type = map[i].type;
                                                from += strlen(map[i].name)+1;
                                                goto subst;
                                        }
                                }
                        } else if (from[0] == '%') {
                                /* substitute format char */
                                unsigned int i;

                                if (from[1] == '%') {
                                        from++;
                                        goto copy;
                                }

                                for (i = 0; i < ELEMENTSOF(map); i++) {
                                        if (from[1] == map[i].fmt) {
                                                type = map[i].type;
                                                from += 2;
                                                goto subst;
                                        }
                                }
                        }
copy:
                        /* copy char */
                        if (l == 0)
                                goto out;
                        s[0] = from[0];
                        from++;
                        s++;
                        l--;
                }

                goto out;
subst:
                /* extract possible $format{attr} */
                if (from[0] == '{') {
                        unsigned int i;

                        from++;
                        for (i = 0; from[i] != '}'; i++) {
                                if (from[i] == '\0') {
                                        log_error("missing closing brace for format '%s'", src);
                                        goto out;
                                }
                        }
                        if (i >= sizeof(attrbuf))
                                goto out;
                        memcpy(attrbuf, from, i);
                        attrbuf[i] = '\0';
                        from += i+1;
                        attr = attrbuf;
                } else {
                        attr = NULL;
                }

                /* result subst handles space as field separator */
                if (type == SUBST_RESULT)
                        replws = false;

                if (replws) {
                        /* store dest string ptr and remaining len */
                        _s = s;
                        _l = l;
                        /* temporarily use sbuf */
                        s = sbuf;
                        l = UTIL_PATH_SIZE;
                }

                switch (type) {
                case SUBST_DEVPATH:
                        l = strpcpy(&s, l, udev_device_get_devpath(dev));
                        break;
                case SUBST_KERNEL:
                        l = strpcpy(&s, l, udev_device_get_sysname(dev));
                        break;
                case SUBST_KERNEL_NUMBER:
                        if (udev_device_get_sysnum(dev) == NULL)
                                break;
                        l = strpcpy(&s, l, udev_device_get_sysnum(dev));
                        break;
                case SUBST_ID:
                        if (event->dev_parent == NULL)
                                break;
                        l = strpcpy(&s, l, udev_device_get_sysname(event->dev_parent));
                        break;
                case SUBST_DRIVER: {
                        const char *driver;

                        if (event->dev_parent == NULL)
                                break;

                        driver = udev_device_get_driver(event->dev_parent);
                        if (driver == NULL)
                                break;
                        l = strpcpy(&s, l, driver);
                        break;
                }
                case SUBST_MAJOR: {
                        char num[UTIL_PATH_SIZE];

                        sprintf(num, "%u", major(udev_device_get_devnum(dev)));
                        l = strpcpy(&s, l, num);
                        break;
                }
                case SUBST_MINOR: {
                        char num[UTIL_PATH_SIZE];

                        sprintf(num, "%u", minor(udev_device_get_devnum(dev)));
                        l = strpcpy(&s, l, num);
                        break;
                }
                case SUBST_RESULT: {
                        char *rest;
                        int i;

                        if (event->program_result == NULL)
                                break;
                        /* get part part of the result string */
                        i = 0;
                        if (attr != NULL)
                                i = strtoul(attr, &rest, 10);
                        if (i > 0) {
                                char result[UTIL_PATH_SIZE];
                                char tmp[UTIL_PATH_SIZE];
                                char *cpos;

                                strscpy(result, sizeof(result), event->program_result);
                                cpos = result;
                                while (--i) {
                                        while (cpos[0] != '\0' && !isspace(cpos[0]))
                                                cpos++;
                                        while (isspace(cpos[0]))
                                                cpos++;
                                        if (cpos[0] == '\0')
                                                break;
                                }
                                if (i > 0) {
                                        log_error("requested part of result string not found");
                                        break;
                                }
                                strscpy(tmp, sizeof(tmp), cpos);
                                /* %{2+}c copies the whole string from the second part on */
                                if (rest[0] != '+') {
                                        cpos = strchr(tmp, ' ');
                                        if (cpos)
                                                cpos[0] = '\0';
                                }
                                l = strpcpy(&s, l, tmp);
                        } else {
                                l = strpcpy(&s, l, event->program_result);
                        }
                        break;
                }
                case SUBST_ATTR: {
                        const char *value = NULL;
                        char vbuf[UTIL_NAME_SIZE];
                        size_t len;
                        int count;

                        if (attr == NULL) {
                                log_error("missing file parameter for attr");
                                break;
                        }

                        /* try to read the value specified by "[dmi/id]product_name" */
                        if (util_resolve_subsys_kernel(event->udev, attr, vbuf, sizeof(vbuf), 1) == 0)
                                value = vbuf;

                        /* try to read the attribute the device */
                        if (value == NULL)
                                value = udev_device_get_sysattr_value(event->dev, attr);

                        /* try to read the attribute of the parent device, other matches have selected */
                        if (value == NULL && event->dev_parent != NULL && event->dev_parent != event->dev)
                                value = udev_device_get_sysattr_value(event->dev_parent, attr);

                        if (value == NULL)
                                break;

                        /* strip trailing whitespace, and replace unwanted characters */
                        if (value != vbuf)
                                strscpy(vbuf, sizeof(vbuf), value);
                        len = strlen(vbuf);
                        while (len > 0 && isspace(vbuf[--len]))
                                vbuf[len] = '\0';
                        count = util_replace_chars(vbuf, UDEV_ALLOWED_CHARS_INPUT);
                        if (count > 0)
                                log_debug("%i character(s) replaced" , count);
                        l = strpcpy(&s, l, vbuf);
                        break;
                }
                case SUBST_PARENT: {
                        struct udev_device *dev_parent;
                        const char *devnode;

                        dev_parent = udev_device_get_parent(event->dev);
                        if (dev_parent == NULL)
                                break;
                        devnode = udev_device_get_devnode(dev_parent);
                        if (devnode != NULL)
                                l = strpcpy(&s, l, devnode + strlen("/dev/"));
                        break;
                }
                case SUBST_DEVNODE:
                        if (udev_device_get_devnode(dev) != NULL)
                                l = strpcpy(&s, l, udev_device_get_devnode(dev));
                        break;
                case SUBST_NAME:
                        if (event->name != NULL)
                                l = strpcpy(&s, l, event->name);
                        else if (udev_device_get_devnode(dev) != NULL)
                                l = strpcpy(&s, l, udev_device_get_devnode(dev) + strlen("/dev/"));
                        else
                                l = strpcpy(&s, l, udev_device_get_sysname(dev));
                        break;
                case SUBST_LINKS: {
                        struct udev_list_entry *list_entry;

                        list_entry = udev_device_get_devlinks_list_entry(dev);
                        if (list_entry == NULL)
                                break;
                        l = strpcpy(&s, l, udev_list_entry_get_name(list_entry) + strlen("/dev/"));
                        udev_list_entry_foreach(list_entry, udev_list_entry_get_next(list_entry))
                                l = strpcpyl(&s, l, " ", udev_list_entry_get_name(list_entry) + strlen("/dev/"), NULL);
                        break;
                }
                case SUBST_ROOT:
                        l = strpcpy(&s, l, "/dev");
                        break;
                case SUBST_SYS:
                        l = strpcpy(&s, l, "/sys");
                        break;
                case SUBST_ENV:
                        if (attr == NULL) {
                                break;
                        } else {
                                const char *value;

                                value = udev_device_get_property_value(event->dev, attr);
                                if (value == NULL)
                                        break;
                                l = strpcpy(&s, l, value);
                                break;
                        }
                default:
                        log_error("unknown substitution type=%i", type);
                        break;
                }

                /* replace whitespace in sbuf and copy to dest */
                if (replws) {
                        size_t tmplen = UTIL_PATH_SIZE - l;

                        /* restore s and l to dest string values */
                        s = _s;
                        l = _l;

                        /* copy ws-replaced value to s */
                        tmplen = util_replace_whitespace(sbuf, s, MIN(tmplen, l));
                        l -= tmplen;
                        s += tmplen;
                }
        }

out:
        s[0] = '\0';
        return l;
}

static int spawn_exec(struct udev_event *event,
                      const char *cmd, char *const argv[], char **envp, const sigset_t *sigmask,
                      int fd_stdout, int fd_stderr) {
        _cleanup_close_ int fd = -1;

        /* discard child output or connect to pipe */
        fd = open("/dev/null", O_RDWR);
        if (fd >= 0) {
                dup2(fd, STDIN_FILENO);
                if (fd_stdout < 0)
                        dup2(fd, STDOUT_FILENO);
                if (fd_stderr < 0)
                        dup2(fd, STDERR_FILENO);
        } else
                log_error_errno(errno, "open /dev/null failed: %m");

        /* connect pipes to std{out,err} */
        if (fd_stdout >= 0) {
                dup2(fd_stdout, STDOUT_FILENO);
                safe_close(fd_stdout);
        }
        if (fd_stderr >= 0) {
                dup2(fd_stderr, STDERR_FILENO);
                safe_close(fd_stderr);
        }

        /* terminate child in case parent goes away */
        prctl(PR_SET_PDEATHSIG, SIGTERM);

        /* restore original udev sigmask before exec */
        if (sigmask)
                sigprocmask(SIG_SETMASK, sigmask, NULL);

        execve(argv[0], argv, envp);

        /* exec failed */
        log_error_errno(errno, "failed to execute '%s' '%s': %m", argv[0], cmd);

        return -errno;
}

static void spawn_read(struct udev_event *event,
                       usec_t timeout_usec,
                       const char *cmd,
                       int fd_stdout, int fd_stderr,
                       char *result, size_t ressize) {
        _cleanup_close_ int fd_ep = -1;
        struct epoll_event ep_outpipe = {
                .events = EPOLLIN,
                .data.ptr = &fd_stdout,
        };
        struct epoll_event ep_errpipe = {
                .events = EPOLLIN,
                .data.ptr = &fd_stderr,
        };
        size_t respos = 0;
        int r;

        /* read from child if requested */
        if (fd_stdout < 0 && fd_stderr < 0)
                return;

        fd_ep = epoll_create1(EPOLL_CLOEXEC);
        if (fd_ep < 0) {
                log_error_errno(errno, "error creating epoll fd: %m");
                return;
        }

        if (fd_stdout >= 0) {
                r = epoll_ctl(fd_ep, EPOLL_CTL_ADD, fd_stdout, &ep_outpipe);
                if (r < 0) {
                        log_error_errno(errno, "fail to add stdout fd to epoll: %m");
                        return;
                }
        }

        if (fd_stderr >= 0) {
                r = epoll_ctl(fd_ep, EPOLL_CTL_ADD, fd_stderr, &ep_errpipe);
                if (r < 0) {
                        log_error_errno(errno, "fail to add stderr fd to epoll: %m");
                        return;
                }
        }

        /* read child output */
        while (fd_stdout >= 0 || fd_stderr >= 0) {
                int timeout;
                int fdcount;
                struct epoll_event ev[4];
                int i;

                if (timeout_usec > 0) {
                        usec_t age_usec;

                        age_usec = now(CLOCK_MONOTONIC) - event->birth_usec;
                        if (age_usec >= timeout_usec) {
                                log_error("timeout '%s'", cmd);
                                return;
                        }
                        timeout = ((timeout_usec - age_usec) / USEC_PER_MSEC) + MSEC_PER_SEC;
                } else {
                        timeout = -1;
                }

                fdcount = epoll_wait(fd_ep, ev, ELEMENTSOF(ev), timeout);
                if (fdcount < 0) {
                        if (errno == EINTR)
                                continue;
                        log_error_errno(errno, "failed to poll: %m");
                        return;
                } else if (fdcount == 0) {
                        log_error("timeout '%s'", cmd);
                        return;
                }

                for (i = 0; i < fdcount; i++) {
                        int *fd = (int *)ev[i].data.ptr;

                        if (*fd < 0)
                                continue;

                        if (ev[i].events & EPOLLIN) {
                                ssize_t count;
                                char buf[4096];

                                count = read(*fd, buf, sizeof(buf)-1);
                                if (count <= 0)
                                        continue;
                                buf[count] = '\0';

                                /* store stdout result */
                                if (result != NULL && *fd == fd_stdout) {
                                        if (respos + count < ressize) {
                                                memcpy(&result[respos], buf, count);
                                                respos += count;
                                        } else {
                                                log_error("'%s' ressize %zu too short", cmd, ressize);
                                        }
                                }

                                /* log debug output only if we watch stderr */
                                if (fd_stderr >= 0) {
                                        char *pos;
                                        char *line;

                                        pos = buf;
                                        while ((line = strsep(&pos, "\n"))) {
                                                if (pos != NULL || line[0] != '\0')
                                                        log_debug("'%s'(%s) '%s'", cmd, *fd == fd_stdout ? "out" : "err" , line);
                                        }
                                }
                        } else if (ev[i].events & EPOLLHUP) {
                                r = epoll_ctl(fd_ep, EPOLL_CTL_DEL, *fd, NULL);
                                if (r < 0) {
                                        log_error_errno(errno, "failed to remove fd from epoll: %m");
                                        return;
                                }
                                *fd = -1;
                        }
                }
        }

        /* return the child's stdout string */
        if (result != NULL)
                result[respos] = '\0';
}

static int spawn_wait(struct udev_event *event,
                      usec_t timeout_usec,
                      usec_t timeout_warn_usec,
                      const char *cmd, pid_t pid) {
        struct pollfd pfd[1];
        int err = 0;

        pfd[0].events = POLLIN;
        pfd[0].fd = event->fd_signal;

        while (pid > 0) {
                int timeout;
                int timeout_warn = 0;
                int fdcount;

                if (timeout_usec > 0) {
                        usec_t age_usec;

                        age_usec = now(CLOCK_MONOTONIC) - event->birth_usec;
                        if (age_usec >= timeout_usec)
                                timeout = 1000;
                        else {
                                if (timeout_warn_usec > 0)
                                        timeout_warn = ((timeout_warn_usec - age_usec) / USEC_PER_MSEC) + MSEC_PER_SEC;

                                timeout = ((timeout_usec - timeout_warn_usec - age_usec) / USEC_PER_MSEC) + MSEC_PER_SEC;
                        }
                } else {
                        timeout = -1;
                }

                fdcount = poll(pfd, 1, timeout_warn);
                if (fdcount < 0) {
                        if (errno == EINTR)
                                continue;
                        err = -errno;
                        log_error_errno(errno, "failed to poll: %m");
                        goto out;
                }
                if (fdcount == 0) {
                        log_warning("slow: '%s' ["PID_FMT"]", cmd, pid);

                        fdcount = poll(pfd, 1, timeout);
                        if (fdcount < 0) {
                                if (errno == EINTR)
                                        continue;
                                err = -errno;
                                log_error_errno(errno, "failed to poll: %m");
                                goto out;
                        }
                        if (fdcount == 0) {
                                log_error("timeout: killing '%s' ["PID_FMT"]", cmd, pid);
                                kill(pid, SIGKILL);
                        }
                }

                if (pfd[0].revents & POLLIN) {
                        struct signalfd_siginfo fdsi;
                        int status;
                        ssize_t size;

                        size = read(event->fd_signal, &fdsi, sizeof(struct signalfd_siginfo));
                        if (size != sizeof(struct signalfd_siginfo))
                                continue;

                        switch (fdsi.ssi_signo) {
                        case SIGTERM:
                                event->sigterm = true;
                                break;
                        case SIGCHLD:
                                if (waitpid(pid, &status, WNOHANG) < 0)
                                        break;
                                if (WIFEXITED(status)) {
                                        log_debug("'%s' ["PID_FMT"] exit with return code %i", cmd, pid, WEXITSTATUS(status));
                                        if (WEXITSTATUS(status) != 0)
                                                err = -1;
                                } else if (WIFSIGNALED(status)) {
                                        log_error("'%s' ["PID_FMT"] terminated by signal %i (%s)", cmd, pid, WTERMSIG(status), strsignal(WTERMSIG(status)));
                                        err = -1;
                                } else if (WIFSTOPPED(status)) {
                                        log_error("'%s' ["PID_FMT"] stopped", cmd, pid);
                                        err = -1;
                                } else if (WIFCONTINUED(status)) {
                                        log_error("'%s' ["PID_FMT"] continued", cmd, pid);
                                        err = -1;
                                } else {
                                        log_error("'%s' ["PID_FMT"] exit with status 0x%04x", cmd, pid, status);
                                        err = -1;
                                }
                                pid = 0;
                                break;
                        }
                }
        }
out:
        return err;
}

int udev_build_argv(struct udev *udev, char *cmd, int *argc, char *argv[]) {
        int i = 0;
        char *pos;

        if (strchr(cmd, ' ') == NULL) {
                argv[i++] = cmd;
                goto out;
        }

        pos = cmd;
        while (pos != NULL && pos[0] != '\0') {
                if (pos[0] == '\'') {
                        /* do not separate quotes */
                        pos++;
                        argv[i] = strsep(&pos, "\'");
                        if (pos != NULL)
                                while (pos[0] == ' ')
                                        pos++;
                } else {
                        argv[i] = strsep(&pos, " ");
                        if (pos != NULL)
                                while (pos[0] == ' ')
                                        pos++;
                }
                i++;
        }
out:
        argv[i] = NULL;
        if (argc)
                *argc = i;
        return 0;
}

int udev_event_spawn(struct udev_event *event,
                     usec_t timeout_usec,
                     usec_t timeout_warn_usec,
                     const char *cmd, char **envp, const sigset_t *sigmask,
                     char *result, size_t ressize) {
        int outpipe[2] = {-1, -1};
        int errpipe[2] = {-1, -1};
        pid_t pid;
        char arg[UTIL_PATH_SIZE];
        char *argv[128];
        char program[UTIL_PATH_SIZE];
        int err = 0;

        strscpy(arg, sizeof(arg), cmd);
        udev_build_argv(event->udev, arg, NULL, argv);

        /* pipes from child to parent */
        if (result != NULL || log_get_max_level() >= LOG_INFO) {
                if (pipe2(outpipe, O_NONBLOCK) != 0) {
                        err = -errno;
                        log_error_errno(errno, "pipe failed: %m");
                        goto out;
                }
        }
        if (log_get_max_level() >= LOG_INFO) {
                if (pipe2(errpipe, O_NONBLOCK) != 0) {
                        err = -errno;
                        log_error_errno(errno, "pipe failed: %m");
                        goto out;
                }
        }

        /* allow programs in /usr/lib/udev/ to be called without the path */
        if (argv[0][0] != '/') {
                strscpyl(program, sizeof(program), UDEV_LIBEXEC_DIR "/", argv[0], NULL);
#ifdef HAVE_SPLIT_USR
                if(access(program, X_OK))
                        strscpyl(program, sizeof(program), "/usr/lib/udev/", argv[0], NULL);
                if(access(program, X_OK))
                        strscpyl(program, sizeof(program), "/lib/udev/", argv[0], NULL);
#endif
                argv[0] = program;
        }

        pid = fork();
        switch(pid) {
        case 0:
                /* child closes parent's ends of pipes */
                if (outpipe[READ_END] >= 0) {
                        close(outpipe[READ_END]);
                        outpipe[READ_END] = -1;
                }
                if (errpipe[READ_END] >= 0) {
                        close(errpipe[READ_END]);
                        errpipe[READ_END] = -1;
                }

                log_debug("starting '%s'", cmd);

                spawn_exec(event, cmd, argv, envp, sigmask,
                           outpipe[WRITE_END], errpipe[WRITE_END]);

                _exit(2 );
        case -1:
                log_error_errno(errno, "fork of '%s' failed: %m", cmd);
                err = -1;
                goto out;
        default:
                /* parent closed child's ends of pipes */
                if (outpipe[WRITE_END] >= 0) {
                        close(outpipe[WRITE_END]);
                        outpipe[WRITE_END] = -1;
                }
                if (errpipe[WRITE_END] >= 0) {
                        close(errpipe[WRITE_END]);
                        errpipe[WRITE_END] = -1;
                }

                spawn_read(event,
                           timeout_usec,
                           cmd,
                           outpipe[READ_END], errpipe[READ_END],
                           result, ressize);

                err = spawn_wait(event, timeout_usec, timeout_warn_usec, cmd, pid);
        }

out:
        if (outpipe[READ_END] >= 0)
                close(outpipe[READ_END]);
        if (outpipe[WRITE_END] >= 0)
                close(outpipe[WRITE_END]);
        if (errpipe[READ_END] >= 0)
                close(errpipe[READ_END]);
        if (errpipe[WRITE_END] >= 0)
                close(errpipe[WRITE_END]);
        return err;
}

#ifdef ENABLE_RULE_GENERATOR
/* function to return the count of rules that assign NAME= to a value matching arg#2 , defined in udev-rules.c */
int udev_rules_assigning_name_to(struct udev_rules *rules,const char *match_name);
#endif

static int rename_netif_dev_fromname_toname(struct udev_device *dev,const char *oldname,const char *name) {
        int r;
        int sk;
        struct ifreq ifr;

	log_debug("changing net interface name from '%s' to '%s'\n",oldname,name);

        sk = socket(PF_INET, SOCK_DGRAM, 0);
        if (sk < 0)
                return log_error_errno(-errno, "error opening socket: %m");

        memzero(&ifr, sizeof(struct ifreq));
        strscpy(ifr.ifr_name, IFNAMSIZ, oldname);
        strscpy(ifr.ifr_newname, IFNAMSIZ, name);
        r = ioctl(sk, SIOCSIFNAME, &ifr);

#ifdef ENABLE_RULE_GENERATOR
	int loop;
    struct ifreq ifr_tmp;

	if (r == 0) {
		log_info("renamed network interface %s to %s\n", ifr.ifr_name, ifr.ifr_newname);
		goto out;
	}
	/* keep trying if the destination interface name already exists */
	log_debug("collision on rename of network interface %s to %s , retrying until timeout\n",
		ifr.ifr_name, ifr.ifr_newname);

	/* there has been a collision so rename my name to a temporal name, letting other one to rename to my name, freeying its name... */
        memzero(&ifr_tmp, sizeof(struct ifreq));
        strscpy(ifr_tmp.ifr_name, IFNAMSIZ, oldname);
	snprintf(ifr_tmp.ifr_newname, IFNAMSIZ, "rename_%s", oldname);
        r = ioctl(sk, SIOCSIFNAME, &ifr_tmp);
		log_info("Temporarily renamed network interface %s to %s\n", ifr_tmp.ifr_name, ifr_tmp.ifr_newname);
	
	/* we have changed our name so in subsequents tries i should rename my temporal name to the wanted one */
        strscpy(ifr.ifr_name, IFNAMSIZ, ifr_tmp.ifr_newname);

	r = -errno;
	if (r != -EEXIST)
		goto out;

	/* wait a maximum of 90 seconds for our target to become available */
	loop = 90 * 20;
	while (loop--) {
		const struct timespec duration = { 0, 1000 * 1000 * 1000 / 20 };

		nanosleep(&duration, NULL);

		r = ioctl(sk, SIOCSIFNAME, &ifr);
		if (r == 0) {
			log_info("renamed network interface %s to %s\n", ifr.ifr_name, ifr.ifr_newname);
			break;
		}
		r = -errno;
		if (r != -EEXIST)
			break;
	}

out:
#endif
	if (r < 0)
                log_error_errno(-errno, "Error changing net interface name %s to %s: %m\n", ifr.ifr_name, ifr.ifr_newname);
	else
	        log_debug("renamed network interface '%s' to '%s'", oldname, name);

        close(sk);
        return r;
}

static int rename_netif(struct udev_event *event) {
	return rename_netif_dev_fromname_toname(event->dev,udev_device_get_sysname(event->dev),event->name);
}

void udev_event_execute_rules(struct udev_event *event,
                              usec_t timeout_usec, usec_t timeout_warn_usec,
                              struct udev_list *properties_list,
                              struct udev_rules *rules,
                              const sigset_t *sigmask) {
        struct udev_device *dev = event->dev;

        if (udev_device_get_subsystem(dev) == NULL)
                return;

        if (streq(udev_device_get_action(dev), "remove")) {
                udev_device_read_db(dev);
                udev_device_tag_index(dev, NULL, false);
                udev_device_delete_db(dev);

                if (major(udev_device_get_devnum(dev)) != 0)
                        udev_watch_end(event->udev, dev);

                udev_rules_apply_to_event(rules, event,
                                          timeout_usec, timeout_warn_usec,
                                          properties_list,
                                          sigmask);

                if (major(udev_device_get_devnum(dev)) != 0)
                        udev_node_remove(dev);
        } else {
                event->dev_db = udev_device_clone_with_db(dev);
                if (event->dev_db != NULL) {
                        /* disable watch during event processing */
                        if (major(udev_device_get_devnum(dev)) != 0)
                                udev_watch_end(event->udev, event->dev_db);
                }

                if (major(udev_device_get_devnum(dev)) == 0 &&
                    streq(udev_device_get_action(dev), "move"))
                        udev_device_copy_properties(dev, event->dev_db);

                udev_rules_apply_to_event(rules, event,
                                          timeout_usec, timeout_warn_usec,
                                          properties_list,
                                          sigmask);

                /* rename a new network interface, if needed */

                /* ENABLE_RULE_GENERATOR conditional:
                 * if this is a net iface, and it is an add event,
                 * and as long as all of the following are FALSE:
                 *  - no NAME target and the current name is not being used
                 *  - there is a NAME target and it is the same as the current name
                 *  - the rules can successfully be searched for the current name (not really part of the conditional)
                 * the run the rename.
                 *
                 * note - udev_rules_assigning_name_to is run when event->name is NULL to ensure renames happen,
                 * but also on its own to check if a temp-rename is necessary when event->name exists.
                 *
                 * A temp-rename is necessary when:
                 * - there is no rule renaming the current iface but the current name IS used in some other rule
                 * - there is a rule renaming the current iface,
                 *   the current name IS used AND the target name != the current name
                 */

#ifdef ENABLE_RULE_GENERATOR
		int r;
                if (udev_device_get_ifindex(dev) > 0 && streq(udev_device_get_action(dev), "add") &&
                    (event->name == NULL && (r=udev_rules_assigning_name_to(rules,udev_device_get_sysname(dev))) > 0 ||
                    event->name != NULL && !streq(event->name, udev_device_get_sysname(dev)))) {
                        char syspath[UTIL_PATH_SIZE];
                        char *pos;
                        char *finalifname = event->name;
                        char newifname[IFNAMSIZ];

                        /* r is the number of rules that assign a device with NAME= this sysname */
                        if (r > 0 || (r=udev_rules_assigning_name_to(rules,udev_device_get_sysname(dev))) > 0) {
                                /* have a conflict, rename to a temp name */
                                char *newpos;
                                int ifidnum;

                                /* build the temporary iface name */
                                strscpy(newifname, IFNAMSIZ, udev_device_get_sysname(dev));
                                newpos=pos=&newifname[strcspn(newifname,"0123456789")];
                                ifidnum=(int)strtol(pos,&newpos,10);
                                *pos='\0';
                                if (newpos > pos && *newpos == '\0') /* append new iface num to name */
                                        /* use udev_device_get_ifindex(dev) as it is unique to every iface */
                                        snprintf(pos,IFNAMSIZ+(newifname-pos), "%d", 128 - udev_device_get_ifindex(dev));

                                /* note, r > 0, which will skip the post-rename stuff if no rename occurs */

                                /* if sysname isn't already the tmpname (ie there is no numeric component), do the rename */
                                if (!streq(newifname,udev_device_get_sysname(dev))) {
                                        r = rename_netif_dev_fromname_toname(dev,udev_device_get_sysname(dev),newifname);
                                        if (r == 0) {
                                                finalifname = newifname;
                                                log_debug("renamed netif to '%s' for collision avoidance\n", newifname);
                                        } else {
                                                log_error("could not rename netif to '%s' for collision avoidance\n",newifname);
                                        }
                                }
                                /* rename it now to its final target if its not already there */
                                if (event->name != NULL && !streq(event->name, newifname)) {
                                        r = rename_netif_dev_fromname_toname(dev,newifname,event->name);
                                        if (r == 0)
                                                finalifname = event->name;
                               }

                        } else { /* no need to rename to a tempname first, do a regular direct rename to event->name */

                                r = 1; /* skip the post-rename stuff if no rename occurs */
                                if (!streq(event->name, udev_device_get_sysname(dev)))
                                        r = rename_netif(event);
                        }

                        if (r == 0) {
                                log_debug("renamed netif to '%s'\n", finalifname);
                                r = udev_device_rename(dev, finalifname);
#else
                if (udev_device_get_ifindex(dev) > 0 && streq(udev_device_get_action(dev), "add") &&
                    event->name != NULL && !streq(event->name, udev_device_get_sysname(dev))) {
                        int r;

                        r = rename_netif(event);
                        if (r < 0)
                                log_warning_errno(r, "could not rename interface '%d' from '%s' to '%s': %m", udev_device_get_ifindex(dev),
                                                  udev_device_get_sysname(dev), event->name);
                        else {
                                r = udev_device_rename(dev, event->name);
#endif
                                if (r < 0)
                                        log_warning_errno(r, "renamed interface '%d' from '%s' to '%s', but could not update udev_device: %m",
                                                          udev_device_get_ifindex(dev), udev_device_get_sysname(dev), event->name);
                                else
                                        log_debug("changed devpath to '%s'", udev_device_get_devpath(dev));
                        }
                }

                if (major(udev_device_get_devnum(dev)) > 0) {
                        bool apply;

                        /* remove/update possible left-over symlinks from old database entry */
                        if (event->dev_db != NULL)
                                udev_node_update_old_links(dev, event->dev_db);

                        if (!event->owner_set)
                                event->uid = udev_device_get_devnode_uid(dev);

                        if (!event->group_set)
                                event->gid = udev_device_get_devnode_gid(dev);

                        if (!event->mode_set) {
                                if (udev_device_get_devnode_mode(dev) > 0) {
                                        /* kernel supplied value */
                                        event->mode = udev_device_get_devnode_mode(dev);
                                } else if (event->gid > 0) {
                                        /* default 0660 if a group is assigned */
                                        event->mode = 0660;
                                } else {
                                        /* default 0600 */
                                        event->mode = 0600;
                                }
                        }

                        apply = streq(udev_device_get_action(dev), "add") || event->owner_set || event->group_set || event->mode_set;
                        udev_node_add(dev, apply, event->mode, event->uid, event->gid, &event->seclabel_list);
                }

                /* preserve old, or get new initialization timestamp */
                udev_device_ensure_usec_initialized(event->dev, event->dev_db);

                /* (re)write database file */
                udev_device_tag_index(dev, event->dev_db, true);
                udev_device_update_db(dev);
                udev_device_set_is_initialized(dev);

                event->dev_db = udev_device_unref(event->dev_db);
        }
}

void udev_event_execute_run(struct udev_event *event, usec_t timeout_usec, usec_t timeout_warn_usec, const sigset_t *sigmask) {
        struct udev_list_entry *list_entry;

        udev_list_entry_foreach(list_entry, udev_list_get_entry(&event->run_list)) {
                const char *cmd = udev_list_entry_get_name(list_entry);
                enum udev_builtin_cmd builtin_cmd = udev_list_entry_get_num(list_entry);

                if (builtin_cmd < UDEV_BUILTIN_MAX) {
                        char command[UTIL_PATH_SIZE];

                        udev_event_apply_format(event, cmd, command, sizeof(command), false);
                        udev_builtin_run(event->dev, builtin_cmd, command, false);
                } else {
                        char program[UTIL_PATH_SIZE];
                        char **envp;

                        if (event->exec_delay > 0) {
                                log_debug("delay execution of '%s'", program);
                                sleep(event->exec_delay);
                        }

                        udev_event_apply_format(event, cmd, program, sizeof(program), false);
                        envp = udev_device_get_properties_envp(event->dev);
                        udev_event_spawn(event, timeout_usec, timeout_warn_usec, program, envp, sigmask, NULL, 0);
                }
        }
}
