/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * The pager of systemd's src/shared/pager.c (as of systemd a446e8ff2c), adapted to eudev: the pager
 * process is forked directly, the owner of the login session, which systemd gets from logind, is the
 * audit login UID, pager_close() is also called at exit, and quitting the pager before all output is
 * written ends the program instead of SIGPIPE, with exit status 0, or with the failure code that the
 * program set with pager_set_exit_status() before.
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include "fileio.h"
#include "log.h"
#include "macro.h"
#include "pager.h"
#include "process-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "util.h"

static pid_t pager_pid = 0;
static pid_t pager_parent = 0;

static int stored_stdout = -1;
static int stored_stderr = -1;
static bool stdout_redirected = false;
static bool stderr_redirected = false;

static struct sigaction old_sigpipe;
static bool sigpipe_handled = false;
static volatile sig_atomic_t sigpipe_exit_status = EXIT_SUCCESS;

noreturn static void pager_fallback(void) {
        char buf[4096];

        for (;;) {
                ssize_t n;
                int r;

                n = read(STDIN_FILENO, buf, sizeof(buf));
                if (n < 0) {
                        if (errno == EINTR)
                                continue;

                        log_error_errno(errno, "Internal pager failed: %m");
                        _exit(EXIT_FAILURE);
                }
                if (n == 0)
                        break;

                r = loop_write(STDOUT_FILENO, buf, n, false);
                if (r < 0) {
                        log_error_errno(r, "Internal pager failed: %m");
                        _exit(EXIT_FAILURE);
                }
        }

        _exit(EXIT_SUCCESS);
}

static int no_quit_on_interrupt(int exe_name_fd, const char *less_opts) {
        _cleanup_close_ int fd = exe_name_fd;
        _cleanup_free_ char *buf = NULL;
        size_t n = 0, allocated = 0;
        const char *line, *p;
        int r;

        assert(exe_name_fd >= 0);
        assert(less_opts);

        /* Read the names of the pagers the child tried, each terminated by a NUL, until the pipe is
         * closed on exec() of the pager. This takes ownership of exe_name_fd. */
        for (;;) {
                ssize_t k;

                if (!GREEDY_REALLOC(buf, allocated, n + 256 + 1))
                        return log_oom();

                k = read(fd, buf + n, 256);
                if (k < 0) {
                        if (errno == EINTR)
                                continue;

                        return log_error_errno(errno, "Failed to read from socket: %m");
                }
                if (k == 0)
                        break;

                n += k;
        }
        buf[n] = '\0';

        /* Find the last line */
        if (n > 0 && buf[n - 1] == '\0')
                n--;
        p = memrchr(buf, '\0', n);
        line = p ? p + 1 : buf;

        /* We only treat "less" specially.
         * Return true whenever option K is *not* set. */
        r = streq(line, "less") && !strchr(less_opts, 'K');

        log_debug("Pager executable is \"%s\", options \"%s\", quit_on_interrupt: %s",
                  line, less_opts, r ? "no" : "yes");
        return r;
}

static bool running_with_escalated_privileges(void) {
        _cleanup_free_ char *s = NULL;
        uid_t uid;
        int r;

        if (getenv("SUDO_UID"))
                return true;

        /* systemd compares the effective UID with the owner of the login session, which it gets
         * from logind. Use the audit login UID instead, the UID of the user who logged in, which
         * su and doas do not change. Like systemd, enable secure mode if it is not known. */
        r = read_one_line_file("/proc/self/loginuid", &s);
        if (r >= 0)
                r = parse_uid(s, &uid);
        if (r < 0) {
                log_debug_errno(r, "Failed to get the login UID, enabling pager secure mode: %m");
                return true;
        }

        return uid != geteuid();
}

/* Unlike systemd, where the program is killed by SIGPIPE (exit status 141 in the shell) when it writes
 * after the pager quit, end like after all output was shown: wait for the pager to exit, as
 * pager_close() does, and exit with status 0, or with the failure code set before with
 * pager_set_exit_status(). Only async-signal-safe functions are used here. */
static void pager_sigpipe_handler(int sig) {
        if (getpid() != pager_parent) {
                /* a child forked later, which did not open the pager */
                (void) signal(SIGPIPE, SIG_DFL);
                (void) raise(SIGPIPE);
                return;
        }

        while (waitpid(pager_pid, NULL, 0) < 0 && errno == EINTR)
                ;

        _exit(sigpipe_exit_status);
}

void pager_set_exit_status(int status) {
        sigpipe_exit_status = status;
}

void pager_open(PagerFlags flags) {
        _cleanup_strv_free_ char **pager_args = NULL;
        _cleanup_free_ char *l = NULL;
        int fd[2] = { -1, -1 }, exe_name_pipe[2] = { -1, -1 };
        const char *pager, *less_opts;
        static bool registered = false;
        pid_t parent, pid;
        int r;

        if (flags & PAGER_DISABLE)
                return;

        if (pager_pid > 0)
                return;

        /* This also caches whether standard output and standard error are a terminal, which is used
         * to decide about the colors, before they are redirected to the pager. */
        if (terminal_is_dumb())
                return;

        if (!is_main_thread()) {
                log_error("Pager invoked from wrong thread.");
                return;
        }

        pager = getenv("SYSTEMD_PAGER");
        if (!pager)
                pager = getenv("PAGER");

        if (pager) {
                r = strv_split_and_extend(&pager_args, pager, WHITESPACE, false);
                if (r < 0) {
                        log_oom();
                        return;
                }

                /* If the pager is explicitly turned off, honour it */
                if (strv_isempty(pager_args) || (strv_length(pager_args) == 1 && streq(pager_args[0], "cat")))
                        return;
        }

        /* Determine the colors before we spawn the pager, so that they are chosen for the actual
         * terminal. */
        (void) colors_enabled();

        if (pipe2(fd, O_CLOEXEC) < 0) {
                log_error_errno(errno, "Failed to create pager pipe: %m");
                return;
        }

        /* This is a pipe to feed the name of the executed pager binary into the parent */
        if (pipe2(exe_name_pipe, O_CLOEXEC) < 0) {
                log_error_errno(errno, "Failed to create exe_name pipe: %m");
                goto finish;
        }

        /* Initialize a good set of less options */
        less_opts = getenv("SYSTEMD_LESS");
        if (!less_opts)
                less_opts = "FRSXMK";
        if (flags & PAGER_JUMP_TO_END) {
                l = strjoin(less_opts, " +G", NULL);
                if (!l) {
                        log_oom();
                        goto finish;
                }
                less_opts = l;
        }

        parent = getpid();

        pid = fork();
        if (pid < 0) {
                log_error_errno(errno, "Failed to fork pager: %m");
                goto finish;
        }
        if (pid == 0) {
                /* Debian's alternatives command for pagers is called 'pager'. Note that we do not call
                 * sensible-pagers here, since that is just a shell script that implements a logic that is
                 * similar to this one anyway, but is Debian-specific. */
                static const char* pagers[] = { "pager", "less", "more", "(built-in)" };
                const char *less_charset;
                int use_secure_mode;
                bool trust_pager;
                unsigned i;

                /* In the child start the pager */

                (void) reset_all_signal_handlers();
                (void) reset_signal_mask();

                /* We set SIGINT as PR_DEATHSIG signal here, to match the "K" parameter we set in $LESS,
                 * which enables SIGINT behaviour. */
                if (prctl(PR_SET_PDEATHSIG, SIGINT) < 0)
                        log_debug_errno(errno, "Failed to set the death signal of the pager, ignoring: %m");
                if (getppid() != parent) {
                        (void) raise(SIGINT);
                        _exit(EXIT_FAILURE);
                }

                if (dup2(fd[0], STDIN_FILENO) < 0) {
                        log_error_errno(errno, "Failed to duplicate file descriptor to STDIN: %m");
                        _exit(EXIT_FAILURE);
                }

                safe_close(fd[0]);
                safe_close(fd[1]);

                if (setenv("LESS", less_opts, 1) < 0) {
                        log_error_errno(errno, "Failed to set environment variable LESS: %m");
                        _exit(EXIT_FAILURE);
                }

                /* Initialize a good charset for less. This is particularly important if we output UTF-8
                 * characters. */
                less_charset = getenv("SYSTEMD_LESSCHARSET");
                if (!less_charset && is_locale_utf8())
                        less_charset = "utf-8";
                if (less_charset &&
                    setenv("LESSCHARSET", less_charset, 1) < 0) {
                        log_error_errno(errno, "Failed to set environment variable LESSCHARSET: %m");
                        _exit(EXIT_FAILURE);
                }

                /* People might invoke us from sudo, don't needlessly allow less to be a way to shell out
                 * privileged stuff. If the user set $SYSTEMD_PAGERSECURE, trust their configuration of the
                 * pager. If they didn't, use secure mode when under euid is changed. If $SYSTEMD_PAGERSECURE
                 * wasn't explicitly set, and we autodetect the need for secure mode, only use the pager we
                 * know to be good. */
                use_secure_mode = secure_getenv_bool("SYSTEMD_PAGERSECURE");
                trust_pager = use_secure_mode >= 0;
                if (use_secure_mode == -ENXIO)
                        use_secure_mode = running_with_escalated_privileges();
                else if (use_secure_mode < 0) {
                        log_warning_errno(use_secure_mode, "Unable to parse $SYSTEMD_PAGERSECURE, assuming true: %m");
                        use_secure_mode = true;
                }

                /* We generally always set variables used by less, even if we end up using a different pager.
                 * They shouldn't hurt in any case, and ideally other pagers would look at them too. */
                if (use_secure_mode)
                        r = setenv("LESSSECURE", "1", 1);
                else
                        r = unsetenv("LESSSECURE");
                if (r < 0) {
                        log_error_errno(errno, "Failed to adjust environment variable LESSSECURE: %m");
                        _exit(EXIT_FAILURE);
                }

                if (trust_pager && pager_args) { /* The pager config might be set globally, and we cannot
                                                  * know if the user adjusted it to be appropriate for the
                                                  * secure mode. Thus, start the pager specified through
                                                  * envvars only when $SYSTEMD_PAGERSECURE was explicitly set
                                                  * as well. */
                        r = loop_write(exe_name_pipe[1], pager_args[0], strlen(pager_args[0]) + 1, false);
                        if (r < 0) {
                                log_error_errno(r, "Failed to write pager name to socket: %m");
                                _exit(EXIT_FAILURE);
                        }

                        execvp(pager_args[0], pager_args);
                        log_full_errno(errno == ENOENT ? LOG_DEBUG : LOG_WARNING, errno,
                                       "Failed to execute '%s', using fallback pagers: %m", pager_args[0]);
                }

                for (i = 0; i < ELEMENTSOF(pagers); i++) {
                        /* Only less (and our trivial fallback) implement secure mode right now. */
                        if (use_secure_mode && !STR_IN_SET(pagers[i], "less", "(built-in)"))
                                continue;

                        r = loop_write(exe_name_pipe[1], pagers[i], strlen(pagers[i]) + 1, false);
                        if (r < 0) {
                                log_error_errno(r, "Failed to write pager name to socket: %m");
                                _exit(EXIT_FAILURE);
                        }

                        if (i < ELEMENTSOF(pagers) - 1) {
                                execlp(pagers[i], pagers[i], NULL);
                                log_full_errno(errno == ENOENT ? LOG_DEBUG : LOG_WARNING, errno,
                                               "Failed to execute '%s', will try '%s' next: %m", pagers[i], pagers[i+1]);
                        } else {
                                /* Close pipe to signal the parent to start sending data */
                                safe_close(exe_name_pipe[0]);
                                safe_close(exe_name_pipe[1]);
                                pager_fallback();
                        }
                }

                _exit(EXIT_FAILURE);
        }

        /* Return in the parent */
        pager_pid = pid;
        pager_parent = parent;

        if (!registered) {
                /* Also close the pager when exit() is called, so that we wait for it. */
                if (atexit(pager_close) == 0)
                        registered = true;
        }

        stored_stdout = fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 3);
        if (dup2(fd[1], STDOUT_FILENO) < 0) {
                stored_stdout = safe_close(stored_stdout);
                log_error_errno(errno, "Failed to duplicate pager pipe: %m");
                goto finish;
        }
        stdout_redirected = true;

        stored_stderr = fcntl(STDERR_FILENO, F_DUPFD_CLOEXEC, 3);
        if (dup2(fd[1], STDERR_FILENO) < 0) {
                stored_stderr = safe_close(stored_stderr);
                log_error_errno(errno, "Failed to duplicate pager pipe: %m");
                goto finish;
        }
        stderr_redirected = true;

        /* Writes after the pager quit raise SIGPIPE, see pager_sigpipe_handler(). */
        {
                struct sigaction sa = {
                        .sa_handler = pager_sigpipe_handler,
                        .sa_flags = SA_RESTART,
                };

                if (sigaction(SIGPIPE, &sa, &old_sigpipe) >= 0)
                        sigpipe_handled = true;
        }

        exe_name_pipe[1] = safe_close(exe_name_pipe[1]);

        r = no_quit_on_interrupt(exe_name_pipe[0], less_opts);
        exe_name_pipe[0] = -1;
        if (r > 0)
                (void) signal(SIGINT, SIG_IGN);

finish:
        safe_close(fd[0]);
        safe_close(fd[1]);
        safe_close(exe_name_pipe[0]);
        safe_close(exe_name_pipe[1]);
}

void pager_close(void) {
        siginfo_t status;

        if (pager_pid <= 0)
                return;

        /* Only in the process that opened the pager, not in a child forked from it later. */
        if (getpid() != pager_parent)
                return;

        /* Inform pager that we are done */
        (void) fflush(stdout);
        if (stdout_redirected)
                if (stored_stdout < 0 || dup2(stored_stdout, STDOUT_FILENO) < 0)
                        (void) close(STDOUT_FILENO);
        stored_stdout = safe_close(stored_stdout);
        (void) fflush(stderr);
        if (stderr_redirected)
                if (stored_stderr < 0 || dup2(stored_stderr, STDERR_FILENO) < 0)
                        (void) close(STDERR_FILENO);
        stored_stderr = safe_close(stored_stderr);
        stdout_redirected = stderr_redirected = false;

        if (sigpipe_handled) {
                (void) sigaction(SIGPIPE, &old_sigpipe, NULL);
                sigpipe_handled = false;
        }

        (void) kill(pager_pid, SIGCONT);
        while (waitid(P_PID, pager_pid, &status, WEXITED) < 0 && errno == EINTR)
                ;
        pager_pid = 0;
}

bool pager_have(void) {
        return pager_pid > 0;
}
