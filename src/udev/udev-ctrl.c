/*
 * libudev - interface to udev device information
 *
 * Copyright (C) 2008 Kay Sievers <kay@vrfy.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "socket-util.h"
#include "udev.h"

/* wire protocol magic must match */
#define UDEV_CTRL_MAGIC                                0xdead1dea

struct udev_ctrl_msg_wire {
        char version[16];
        unsigned int magic;
        enum udev_ctrl_msg_type type;
        union {
                int intval;
                char buf[256];
        };
};

struct udev_ctrl_msg {
        int refcount;
        struct udev_ctrl_connection *conn;
        struct udev_ctrl_msg_wire ctrl_msg_wire;
};

struct udev_ctrl {
        int refcount;
        struct udev *udev;
        int sock;
        union sockaddr_union saddr;
        socklen_t addrlen;
        bool bound;
        bool cleanup_socket;
        bool connected;
        /* udev_ctrl_send() started the connection with UDEV_CTRL_BEGIN_MESSAGES, udev_ctrl_wait() ends it */
        bool batch;
};

struct udev_ctrl_connection {
        int refcount;
        struct udev_ctrl *uctrl;
        int sock;
};

struct udev_ctrl *udev_ctrl_new_from_fd(struct udev *udev, int fd) {
        struct udev_ctrl *uctrl;
        const int on = 1;
        int r;

        uctrl = new0(struct udev_ctrl, 1);
        if (uctrl == NULL)
                return NULL;
        uctrl->refcount = 1;
        uctrl->udev = udev;

        if (fd < 0) {
                uctrl->sock = socket(AF_LOCAL, SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC, 0);
                if (uctrl->sock < 0) {
                        /* the caller logs the error, with errno */
                        r = errno;
                        udev_ctrl_unref(uctrl);
                        errno = r;
                        return NULL;
                }
        } else {
                uctrl->bound = true;
                uctrl->sock = fd;
        }
        r = setsockopt(uctrl->sock, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on));
        if (r < 0)
                log_warning_errno(errno, "could not set SO_PASSCRED: %m");

        uctrl->saddr.un.sun_family = AF_LOCAL;
        strscpy(uctrl->saddr.un.sun_path, sizeof(uctrl->saddr.un.sun_path), UDEV_ROOT_RUN "/udev/control");
        uctrl->addrlen = offsetof(struct sockaddr_un, sun_path) + strlen(uctrl->saddr.un.sun_path);
        return uctrl;
}

struct udev_ctrl *udev_ctrl_new(struct udev *udev) {
        return udev_ctrl_new_from_fd(udev, -1);
}

int udev_ctrl_enable_receiving(struct udev_ctrl *uctrl) {
        int err;

        if (!uctrl->bound) {
                err = bind(uctrl->sock, &uctrl->saddr.sa, uctrl->addrlen);
                if (err < 0 && errno == EADDRINUSE) {
                        unlink(uctrl->saddr.un.sun_path);
                        err = bind(uctrl->sock, &uctrl->saddr.sa, uctrl->addrlen);
                }

                /* with the messages of udev-ctrl.c of systemd v261; udevd, the only caller, does not log the
                 * error again */
                if (err < 0)
                        return log_error_errno(errno, "Failed to bind udev control socket: %m");

                err = listen(uctrl->sock, 0);
                if (err < 0)
                        return log_error_errno(errno, "Failed to listen udev control socket: %m");

                uctrl->bound = true;
                uctrl->cleanup_socket = true;
        }
        return 0;
}

struct udev *udev_ctrl_get_udev(struct udev_ctrl *uctrl) {
        return uctrl->udev;
}

static struct udev_ctrl *udev_ctrl_ref(struct udev_ctrl *uctrl) {
        if (uctrl)
                uctrl->refcount++;

        return uctrl;
}

struct udev_ctrl *udev_ctrl_unref(struct udev_ctrl *uctrl) {
        if (uctrl && -- uctrl->refcount == 0) {
                if (uctrl->sock >= 0)
                        close(uctrl->sock);
                free(uctrl);
        }

        return NULL;
}

int udev_ctrl_cleanup(struct udev_ctrl *uctrl) {
        if (uctrl == NULL)
                return 0;
        if (uctrl->cleanup_socket)
                unlink(uctrl->saddr.un.sun_path);
        return 0;
}

int udev_ctrl_get_fd(struct udev_ctrl *uctrl) {
        if (uctrl == NULL)
                return -EINVAL;
        return uctrl->sock;
}

static inline int accept4_fallback(int sockfd) {
        int fd;

        /* This is racey, but what can we do without accept4? */
        if ((fd = accept(sockfd, NULL, NULL)) >= 0) {
                fcntl(fd, F_SETFL, O_NONBLOCK);
                fcntl(fd, F_SETFD, FD_CLOEXEC);
        }

        return fd;
}

struct udev_ctrl_connection *udev_ctrl_get_connection(struct udev_ctrl *uctrl) {
        struct udev_ctrl_connection *conn;
        struct ucred ucred = {};
        const int on = 1;
        int r;

        conn = new(struct udev_ctrl_connection, 1);
        if (conn == NULL)
                return NULL;
        conn->refcount = 1;
        conn->uctrl = uctrl;

#if HAVE_DECL_ACCEPT4
        conn->sock = accept4(uctrl->sock, NULL, NULL, SOCK_CLOEXEC|SOCK_NONBLOCK);

        /* Fallback path when accept4() is unavailable */
        if ( conn->sock < 0 && (errno == ENOSYS || errno == EOPNOTSUPP) )
                conn->sock = accept4_fallback(uctrl->sock);
#else
        conn->sock = accept4_fallback(uctrl->sock);
#endif

        if (conn->sock < 0) {
                if (errno != EINTR)
                        log_error_errno(errno, "unable to receive ctrl connection: %m");
                goto err;
        }

        /* check peer credential of connection */
        r = getpeercred(conn->sock, &ucred);
        if (r < 0) {
                log_error_errno(r, "unable to receive credentials of ctrl connection: %m");
                goto err;
        }
        if (ucred.uid > 0) {
                log_error("sender uid="UID_FMT", message ignored", ucred.uid);
                goto err;
        }

        /* enable receiving of the sender credentials in the messages */
        r = setsockopt(conn->sock, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on));
        if (r < 0)
                log_warning_errno(errno, "could not set SO_PASSCRED: %m");

        udev_ctrl_ref(uctrl);
        return conn;
err:
        if (conn->sock >= 0)
                close(conn->sock);
        free(conn);
        return NULL;
}

struct udev_ctrl_connection *udev_ctrl_connection_ref(struct udev_ctrl_connection *conn) {
        if (conn == NULL)
                return NULL;
        conn->refcount++;
        return conn;
}

struct udev_ctrl_connection *udev_ctrl_connection_unref(struct udev_ctrl_connection *conn) {
        if (conn && -- conn->refcount == 0) {
                if (conn->sock >= 0)
                        close(conn->sock);

                udev_ctrl_unref(conn->uctrl);

                free(conn);
        }

        return NULL;
}

/* udevd replies to these messages with one byte before it closes the connection. An udevd that does not know
 * such a message closes the connection without a reply, which is how the message is found unsupported. */
static bool ctrl_msg_type_has_reply(enum udev_ctrl_msg_type type) {
        return IN_SET(type, UDEV_CTRL_SET_TRACE, UDEV_CTRL_REVERT);
}

/* Connects the socket, a new one if it was connected before, as udevd handles one connection at a time and
 * closes it when it is done with it. */
static int ctrl_connect(struct udev_ctrl *uctrl) {
        if (uctrl->connected) {
                const int on = 1;
                int fd;

                fd = socket(AF_LOCAL, SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC, 0);
                if (fd < 0)
                        return -errno;
                if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on)) < 0)
                        log_warning_errno(errno, "could not set SO_PASSCRED: %m");

                safe_close(uctrl->sock);
                uctrl->sock = fd;
                uctrl->connected = false;
                uctrl->batch = false;
        }

        if (connect(uctrl->sock, &uctrl->saddr.sa, uctrl->addrlen) < 0)
                return -errno;

        uctrl->connected = true;
        return 0;
}

/* Sends one message on the connected socket, without waiting. */
static int ctrl_send_msg(struct udev_ctrl *uctrl, enum udev_ctrl_msg_type type, int intval, const char *buf) {
        struct udev_ctrl_msg_wire ctrl_msg_wire;

        memzero(&ctrl_msg_wire, sizeof(struct udev_ctrl_msg_wire));
        snprintf(ctrl_msg_wire.version, sizeof(ctrl_msg_wire.version), "%.*s", (int)(sizeof(ctrl_msg_wire.version) - 1), "udev-" VERSION);
        ctrl_msg_wire.magic = UDEV_CTRL_MAGIC;
        ctrl_msg_wire.type = type;

        if (buf != NULL)
                strscpy(ctrl_msg_wire.buf, sizeof(ctrl_msg_wire.buf), buf);
        else
                ctrl_msg_wire.intval = intval;

        /* no SIGPIPE when udevd closed the connection already, see udev_ctrl_send() */
        if (send(uctrl->sock, &ctrl_msg_wire, sizeof(ctrl_msg_wire), MSG_NOSIGNAL) < 0)
                return -errno;

        return 0;
}

/* Sends a message on a connection of its own, and waits until udevd handled it, or for its reply. Every udevd
 * handles such a connection, the one of eudev before udev_ctrl_send() too. ret_sent, if not NULL, tells
 * whether the message was sent, so that a failure is one of waiting for udevd, like udev_ctrl_wait() of
 * systemd v261, rather than one of connecting to it or sending the message, like its udev_ctrl_send(). */
int udev_ctrl_send_one(struct udev_ctrl *uctrl, enum udev_ctrl_msg_type type, int intval, const char *buf, int timeout,
                       bool *ret_sent) {
        int err = 0;

        if (ret_sent)
                *ret_sent = false;

        err = ctrl_connect(uctrl);
        if (err < 0)
                goto out;

        err = ctrl_send_msg(uctrl, type, intval, buf);
        if (err < 0)
                goto out;
        if (ret_sent)
                *ret_sent = true;

        /* Wait for peer message handling or disconnect. Like udev_ctrl_wait() of systemd v261, any event on the
         * socket means that udevd is done with the message: its reply, the end of the connection, or an error,
         * e.g. POLLERR with ECONNRESET when udevd closes the connection without reading the message. Only a
         * message that needs a reply fails without one. */
        for (;;) {
                struct pollfd pfd[1];
                int r;

                pfd[0].fd = uctrl->sock;
                pfd[0].events = POLLIN;
                r = poll(pfd, 1, timeout * MSEC_PER_SEC);
                if (r  < 0) {
                        if (errno == EINTR)
                                continue;
                        err = -errno;
                        break;
                }

                if (r == 0)
                        err = -ETIMEDOUT;
                else if (ctrl_msg_type_has_reply(type)) {
                        char reply;
                        ssize_t n;

                        n = recv(uctrl->sock, &reply, sizeof(reply), MSG_DONTWAIT);
                        if (n < 0) {
                                if (IN_SET(errno, EINTR, EAGAIN))
                                        continue;
                                err = -errno;
                        } else if (n == 0)
                                /* the connection was closed without a reply */
                                err = -EOPNOTSUPP;
                }
                break;
        }
out:
        return err;
}

int udev_ctrl_send_ping_full(struct udev_ctrl *uctrl, int timeout, bool *ret_sent) {
        return udev_ctrl_send_one(uctrl, UDEV_CTRL_PING, 0, NULL, timeout, ret_sent);
}

int udev_ctrl_send_exit(struct udev_ctrl *uctrl, int timeout) {
        return udev_ctrl_send_one(uctrl, UDEV_CTRL_EXIT, 0, NULL, timeout, NULL);
}

/* Like udev_ctrl_send() of systemd v261: sends the message on the connection that udev_ctrl_wait() ends,
 * without waiting for udevd to handle it. Returns 0, or a negative errno if connecting or sending failed, e.g.
 * -ENOENT or -ECONNREFUSED when udevd does not run.
 *
 * Unlike systemd, the connection starts with UDEV_CTRL_BEGIN_MESSAGES, which tells udevd to handle all the
 * messages of the connection until _UDEV_CTRL_END_MESSAGES, as the udevd of systemd does with every connection.
 * Without it, udevd handles the first message of a connection and closes it, as before, for an older udevadm,
 * which sends one message per connection and waits until the connection ends. The udevd of an older eudev
 * handles every connection that way: it ignores UDEV_CTRL_BEGIN_MESSAGES as a message of unknown type and
 * closes the connection, so none of the messages is handled. That shows when a later message cannot be sent,
 * here, or in udev_ctrl_wait(), as the connection was closed already, and -EPROTONOSUPPORT is returned then: each
 * message needs to be sent with udev_ctrl_send_one() instead. */
int udev_ctrl_send(struct udev_ctrl *uctrl, enum udev_ctrl_msg_type type, int intval, const char *buf) {
        int r;

        if (!uctrl->batch) {
                r = ctrl_connect(uctrl);
                if (r < 0)
                        return r;

                r = ctrl_send_msg(uctrl, UDEV_CTRL_BEGIN_MESSAGES, 0, NULL);
                if (r < 0)
                        return r;

                uctrl->batch = true;
        }

        r = ctrl_send_msg(uctrl, type, intval, buf);
        if (IN_SET(r, -EPIPE, -ECONNRESET))
                return -EPROTONOSUPPORT;

        return r;
}

/* Like udev_ctrl_wait() of systemd v261: ends the messages of udev_ctrl_send() with _UDEV_CTRL_END_MESSAGES, and
 * waits once, at most timeout seconds (-1 forever), until udevd handled all of them, which it tells by closing
 * the connection after it read the last one. The replies of the messages that have one (see
 * ctrl_msg_type_has_reply()) are skipped: an udevd that knows UDEV_CTRL_BEGIN_MESSAGES knows them too. Returns 0
 * then, -ETIMEDOUT, -EPROTONOSUPPORT when an older udevd closed the connection without reading all the messages,
 * see udev_ctrl_send(), or another negative errno. */
int udev_ctrl_wait(struct udev_ctrl *uctrl, int timeout) {
        usec_t deadline = USEC_INFINITY;
        int r;

        if (!uctrl->batch)
                return 0;
        uctrl->batch = false;

        r = ctrl_send_msg(uctrl, _UDEV_CTRL_END_MESSAGES, 0, NULL);
        if (IN_SET(r, -EPIPE, -ECONNRESET))
                return -EPROTONOSUPPORT;
        if (r < 0)
                return r;

        if (timeout >= 0)
                deadline = usec_add(now(CLOCK_MONOTONIC), timeout * USEC_PER_SEC);

        for (;;) {
                struct pollfd pfd = { .fd = uctrl->sock, .events = POLLIN };
                char reply[16];
                int timeout_msec = -1;
                ssize_t n;

                if (deadline != USEC_INFINITY) {
                        usec_t t = now(CLOCK_MONOTONIC);

                        if (t >= deadline)
                                return -ETIMEDOUT;
                        timeout_msec = (int) MIN(DIV_ROUND_UP(deadline - t, USEC_PER_MSEC), (usec_t) INT_MAX);
                }

                r = poll(&pfd, 1, timeout_msec);
                if (r < 0) {
                        if (errno == EINTR)
                                continue;
                        return -errno;
                }
                if (r == 0)
                        return -ETIMEDOUT;

                n = recv(uctrl->sock, reply, sizeof(reply), MSG_DONTWAIT);
                if (n > 0)
                        /* replies */
                        continue;
                if (n == 0)
                        /* udevd read all the messages, handled them and closed the connection */
                        return 0;
                if (IN_SET(errno, EINTR, EAGAIN))
                        continue;
                if (errno == ECONNRESET)
                        /* udevd closed the connection without reading all the messages */
                        return -EPROTONOSUPPORT;
                return -errno;
        }
}

/* Tells the sender of a message that has a reply that udevd handled it, see ctrl_msg_type_has_reply(). */
int udev_ctrl_msg_reply(struct udev_ctrl_msg *ctrl_msg) {
        const char reply = 1;

        if (send(ctrl_msg->conn->sock, &reply, sizeof(reply), MSG_NOSIGNAL|MSG_DONTWAIT) < 0)
                return -errno;

        return 0;
}

/* Receives the next message of the connection, waiting for it at most timeout_msec milliseconds. Returns NULL on
 * an error, which is logged, and when the sender closed the connection, which is logged at debug level only. */
struct udev_ctrl_msg *udev_ctrl_receive_msg(struct udev_ctrl_connection *conn, int timeout_msec) {
        struct udev_ctrl_msg *uctrl_msg;
        ssize_t size;
        struct cmsghdr *cmsg;
        struct iovec iov;
        char cred_msg[CMSG_SPACE(sizeof(struct ucred))];
        struct msghdr smsg = {
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = cred_msg,
                .msg_controllen = sizeof(cred_msg),
        };
        struct ucred *cred;

        uctrl_msg = new0(struct udev_ctrl_msg, 1);
        if (uctrl_msg == NULL)
                return NULL;
        uctrl_msg->refcount = 1;
        uctrl_msg->conn = conn;
        udev_ctrl_connection_ref(conn);

        /* wait for the incoming message */
        for (;;) {
                struct pollfd pfd[1];
                int r;

                pfd[0].fd = conn->sock;
                pfd[0].events = POLLIN;

                r = poll(pfd, 1, timeout_msec);
                if (r  < 0) {
                        if (errno == EINTR)
                                continue;
                        goto err;
                } else if (r == 0) {
                        log_error("timeout waiting for ctrl message");
                        goto err;
                } else {
                        if (!(pfd[0].revents & POLLIN)) {
                                log_error_errno(errno, "ctrl connection error: %m");
                                goto err;
                        }
                }

                break;
        }

        iov.iov_base = &uctrl_msg->ctrl_msg_wire;
        iov.iov_len = sizeof(struct udev_ctrl_msg_wire);

        size = recvmsg(conn->sock, &smsg, 0);
        if (size <  0) {
                log_error_errno(errno, "unable to receive ctrl message: %m");
                goto err;
        }
        if (size == 0) {
                /* e.g. the sender exited without _UDEV_CTRL_END_MESSAGES, see udev_ctrl_send() */
                log_debug("ctrl connection closed by the sender");
                goto err;
        }

        cmsg_close_all(&smsg);

        if (size != sizeof(struct udev_ctrl_msg_wire) || (smsg.msg_flags & MSG_TRUNC)) {
                log_error("received message with invalid length, message ignored");
                goto err;
        }

        /* make sure that the string in the message is NUL terminated */
        uctrl_msg->ctrl_msg_wire.buf[sizeof(uctrl_msg->ctrl_msg_wire.buf) - 1] = '\0';

        cmsg = CMSG_FIRSTHDR(&smsg);
        cred = (struct ucred *) CMSG_DATA(cmsg);

        if (cmsg == NULL || cmsg->cmsg_type != SCM_CREDENTIALS) {
                log_error("no sender credentials received, message ignored");
                goto err;
        }

        if (cred->uid != 0) {
                log_error("sender uid="UID_FMT", message ignored", cred->uid);
                goto err;
        }

        if (uctrl_msg->ctrl_msg_wire.magic != UDEV_CTRL_MAGIC) {
                log_error("message magic 0x%08x doesn't match, ignore it", uctrl_msg->ctrl_msg_wire.magic);
                goto err;
        }

        /* e.g. from a newer udevadm, which then finds the message unsupported, if it expects a reply */
        if (uctrl_msg->ctrl_msg_wire.type < _UDEV_CTRL_END_MESSAGES ||
            uctrl_msg->ctrl_msg_wire.type >= _UDEV_CTRL_MSG_TYPE_MAX) {
                log_warning("received control message of unknown type %i, message ignored",
                            (int) uctrl_msg->ctrl_msg_wire.type);
                goto err;
        }

        return uctrl_msg;
err:
        udev_ctrl_msg_unref(uctrl_msg);
        return NULL;
}

struct udev_ctrl_msg *udev_ctrl_msg_unref(struct udev_ctrl_msg *ctrl_msg) {
        if (ctrl_msg && -- ctrl_msg->refcount == 0) {
                udev_ctrl_connection_unref(ctrl_msg->conn);
                free(ctrl_msg);
        }

        return NULL;
}

bool udev_ctrl_msg_is_begin(struct udev_ctrl_msg *ctrl_msg) {
        return ctrl_msg->ctrl_msg_wire.type == UDEV_CTRL_BEGIN_MESSAGES;
}

bool udev_ctrl_msg_is_end(struct udev_ctrl_msg *ctrl_msg) {
        return ctrl_msg->ctrl_msg_wire.type == _UDEV_CTRL_END_MESSAGES;
}

/* Returns 1 and the log level in *ret if this is a SET_LOG_LEVEL message, and 0 otherwise, so that the caller
 * can tell an invalid, e.g. negative, log level from another message. */
int udev_ctrl_get_set_log_level(struct udev_ctrl_msg *ctrl_msg, int *ret) {
        if (ctrl_msg->ctrl_msg_wire.type != UDEV_CTRL_SET_LOG_LEVEL)
                return 0;
        *ret = ctrl_msg->ctrl_msg_wire.intval;
        return 1;
}

int udev_ctrl_get_stop_exec_queue(struct udev_ctrl_msg *ctrl_msg) {
        if (ctrl_msg->ctrl_msg_wire.type == UDEV_CTRL_STOP_EXEC_QUEUE)
                return 1;
        return -1;
}

int udev_ctrl_get_start_exec_queue(struct udev_ctrl_msg *ctrl_msg) {
        if (ctrl_msg->ctrl_msg_wire.type == UDEV_CTRL_START_EXEC_QUEUE)
                return 1;
        return -1;
}

int udev_ctrl_get_reload(struct udev_ctrl_msg *ctrl_msg) {
        if (ctrl_msg->ctrl_msg_wire.type == UDEV_CTRL_RELOAD)
                return 1;
        return -1;
}

const char *udev_ctrl_get_set_env(struct udev_ctrl_msg *ctrl_msg) {
        if (ctrl_msg->ctrl_msg_wire.type == UDEV_CTRL_SET_ENV)
                return ctrl_msg->ctrl_msg_wire.buf;
        return NULL;
}

/* Returns 1 and the requested maximum, which may be invalid (negative), if the message is SET_CHILDREN_MAX,
 * otherwise 0. */
int udev_ctrl_get_set_children_max(struct udev_ctrl_msg *ctrl_msg, int *ret) {
        if (ctrl_msg->ctrl_msg_wire.type != UDEV_CTRL_SET_CHILDREN_MAX)
                return 0;
        *ret = ctrl_msg->ctrl_msg_wire.intval;
        return 1;
}

int udev_ctrl_get_ping(struct udev_ctrl_msg *ctrl_msg) {
        if (ctrl_msg->ctrl_msg_wire.type == UDEV_CTRL_PING)
                return 1;
        return -1;
}

int udev_ctrl_get_exit(struct udev_ctrl_msg *ctrl_msg) {
        if (ctrl_msg->ctrl_msg_wire.type == UDEV_CTRL_EXIT)
                return 1;
        return -1;
}

int udev_ctrl_get_set_trace(struct udev_ctrl_msg *ctrl_msg) {
        if (ctrl_msg->ctrl_msg_wire.type == UDEV_CTRL_SET_TRACE)
                return !!ctrl_msg->ctrl_msg_wire.intval;
        return -1;
}

int udev_ctrl_get_revert(struct udev_ctrl_msg *ctrl_msg) {
        if (ctrl_msg->ctrl_msg_wire.type == UDEV_CTRL_REVERT)
                return 1;
        return -1;
}
