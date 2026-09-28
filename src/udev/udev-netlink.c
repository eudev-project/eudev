/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Minimal rtnetlink support for the alternative names of network interfaces.
 *
 * eudev has no sd-netlink. This implements just what is needed to read, add and delete the
 * alternative names of a network interface (IFLA_PROP_LIST/IFLA_ALT_IFNAME, RTM_NEWLINKPROP and
 * RTM_DELLINKPROP, Linux 5.5 and later), following rtnl_get_ifname_full(),
 * rtnl_set_link_alternative_names(), rtnl_delete_link_alternative_names() and
 * rtnl_set_link_name() of systemd's sd-netlink. Older kernels refuse the requests with EOPNOTSUPP.
 *
 * The kernel processes an rtnetlink request while it is sent, i.e. its answer is queued on the socket
 * when sendto() returns. The receive timeout therefore only guards against a lost answer, and is
 * shorter than the 25 seconds of sd_netlink_call().
 */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "log.h"
#include "socket-util.h"
#include "strv.h"
#include "udev-netlink.h"
#include "util.h"

#ifndef IFLA_PROP_LIST
#define IFLA_PROP_LIST 52
#endif

#ifndef IFLA_ALT_IFNAME
#define IFLA_ALT_IFNAME 53
#endif

#ifndef RTM_NEWLINKPROP
#define RTM_NEWLINKPROP 108
#endif

#ifndef RTM_DELLINKPROP
#define RTM_DELLINKPROP 109
#endif

#define RTNL_TIMEOUT_SEC 5

/* Appends an attribute to the message in the buffer of the given size. Returns the attribute, or NULL if it
 * does not fit. */
static struct rtattr *rtnl_message_append(struct nlmsghdr *m, size_t size, unsigned short type,
                                          const void *data, size_t len) {
        struct rtattr *rta;
        size_t offset;

        offset = NLMSG_ALIGN(m->nlmsg_len);
        if (offset + RTA_SPACE(len) > size)
                return NULL;

        rta = (struct rtattr *) ((uint8_t *) m + offset);
        rta->rta_type = type;
        rta->rta_len = RTA_LENGTH(len);
        if (len > 0)
                memcpy(RTA_DATA(rta), data, len);

        m->nlmsg_len = offset + RTA_SPACE(len);
        return rta;
}

/* Allocates an RTM_*LINK* request for the interface, with room for the given number of bytes of attributes. */
static struct nlmsghdr *rtnl_message_new_link(uint16_t type, int ifindex, size_t attrs_size, size_t *ret_size) {
        struct ifinfomsg *ifi;
        struct nlmsghdr *m;
        size_t size;

        size = NLMSG_SPACE(sizeof(struct ifinfomsg)) + attrs_size;
        m = calloc(1, size);
        if (!m)
                return NULL;

        m->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
        m->nlmsg_type = type;
        m->nlmsg_flags = NLM_F_REQUEST;

        ifi = NLMSG_DATA(m);
        ifi->ifi_family = AF_UNSPEC;
        ifi->ifi_index = ifindex;

        *ret_size = size;
        return m;
}

/* Opens the netlink socket, unless *fd is one already. */
static int rtnl_open(int *fd) {
        _cleanup_close_ int s = -1;
        struct sockaddr_nl sa = {
                .nl_family = AF_NETLINK,
        };
        struct timeval tv = {
                .tv_sec = RTNL_TIMEOUT_SEC,
        };

        assert(fd);

        if (*fd >= 0)
                return 0;

        s = socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_ROUTE);
        if (s < 0)
                return -errno;

        if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
                return -errno;

        if (bind(s, (struct sockaddr *) &sa, sizeof(sa)) < 0)
                return -errno;

        *fd = s;
        s = -1;
        return 0;
}

/* Sends the request on the socket, which is opened if needed, and waits for the answer. When ret_reply is NULL,
 * an acknowledgement is requested, and the error it carries is returned. Otherwise the first reply of the given
 * type is returned in ret_reply. Answers to earlier requests, e.g. ones that timed out, are skipped. */
static int rtnl_call(int *fd, struct nlmsghdr *m, uint16_t reply_type, struct nlmsghdr **ret_reply) {
        struct sockaddr_nl sa = {
                .nl_family = AF_NETLINK,
        };
        static uint32_t serial = 0;
        uint32_t seq;
        int r;

        assert(m);

        r = rtnl_open(fd);
        if (r < 0)
                return r;

        seq = ++serial;
        if (seq == 0)
                seq = serial = 1;

        m->nlmsg_seq = seq;
        if (!ret_reply)
                m->nlmsg_flags |= NLM_F_ACK;

        if (sendto(*fd, m, m->nlmsg_len, 0, (struct sockaddr *) &sa, sizeof(sa)) < 0)
                return -errno;

        for (;;) {
                _cleanup_free_ void *buf = NULL;
                struct sockaddr_nl from = {};
                socklen_t fromlen = sizeof(from);
                struct nlmsghdr *h;
                ssize_t n;
                int len;

                /* get the size of the next datagram */
                n = recv(*fd, NULL, 0, MSG_PEEK|MSG_TRUNC);
                if (n < 0) {
                        if (errno == EINTR)
                                continue;
                        return IN_SET(errno, EAGAIN, EWOULDBLOCK) ? -ETIMEDOUT : -errno;
                }

                buf = malloc((size_t) n > sizeof(struct nlmsghdr) ? (size_t) n : sizeof(struct nlmsghdr));
                if (!buf)
                        return -ENOMEM;

                n = recvfrom(*fd, buf, n, 0, (struct sockaddr *) &from, &fromlen);
                if (n < 0) {
                        if (errno == EINTR)
                                continue;
                        return IN_SET(errno, EAGAIN, EWOULDBLOCK) ? -ETIMEDOUT : -errno;
                }

                /* only accept messages from the kernel */
                if (fromlen != sizeof(from) || from.nl_pid != 0)
                        continue;

                len = (int) n;
                for (h = buf; NLMSG_OK(h, len); h = NLMSG_NEXT(h, len)) {
                        if (h->nlmsg_seq != seq)
                                continue;

                        if (h->nlmsg_type == NLMSG_ERROR) {
                                const struct nlmsgerr *e = NLMSG_DATA(h);

                                if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr)))
                                        return -EBADMSG;

                                /* 0 is the acknowledgement, otherwise a negative errno */
                                if (e->error > 0)
                                        return -EBADMSG;
                                if (e->error < 0 || !ret_reply)
                                        return e->error;
                                continue;
                        }

                        if (ret_reply && h->nlmsg_type == reply_type) {
                                struct nlmsghdr *reply;

                                reply = malloc(h->nlmsg_len);
                                if (!reply)
                                        return -ENOMEM;

                                memcpy(reply, h, h->nlmsg_len);
                                *ret_reply = reply;
                                return 0;
                        }
                }
        }
}

int rtnl_get_link_alternative_names(int *fd, int ifindex, char ***ret) {
        _cleanup_free_ struct nlmsghdr *m = NULL, *reply = NULL;
        _cleanup_strv_free_ char **altnames = NULL;
        struct ifinfomsg *ifi;
        struct rtattr *rta;
        size_t size;
        int len, r;

        assert(ifindex > 0);
        assert(ret);

        m = rtnl_message_new_link(RTM_GETLINK, ifindex, 0, &size);
        if (!m)
                return -ENOMEM;

        r = rtnl_call(fd, m, RTM_NEWLINK, &reply);
        if (r == -EINVAL)
                return -ENODEV; /* The device does not exist */
        if (r < 0)
                return r;

        if (reply->nlmsg_len < NLMSG_LENGTH(sizeof(struct ifinfomsg)))
                return -EBADMSG;

        ifi = NLMSG_DATA(reply);
        if (ifi->ifi_index != ifindex)
                return -EIO;

        len = reply->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg));
        for (rta = (struct rtattr *) ((uint8_t *) ifi + NLMSG_ALIGN(sizeof(struct ifinfomsg)));
             RTA_OK(rta, len);
             rta = RTA_NEXT(rta, len)) {
                struct rtattr *p;
                int plen;

                if ((rta->rta_type & NLA_TYPE_MASK) != IFLA_PROP_LIST)
                        continue;

                plen = RTA_PAYLOAD(rta);
                for (p = RTA_DATA(rta); RTA_OK(p, plen); p = RTA_NEXT(p, plen)) {
                        char *s;

                        if ((p->rta_type & NLA_TYPE_MASK) != IFLA_ALT_IFNAME)
                                continue;

                        s = strndup(RTA_DATA(p), RTA_PAYLOAD(p));
                        if (!s)
                                return -ENOMEM;

                        r = strv_consume(&altnames, s);
                        if (r < 0)
                                return r;
                }
        }

        *ret = altnames;
        altnames = NULL;
        return 0;
}

static int rtnl_update_link_alternative_names(int *fd, uint16_t nlmsg_type, int ifindex, char * const *alternative_names) {
        _cleanup_free_ struct nlmsghdr *m = NULL;
        char * const *a;
        struct rtattr *list;
        size_t size, attrs_size;

        assert(ifindex > 0);
        assert(IN_SET(nlmsg_type, RTM_NEWLINKPROP, RTM_DELLINKPROP));

        if (strv_isempty(alternative_names))
                return 0;

        attrs_size = RTA_SPACE(0);
        STRV_FOREACH(a, alternative_names)
                attrs_size += RTA_SPACE(strlen(*a) + 1);

        m = rtnl_message_new_link(nlmsg_type, ifindex, attrs_size, &size);
        if (!m)
                return -ENOMEM;

        list = rtnl_message_append(m, size, IFLA_PROP_LIST | NLA_F_NESTED, NULL, 0);
        if (!list)
                return -ENOBUFS;

        STRV_FOREACH(a, alternative_names)
                if (!rtnl_message_append(m, size, IFLA_ALT_IFNAME, *a, strlen(*a) + 1))
                        return -ENOBUFS;

        list->rta_len = (uint8_t *) m + m->nlmsg_len - (uint8_t *) list;

        return rtnl_call(fd, m, 0, NULL);
}

int rtnl_set_link_alternative_names(int *fd, int ifindex, char * const *alternative_names) {
        return rtnl_update_link_alternative_names(fd, RTM_NEWLINKPROP, ifindex, alternative_names);
}

int rtnl_delete_link_alternative_names(int *fd, int ifindex, char * const *alternative_names) {
        return rtnl_update_link_alternative_names(fd, RTM_DELLINKPROP, ifindex, alternative_names);
}

/* Like the second half of rtnl_set_link_name() of systemd: assigns the alternative names that are valid and
 * not in assigned_names, the alternative names the interface has, as read with
 * rtnl_get_link_alternative_names() before, e.g. before renaming the interface, as systemd does. That
 * avoids reading them again. Failures to assign the names are logged at debug level and ignored, as by
 * systemd; only failures to allocate memory are returned. */
int rtnl_append_link_alternative_names(int *fd, int ifindex, char * const *assigned_names,
                                       char * const *alternative_names) {
        _cleanup_strv_free_ char **new_altnames = NULL;
        char * const *a;
        int r;

        assert(ifindex > 0);

        if (strv_isempty(alternative_names))
                return 0;

        /* Filter out already assigned names from requested alternative names. Also, dedup the request. */
        STRV_FOREACH(a, alternative_names) {
                if (strv_contains(assigned_names, *a))
                        continue;

                if (strv_contains(new_altnames, *a))
                        continue;

                if (!ifname_valid_full(*a, IFNAME_VALID_ALTERNATIVE))
                        continue;

                r = strv_extend(&new_altnames, *a);
                if (r < 0)
                        return r;
        }

        if (strv_isempty(new_altnames))
                return 0;

        strv_sort(new_altnames);

        /* Finally, assign alternative names. */
        r = rtnl_set_link_alternative_names(fd, ifindex, new_altnames);
        if (r == -EEXIST) /* Already assigned to another interface? */
                STRV_FOREACH(a, new_altnames) {
                        char *one[2] = { *a, NULL };

                        r = rtnl_set_link_alternative_names(fd, ifindex, one);
                        if (r < 0)
                                log_debug_errno(r, "Failed to assign '%s' as an alternative name on network interface %i, ignoring: %m",
                                                *a, ifindex);
                }
        else if (r < 0)
                log_debug_errno(r, "Failed to assign alternative names on network interface %i, ignoring: %m", ifindex);

        return 0;
}
