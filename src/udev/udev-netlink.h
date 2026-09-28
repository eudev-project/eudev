/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* Minimal rtnetlink support for the alternative names of network interfaces (Linux 5.5 and later), like the
 * functions of the same names of systemd's sd-netlink.
 *
 * fd is the netlink socket to use. If *fd is negative, the socket is opened by the first call that needs it
 * and stored there, so that it can be reused, e.g. by all events that a udevd worker processes, like systemd
 * does with the sd_netlink object of its udev workers. The caller closes it with safe_close(). */
int rtnl_get_link_alternative_names(int *fd, int ifindex, char ***ret);
int rtnl_set_link_alternative_names(int *fd, int ifindex, char * const *alternative_names);
int rtnl_delete_link_alternative_names(int *fd, int ifindex, char * const *alternative_names);
int rtnl_append_link_alternative_names(int *fd, int ifindex, char * const *assigned_names,
                                       char * const *alternative_names);
