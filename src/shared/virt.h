/***
  This file is part of eudev, forked from systemd.

  Copyright 2011 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#pragma once

int detect_container(const char **id);

/* Like systemd's running_in_chroot(): > 0 if the root directory is not the one of PID 1, or if /proc
 * is not mounted (unless this is PID 1), 0 if it is, and a negative error if that cannot be
 * determined, e.g. -ENOSYS with a /proc that has no /proc/1. $UDEV_IN_CHROOT, or else
 * $SYSTEMD_IN_CHROOT, overrides the check with a boolean. Otherwise, the deprecated
 * $SYSTEMD_IGNORE_CHROOT, when true, makes it 0. */
int running_in_chroot(void);
