/***
  This file is part of eudev.

  eudev is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  eudev is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with eudev; If not, see <http://www.gnu.org/licenses/>.
***/

#pragma once

/* Makes all mounts of the mount namespace of the caller, which it has created with unshare(CLONE_NEWNS),
 * private, so that no mount in it shows in the namespace it was created from, e.g. that of the host, and
 * back. Also in a plain chroot, where / is not a mount point, unless the mount that / is in is shared.
 * Returns 0, or a negative errno after printing why not to stderr. */
int make_mounts_private(void);
