#  -*- Mode: makefile; indent-tabs-mode: t -*-
#
#  This file is part of systemd.
#
#  Copyright 2010-2012 Lennart Poettering
#  Copyright 2010-2012 Kay Sievers
#  Copyright 2013 Zbigniew Jędrzejewski-Szmek
#  Copyright 2013 David Strauss
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.
#
#  systemd is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with systemd; If not, see <http://www.gnu.org/licenses/>.

ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
#AM_MAKEFLAGS = --no-print-directory
#AUTOMAKE_OPTIONS = color-tests parallel-tests

LIBUDEV_CURRENT=7
LIBUDEV_REVISION=4
LIBUDEV_AGE=6

# Dirs of external packages
pkgconfigdatadir=$(datadir)/pkgconfig
pkgconfiglibdir=$(libdir)/pkgconfig

# Our own, non-special dirs
udevlibexecdir=$(prefix)/lib/udev
udevrulesdir=$(udevlibexecdir)/rules.d
udevhwdbdir=$(udevlibexecdir)/hwdb.d

EXTRA_DIST =
noinst_DATA =
noinst_LTLIBRARIES =
BUILT_SOURCES =
include_HEADERS =
lib_LTLIBRARIES =
pkgconfiglib_DATA =
dist_udevrules_DATA =
pkgconfigdata_DATA =
tests =
manual_tests =
check_DATA =

noinst_PROGRAMS = $(manual_tests) $(tests) $(unsafe_tests)
TESTS = $(tests) $(unsafe_tests)

in_files = $(filter %.in,$(EXTRA_DIST))
in_in_files = $(filter %.in.in, $(in_files))
m4_files = $(filter %.m4,$(EXTRA_DIST) $(in_files:.m4.in=.m4))

CLEANFILES = $(BUILT_SOURCES) \
	$(pkgconfigdata_DATA) \
	$(pkgconfiglib_DATA) \
	$(in_files:.in=) $(in_in_files:.in.in=) \
	$(m4_files:.m4=)

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-DUDEVLIBEXECDIR=\"$(udevlibexecdir)\" \
	-I $(top_srcdir)/src \
	-I $(top_builddir)/src/basic \
	-I $(top_srcdir)/src/basic \
	-I $(top_srcdir)/src/shared \
	-I $(top_builddir)/src/shared \
	-I $(top_srcdir)/src/systemd \
	-I $(top_srcdir)/src/libudev \
	-I $(top_srcdir)/src/udev \
	-I $(top_builddir)/src/udev \
	-I $(top_srcdir)/src/libsystemd/sd-event \
	-I $(top_srcdir)/src/libsystemd/sd-netlink \
	-I $(top_srcdir)/src/libsystemd/sd-hwdb \
	-I $(top_srcdir)/src/libsystemd/sd-device \
	$(OUR_CPPFLAGS)

AM_CFLAGS = $(OUR_CFLAGS)
AM_LDFLAGS = $(OUR_LDFLAGS)

# ------------------------------------------------------------------------------
define move-to-rootlibdir
	if test "$(libdir)" != "$(rootlibdir)"; then \
		$(MKDIR_P) $(DESTDIR)$(rootlibdir) && \
		so_img_name=$$(readlink $(DESTDIR)$(libdir)/$$libname) && \
		rm -f $(DESTDIR)$(libdir)/$$libname && \
		$(LN_S) --relative -f $(DESTDIR)$(rootlibdir)/$$so_img_name $(DESTDIR)$(libdir)/$$libname && \
		mv $(DESTDIR)$(libdir)/$$libname.* $(DESTDIR)$(rootlibdir); \
	fi
endef

INSTALL_DIRS =

SYSTEM_UNIT_ALIASES =
USER_UNIT_ALIASES =
GENERAL_ALIASES =

define add-wants
	[ -z "$$what" ] || ( \
	  dir=$(DESTDIR)$$dir/$$wants.wants && \
	  $(MKDIR_P) -m 0755 $$dir && \
	  cd $$dir && \
	  rm -f $$what && \
	  for i in $$what; do $(LN_S) ../$$i . || exit $$? ; done )
endef

install-directories-hook:
	$(MKDIR_P) $(addprefix $(DESTDIR),$(INSTALL_DIRS))

define install-aliases
	while [ -n "$$1" ]; do \
		$(MKDIR_P) `dirname $(DESTDIR)$$dir/$$2` && \
		rm -f $(DESTDIR)$$dir/$$2 && \
		$(LN_S) $$1 $(DESTDIR)$$dir/$$2 && \
		shift 2 || exit $$?; \
	done
endef

define install-relative-aliases
	while [ -n "$$1" ]; do \
		$(MKDIR_P) `dirname $(DESTDIR)$$dir/$$2` && \
		rm -f $(DESTDIR)$$dir/$$2 && \
		$(LN_S) --relative $(DESTDIR)$$1 $(DESTDIR)$$dir/$$2 && \
		shift 2 || exit $$?; \
	done
endef

# ------------------------------------------------------------------------------
AM_V_M4 = $(AM_V_M4_$(V))
AM_V_M4_ = $(AM_V_M4_$(AM_DEFAULT_VERBOSITY))
AM_V_M4_0 = @echo "  M4      " $@;

AM_V_XSLT = $(AM_V_XSLT_$(V))
AM_V_XSLT_ = $(AM_V_XSLT_$(AM_DEFAULT_VERBOSITY))
AM_V_XSLT_0 = @echo "  XSLT    " $@;

AM_V_GPERF = $(AM_V_GPERF_$(V))
AM_V_GPERF_ = $(AM_V_GPERF_$(AM_DEFAULT_VERBOSITY))
AM_V_GPERF_0 = @echo "  GPERF   " $@;

AM_V_LN = $(AM_V_LN_$(V))
AM_V_LN_ = $(AM_V_LN_$(AM_DEFAULT_VERBOSITY))
AM_V_LN_0 = @echo "  LN      " $@;

AM_V_RM = $(AM_V_RM_$(V))
AM_V_RM_ = $(AM_V_RM_$(AM_DEFAULT_VERBOSITY))
AM_V_RM_0 = @echo "  RM      " $@;

EXTRA_DIST += \
	LICENSE.LGPL2.1 \
	LICENSE.GPL2 \
	README.md \
	autogen.sh \
	.vimrc

# ------------------------------------------------------------------------------

MANPAGES =
MANPAGES_ALIAS =

include Makefile-man.am

.PHONY: man update-man-list
man: $(MANPAGES) $(MANPAGES_ALIAS) $(HTML_FILES) $(HTML_ALIAS)

XML_FILES = \
	${patsubst %.1,%.xml,${patsubst %.3,%.xml,${patsubst %.5,%.xml,${patsubst %.7,%.xml,${patsubst %.8,%.xml,$(MANPAGES)}}}}}
HTML_FILES = \
	${XML_FILES:.xml=.html}
HTML_ALIAS = \
	${patsubst %.1,%.html,${patsubst %.3,%.html,${patsubst %.5,%.html,${patsubst %.7,%.html,${patsubst %.8,%.html,$(MANPAGES_ALIAS)}}}}}

if ENABLE_MANPAGES
man_MANS = \
	$(MANPAGES) \
	$(MANPAGES_ALIAS)

noinst_DATA += \
	$(HTML_FILES) \
	$(HTML_ALIAS)
endif

CLEANFILES += \
	$(man_MANS) \
	$(HTML_FILES) \
	$(HTML_ALIAS)

docs/html/man:
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_LN)$(LN_S) -f ../../man $@

man/index.html: man/systemd.index.html
	$(AM_V_LN)$(LN_S) -f systemd.index.html $@

if HAVE_PYTHON
noinst_DATA += \
	man/index.html
endif

CLEANFILES += \
	man/index.html

XML_GLOB = $(wildcard $(top_srcdir)/man/*.xml)
NON_INDEX_XML_FILES = $(filter-out man/systemd.index.xml,$(XML_FILES))
SOURCE_XML_FILES = ${patsubst %,$(top_srcdir)/%,$(filter-out man/systemd.directives.xml,$(NON_INDEX_XML_FILES))}

# This target should only be run manually. It recreates Makefile-man.am
# file in the source directory based on all man/*.xml files. Run it after
# adding, removing, or changing the conditional in a man page.
update-man-list: $(top_srcdir)/tools/make-man-rules.py $(XML_GLOB) man/custom-entities.ent
	$(AM_V_GEN)$(PYTHON) $< $(XML_GLOB) > $(top_srcdir)/Makefile-man.tmp
	$(AM_V_at)mv $(top_srcdir)/Makefile-man.tmp $(top_srcdir)/Makefile-man.am
	@echo "Makefile-man.am has been regenerated"

man/systemd.index.xml: $(top_srcdir)/tools/make-man-index.py $(NON_INDEX_XML_FILES)
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(PYTHON) $< $@ $(filter-out $<,$^)

man/systemd.directives.xml: $(top_srcdir)/tools/make-directive-index.py man/custom-entities.ent $(SOURCE_XML_FILES)
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(PYTHON) $< $@ $(SOURCE_XML_FILES)

CLEANFILES += \
	man/systemd.index.xml \
	man/systemd.directives.xml

EXTRA_DIST += \
	$(filter-out man/systemd.directives.xml man/systemd.index.xml,$(XML_FILES)) \
	tools/make-man-index.py \
	tools/make-man-rules.py \
	tools/make-directive-index.py \
	tools/xml_helper.py

# ------------------------------------------------------------------------------
noinst_LTLIBRARIES += \
	libbasic.la

libbasic_la_SOURCES = \
	src/basic/missing.h \
	src/basic/missing_syscall.h \
	src/basic/raw-clone.h \
	src/basic/conf-files.c \
	src/basic/conf-files.h \
	src/basic/stdio-util.h \
	src/basic/hostname-util.h \
	src/basic/hostname-util.c \
	src/basic/unit-name.c \
	src/basic/unit-name.h \
	src/basic/ioprio.h \
	src/basic/special.h \
	src/basic/list.h \
	src/basic/unaligned.h \
	src/basic/macro.h \
	src/basic/def.h \
	src/basic/sparse-endian.h \
	src/basic/refcnt.h \
	src/basic/util.c \
	src/basic/util.h \
	src/basic/io-util.c \
	src/basic/io-util.h \
	src/basic/string-util.c \
	src/basic/string-util.h \
	src/basic/fd-util.c \
	src/basic/fd-util.h \
	src/basic/parse-util.c \
	src/basic/parse-util.h \
	src/basic/user-util.c \
	src/basic/user-util.h \
	src/basic/dirent-util.c \
	src/basic/dirent-util.h \
	src/basic/xattr-util.c \
	src/basic/xattr-util.h \
	src/basic/proc-cmdline.c \
	src/basic/proc-cmdline.h \
	src/basic/fs-util.c \
	src/basic/fs-util.h \
        src/basic/syslog-util.c \
        src/basic/syslog-util.h \
	src/basic/stat-util.c \
	src/basic/stat-util.h \
	src/basic/mount-util.c \
	src/basic/mount-util.h \
	src/basic/hexdecoct.c \
	src/basic/hexdecoct.h \
	src/basic/glob-util.h \
	src/basic/glob-util.c \
	src/basic/extract-word.c \
	src/basic/extract-word.h \
	src/basic/escape.c \
	src/basic/escape.h \
	src/basic/cpu-set-util.c \
	src/basic/cpu-set-util.h \
	src/basic/path-util.c \
	src/basic/path-util.h \
	src/basic/time-util.c \
	src/basic/time-util.h \
	src/basic/umask-util.h \
	src/basic/signal-util.c \
	src/basic/signal-util.h \
	src/basic/string-table.c \
	src/basic/string-table.h \
	src/basic/mempool.c \
	src/basic/mempool.h \
	src/basic/hashmap.c \
	src/basic/hashmap.h \
	src/basic/hash-funcs.c \
	src/basic/hash-funcs.h \
	src/basic/siphash24.c \
	src/basic/siphash24.h \
	src/basic/set.h \
	src/basic/prioq.c \
	src/basic/prioq.h \
	src/basic/strv.c \
	src/basic/strv.h \
	src/basic/strbuf.c \
	src/basic/strbuf.h \
	src/basic/strxcpyx.c \
	src/basic/strxcpyx.h \
	src/basic/log.c \
	src/basic/log.h \
	src/basic/bus-label.c \
	src/basic/bus-label.h \
	src/basic/virt.c \
	src/basic/virt.h \
	src/basic/smack-util.c \
	src/basic/smack-util.h \
	src/basic/device-nodes.c \
	src/basic/device-nodes.h \
	src/basic/utf8.c \
	src/basic/utf8.h \
	src/basic/gunicode.c \
	src/basic/gunicode.h \
	src/basic/socket-util.c \
	src/basic/socket-util.h \
	src/basic/fileio.c \
	src/basic/fileio.h \
	src/basic/MurmurHash2.c \
	src/basic/MurmurHash2.h \
	src/basic/mkdir.c \
	src/basic/mkdir.h \
	src/basic/cgroup-util.c \
	src/basic/cgroup-util.h \
	src/basic/terminal-util.c \
	src/basic/terminal-util.h \
	src/basic/login-util.h \
	src/basic/login-util.c \
	src/basic/process-util.c \
	src/basic/process-util.h \
	src/basic/random-util.c \
	src/basic/random-util.h \
	src/basic/verbs.c \
	src/basic/verbs.h \
	src/basic/sigbus.c \
	src/basic/sigbus.h \
	src/basic/build.h \
	src/basic/socket-label.c \
	src/basic/label.c \
	src/basic/label.h \
	src/basic/selinux-util.c \
	src/basic/selinux-util.h \
	src/basic/mkdir-label.c \
	src/basic/alloc-util.h \
	src/basic/alloc-util.c \
	src/basic/formats-util.h

nodist_libbasic_la_SOURCES = \
	src/basic/af-from-name.h \
	src/basic/af-to-name.h \
	src/basic/arphrd-from-name.h \
	src/basic/arphrd-to-name.h \
	src/basic/cap-from-name.h \
	src/basic/cap-to-name.h

libbasic_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(SELINUX_CFLAGS) \
	$(CAP_CFLAGS) \
	-pthread

libbasic_la_LIBADD = \
	$(SELINUX_LIBS) \
	$(CAP_LIBS) \
	-lrt \
	-lm

# -----------------------------------------------------------------------------
noinst_LTLIBRARIES += \
	libshared.la

libshared_la_SOURCES = \
	src/shared/gpt.h \
	src/shared/udev-util.h \
	src/shared/efivars.c \
	src/shared/efivars.h \
	src/shared/dev-setup.c \
	src/shared/dev-setup.h \
	src/shared/sysctl-util.c \
	src/shared/sysctl-util.h

libshared_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(LIBIDN_CFLAGS)

libshared_la_LIBADD = \
	libsystemd-internal.la \
	libudev-internal.la \
	$(LIBIDN_LIBS)

# ------------------------------------------------------------------------------
BUILT_SOURCES += \
	$(gperf_gperf_m4_sources:-gperf.gperf.m4=-gperf.c) \
	$(gperf_gperf_m4_sources:-gperf.gperf.m4=-gperf-nulstr.c) \
	$(gperf_gperf_sources:-gperf.gperf=-gperf.c) \
	$(gperf_txt_sources:-list.txt=-from-name.h) \
	$(filter-out %keyboard-keys-to-name.h,$(gperf_txt_sources:-list.txt=-to-name.h))

CLEANFILES += \
	$(gperf_txt_sources:-list.txt=-from-name.gperf)
DISTCLEANFILES = \
	$(gperf_txt_sources)

EXTRA_DIST += \
	$(gperf_gperf_m4_sources) \
	$(gperf_gperf_sources)

CLEANFILES += \
	$(gperf_txt_sources)

%-from-name.gperf: %-list.txt
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(AWK) 'BEGIN{ print "struct $(notdir $*)_name { const char* name; int id; };"; print "%null-strings"; print "%%";} { printf "%s, %s\n", $$1, $$1 }' <$< >$@

%-from-name.h: %-from-name.gperf
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GPERF)$(GPERF) -L ANSI-C -t --ignore-case -N lookup_$(notdir $*) -H hash_$(notdir $*)_name -p -C <$< >$@

audit_list_includes = -include linux/audit.h -include missing.h

# ------------------------------------------------------------------------------
libsystemd_internal_la_SOURCES = \
	src/systemd/_sd-common.h \
	src/systemd/sd-event.h \
	src/systemd/sd-netlink.h \
	src/systemd/sd-id128.h \
	src/systemd/sd-daemon.h \
	src/systemd/sd-hwdb.h \
	src/systemd/sd-device.h \
	src/systemd/sd-messages.h \
	src/libsystemd/sd-event/sd-event.c \
	src/libsystemd/sd-netlink/sd-netlink.c \
	src/libsystemd/sd-netlink/netlink-internal.h \
	src/libsystemd/sd-netlink/netlink-message.c \
	src/libsystemd/sd-netlink/netlink-socket.c \
	src/libsystemd/sd-netlink/rtnl-message.c \
	src/libsystemd/sd-netlink/netlink-types.h \
	src/libsystemd/sd-netlink/netlink-types.c \
	src/libsystemd/sd-netlink/netlink-util.h \
	src/libsystemd/sd-netlink/netlink-util.c \
	src/libsystemd/sd-id128/sd-id128.c \
	src/libsystemd/sd-daemon/sd-daemon.c \
	src/libsystemd/sd-hwdb/sd-hwdb.c \
	src/libsystemd/sd-hwdb/hwdb-util.h \
	src/libsystemd/sd-hwdb/hwdb-internal.h \
	src/libsystemd/sd-device/device-internal.h \
	src/libsystemd/sd-device/device-util.h \
	src/libsystemd/sd-device/device-enumerator.c \
	src/libsystemd/sd-device/device-enumerator-private.h \
	src/libsystemd/sd-device/sd-device.c \
	src/libsystemd/sd-device/device-private.c \
	src/libsystemd/sd-device/device-private.h

libsystemd_internal_la_LIBADD = \
	libbasic.la \
	-lresolv

noinst_LTLIBRARIES += \
	libsystemd-internal.la

# ------------------------------------------------------------------------------
include_HEADERS += \
	src/libudev/libudev.h

lib_LTLIBRARIES += \
	libudev.la

libudev_la_SOURCES =\
	src/libudev/libudev.sym \
	src/libudev/libudev-private.h \
	src/libudev/libudev-device-internal.h \
	src/libudev/libudev.c \
	src/libudev/libudev-list.c \
	src/libudev/libudev-util.c \
	src/libudev/libudev-device.c \
	src/libudev/libudev-device-private.c \
	src/libudev/libudev-enumerate.c \
	src/libudev/libudev-monitor.c \
	src/libudev/libudev-queue.c \
	src/libudev/libudev-hwdb.c

libudev_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-version-info $(LIBUDEV_CURRENT):$(LIBUDEV_REVISION):$(LIBUDEV_AGE) \
	-Wl,--version-script=$(top_srcdir)/src/libudev/libudev.sym

libudev_la_LIBADD = \
	libsystemd-internal.la

pkgconfiglib_DATA += \
	src/libudev/libudev.pc

EXTRA_DIST += \
	src/libudev/libudev.pc.in

# ------------------------------------------------------------------------------
noinst_LTLIBRARIES += \
	libudev-internal.la

libudev_internal_la_SOURCES =\
	$(libudev_la_SOURCES)

# ------------------------------------------------------------------------------
INSTALL_DIRS += \
	$(sysconfdir)/udev/rules.d

dist_udevrules_DATA += \
	rules/50-udev-default.rules \
	rules/60-block.rules \
	rules/60-drm.rules \
	rules/60-evdev.rules \
	rules/60-persistent-storage-tape.rules \
	rules/60-persistent-input.rules \
	rules/60-persistent-alsa.rules \
	rules/60-persistent-storage.rules \
	rules/60-serial.rules \
	rules/64-btrfs.rules \
	rules/70-mouse.rules \
	rules/75-net-description.rules \
	rules/78-sound-card.rules \
	rules/80-net-setup-link.rules

udevconfdir = $(sysconfdir)/udev
dist_udevconf_DATA = \
	src/udev/udev.conf

pkgconfigdata_DATA += \
	src/udev/udev.pc

EXTRA_DIST += \
	rules/99-systemd.rules.in \
	src/udev/udev.pc.in

bin_PROGRAMS = \
	udevadm

udevlibexec_PROGRAMS = \
	udevd

noinst_LTLIBRARIES += \
	libudev-core.la

src/udev/keyboard-keys-list.txt:
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(CPP) $(CFLAGS) $(AM_CPPFLAGS) $(CPPFLAGS) -dM -include linux/input.h - < /dev/null | $(AWK) '/^#define[ \t]+KEY_[^ ]+[ \t]+[0-9K]/ { if ($$2 != "KEY_MAX") { print $$2 } }' > $@

src/udev/keyboard-keys-from-name.gperf: src/udev/keyboard-keys-list.txt
	$(AM_V_GEN)$(AWK) 'BEGIN{ print "struct key { const char* name; unsigned short id; };"; print "%null-strings"; print "%%";} { print tolower(substr($$1 ,5)) ", " $$1 }' < $< > $@

src/udev/keyboard-keys-from-name.h: src/udev/keyboard-keys-from-name.gperf
	$(AM_V_GPERF)$(GPERF) -L ANSI-C -t -N keyboard_lookup_key -H hash_key_name -p -C < $< > $@

gperf_txt_sources = \
	src/udev/keyboard-keys-list.txt

libudev_core_la_SOURCES = \
	src/udev/udev.h \
	src/udev/udev-event.c \
	src/udev/udev-watch.c \
	src/udev/udev-node.c \
	src/udev/udev-rules.c \
	src/udev/udev-ctrl.c \
	src/udev/udev-builtin.c \
	src/udev/udev-builtin-btrfs.c \
	src/udev/udev-builtin-hwdb.c \
	src/udev/udev-builtin-input_id.c \
	src/udev/udev-builtin-keyboard.c \
	src/udev/udev-builtin-net_id.c \
	src/udev/udev-builtin-path_id.c \
	src/udev/udev-builtin-usb_id.c

nodist_libudev_core_la_SOURCES = \
	src/udev/keyboard-keys-from-name.h

libudev_core_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(BLKID_CFLAGS) \
	$(KMOD_CFLAGS)

libudev_core_la_LIBADD = \
	libshared.la \
	$(BLKID_LIBS) \
	$(KMOD_LIBS)

if HAVE_KMOD
libudev_core_la_SOURCES += \
	src/udev/udev-builtin-kmod.c

dist_udevrules_DATA += \
	rules/80-drivers.rules
endif

if HAVE_BLKID
libudev_core_la_SOURCES += \
	src/udev/udev-builtin-blkid.c
endif

udevd_SOURCES = \
	src/udev/udevd.c

udevd_LDADD = \
	libudev-core.la

udevadm_SOURCES = \
	src/udev/udevadm.c \
	src/udev/udevadm-info.c \
	src/udev/udevadm-control.c \
	src/udev/udevadm-monitor.c \
	src/udev/udevadm-hwdb.c \
	src/udev/udevadm-settle.c \
	src/udev/udevadm-trigger.c \
	src/udev/udevadm-test.c \
	src/udev/udevadm-test-builtin.c \
	src/udev/udevadm-util.c \
	src/udev/udevadm-util.h

udevadm_LDADD = \
	libudev-core.la

# ------------------------------------------------------------------------------
if ENABLE_HWDB
INSTALL_DIRS += \
	$(sysconfdir)/udev/hwdb.d

systemd_hwdb_SOURCES = \
	src/libsystemd/sd-hwdb/hwdb-internal.h \
	src/hwdb/hwdb.c

systemd_hwdb_LDADD = \
	libshared.la

bin_PROGRAMS += \
	systemd-hwdb

dist_udevhwdb_DATA = \
	hwdb/20-pci-vendor-model.hwdb \
	hwdb/20-pci-classes.hwdb \
	hwdb/20-usb-vendor-model.hwdb \
	hwdb/20-usb-classes.hwdb \
	hwdb/20-sdio-vendor-model.hwdb \
	hwdb/20-sdio-classes.hwdb \
	hwdb/20-bluetooth-vendor-product.hwdb \
	hwdb/20-acpi-vendor.hwdb \
	hwdb/20-OUI.hwdb \
	hwdb/20-net-ifname.hwdb \
	hwdb/60-evdev.hwdb \
	hwdb/60-keyboard.hwdb \
	hwdb/70-mouse.hwdb \
	hwdb/70-pointingstick.hwdb
endif

EXTRA_DIST += \
	hwdb/ids-update.pl \
	hwdb/sdio.ids

# ------------------------------------------------------------------------------
TESTS += \
	test/udev-test.pl

TESTS += \
	test/rule-syntax-check.py

tests += \
	test-libudev

manual_tests += \
	test-udev

test_libudev_SOURCES = \
	src/test/test-libudev.c

test_libudev_LDADD = \
	libshared.la

test_udev_SOURCES = \
	src/test/test-udev.c

test_udev_LDADD = \
	libudev-core.la  \
	$(BLKID_LIBS) \
	$(KMOD_LIBS)

check_DATA += \
	test/sys

# packed sysfs test tree
test/sys: test/sys.tar.xz
	-rm -rf test/sys
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)tar -C test/ -xJf $(top_srcdir)/test/sys.tar.xz
	-touch test/sys

test-sys-distclean:
	-rm -rf test/sys

EXTRA_DIST += \
	test/sys.tar.xz \
	test/udev-test.pl \
	test/rule-syntax-check.py

# ------------------------------------------------------------------------------
ata_id_SOURCES = \
	src/udev/ata_id/ata_id.c

ata_id_LDADD = \
	libshared.la

udevlibexec_PROGRAMS += \
	ata_id

# ------------------------------------------------------------------------------
cdrom_id_SOURCES = \
	src/udev/cdrom_id/cdrom_id.c

cdrom_id_LDADD = \
	libshared.la

udevlibexec_PROGRAMS += \
	cdrom_id

dist_udevrules_DATA += \
	rules/60-cdrom_id.rules

# ------------------------------------------------------------------------------
collect_SOURCES = \
	src/udev/collect/collect.c

collect_LDADD = \
	libshared.la

udevlibexec_PROGRAMS += \
	collect

# ------------------------------------------------------------------------------
scsi_id_SOURCES =\
	src/udev/scsi_id/scsi_id.c \
	src/udev/scsi_id/scsi_serial.c \
	src/udev/scsi_id/scsi.h \
	src/udev/scsi_id/scsi_id.h

scsi_id_LDADD = \
	libshared.la

udevlibexec_PROGRAMS += \
	scsi_id

EXTRA_DIST += \
	src/udev/scsi_id/README

# ------------------------------------------------------------------------------
v4l_id_SOURCES = \
	src/udev/v4l_id/v4l_id.c

v4l_id_LDADD = \
	libshared.la

udevlibexec_PROGRAMS += \
	v4l_id

dist_udevrules_DATA += \
	rules/60-persistent-v4l.rules

# ------------------------------------------------------------------------------
mtd_probe_SOURCES =  \
	src/udev/mtd_probe/mtd_probe.c \
	src/udev/mtd_probe/mtd_probe.h \
	src/udev/mtd_probe/probe_smartmedia.c

dist_udevrules_DATA += \
	rules/75-probe_mtd.rules

udevlibexec_PROGRAMS += \
	mtd_probe

# ------------------------------------------------------------------------------
substitutions = \
       '|prefix=$(prefix)|' \
       '|exec_prefix=$(exec_prefix)|' \
       '|libdir=$(libdir)|' \
       '|includedir=$(includedir)|' \
       '|VERSION=$(VERSION)|' \
       '|udevlibexecdir=$(udevlibexecdir)|'

SED_PROCESS = \
	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && \
	$(SED) $(subst '|,-e 's|@,$(subst =,\@|,$(subst |',|g',$(substitutions)))) \
		< $< > $@

man/%: man/%.in
	$(SED_PROCESS)

%.pc: %.pc.in
	$(SED_PROCESS)

%.conf: %.conf.in
	$(SED_PROCESS)

src/%.policy.in: src/%.policy.in.in
	$(SED_PROCESS)

%.rules: %.rules.in
	$(SED_PROCESS)

%.conf: %.conf.in
	$(SED_PROCESS)

%.sh: %.sh.in
	$(SED_PROCESS)
	$(AM_V_GEN)chmod +x $@

src/%.c: src/%.gperf
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GPERF)$(GPERF) < $< > $@

src/%: src/%.m4 $(top_builddir)/config.status
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_M4)$(M4) -P $(M4_DEFINES) < $< > $@

# ------------------------------------------------------------------------------
man/custom-entities.ent: configure.ac
	$(AM_V_GEN)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)(echo '<?xml version="1.0" encoding="utf-8" ?>' && \
	 printf '$(subst '|,<!ENTITY ,$(subst =, ",$(subst |',">\n,$(substitutions))))') \
	 > $@ # '

CLEANFILES += \
	man/custom-entities.ent

XSLTPROC_FLAGS = \
	--nonet \
	--xinclude \
	--stringparam man.output.quietly 1 \
	--stringparam funcsynopsis.style ansi \
	--stringparam man.authors.section.enabled 0 \
	--stringparam man.copyright.section.enabled 0 \
	--stringparam systemd.version $(VERSION) \
	--path '$(builddir)/man:$(srcdir)/man'

XSLT = $(if $(XSLTPROC), $(XSLTPROC), xsltproc)
XSLTPROC_PROCESS_MAN = \
	$(AM_V_XSLT)$(XSLT) -o $@ $(XSLTPROC_FLAGS) $(srcdir)/man/custom-man.xsl $<

XSLTPROC_PROCESS_HTML = \
	$(AM_V_XSLT)$(XSLT) -o $@ $(XSLTPROC_FLAGS) $(srcdir)/man/custom-html.xsl $<

man/%.1: man/%.xml man/custom-man.xsl man/custom-entities.ent
	$(XSLTPROC_PROCESS_MAN)

man/%.3: man/%.xml man/custom-man.xsl man/custom-entities.ent
	$(XSLTPROC_PROCESS_MAN)

man/%.5: man/%.xml man/custom-man.xsl man/custom-entities.ent
	$(XSLTPROC_PROCESS_MAN)

man/%.7: man/%.xml man/custom-man.xsl man/custom-entities.ent
	$(XSLTPROC_PROCESS_MAN)

man/%.8: man/%.xml man/custom-man.xsl man/custom-entities.ent
	$(XSLTPROC_PROCESS_MAN)

man/%.html: man/%.xml man/custom-html.xsl man/custom-entities.ent
	$(XSLTPROC_PROCESS_HTML)

define html-alias
	$(AM_V_LN)$(LN_S) -f $(notdir $<) $@
endef

EXTRA_DIST += \
	man/custom-html.xsl \
	man/custom-man.xsl

# ------------------------------------------------------------------------------
.PHONY: hwdb-update
hwdb-update:
	( cd $(top_srcdir)/hwdb && \
	wget -O usb.ids 'http://www.linux-usb.org/usb.ids' && \
	wget -O pci.ids 'http://pci-ids.ucw.cz/v2.2/pci.ids' && \
	wget -O ma-large.txt 'http://standards.ieee.org/develop/regauth/oui/oui.txt' && \
	wget -O ma-medium.txt 'http://standards.ieee.org/develop/regauth/oui28/mam.txt' && \
	wget -O ma-small.txt 'http://standards.ieee.org/develop/regauth/oui36/oui36.txt' && \
	./ids-update.pl )

.PHONY: built-sources
built-sources: $(BUILT_SOURCES)

.PHONY: install-tree
install-tree: all
	rm -rf $(abs_srcdir)/install-tree
	$(MAKE) install DESTDIR=$(abs_srcdir)/install-tree
	tree $(abs_srcdir)/install-tree

exported-%: %
	$(AM_V_GEN)$(NM) -g --defined-only $(builddir)/.libs/$(<:.la=.so) 2>&1 /dev/null | grep " T " | cut -d" " -f3 > $@

exported: $(addprefix exported-, $(lib_LTLIBRARIES))
	$(AM_V_GEN)sort -u $^ > $@

OBJECT_VARIABLES:=$(filter %_OBJECTS,$(.VARIABLES))
ALL_OBJECTS:=$(foreach v,$(OBJECT_VARIABLES),$($(v)))

undefined defined: $(ALL_OBJECTS)
	$(AM_V_GEN)for f in $(ALL_OBJECTS) ; do \
		$(NM) -g --$@-only `echo $(builddir)/"$$f" | sed -e 's,\([^/]*\).lo$$,.libs/\1.o,'` ; \
	done | cut -c 20- | cut -d @ -f 1 | sort -u > $@

CLEANFILES += \
	defined \
	undefined

.PHONY: check-api-unused
check-api-unused: defined undefined exported
	( cat exported undefined ) | sort -u  | diff -u - defined | grep ^+ | grep -v ^+++ | cut -c2-

.PHONY: check-includes
check-includes: $(top_srcdir)/tools/check-includes.pl
	$(AM_V_GEN) find * -name '*.[hcS]' -type f -print | sort -u \
		| xargs $(top_srcdir)/tools/check-includes.pl

EXTRA_DIST += \
	$(top_srcdir)/tools/check-includes.pl

# Stupid test that everything purported to be exported really is
define generate-sym-test
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_at)printf '#include <stdio.h>\n' > $@
	$(AM_V_at)printf '#include "%s"\n' $(notdir $(filter %.h, $^)) >> $@
	$(AM_V_at)printf 'void* functions[] = {\n' >> $@
	$(AM_V_GEN)sed -r -n 's/^ +([a-zA-Z0-9_]+);/\1,/p' $< >> $@
	$(AM_V_at)printf '};\nint main(void) {\n' >> $@
	$(AM_V_at)printf 'unsigned i; for (i=0;i<sizeof(functions)/sizeof(void*);i++) printf("%%p\\n", functions[i]);\n' >> $@
	$(AM_V_at)printf 'return 0; }\n' >> $@
endef

test-libudev-sym.c: \
		src/libudev/libudev.sym \
		src/udev/udev.h
	$(generate-sym-test)

nodist_test_libudev_sym_SOURCES = \
	test-libudev-sym.c
test_libudev_sym_CFLAGS = \
	$(AM_CFLAGS) \
	-Wno-deprecated-declarations
test_libudev_sym_LDADD = \
	libudev.la

BUILT_SOURCES += \
	test-libudev-sym.c

CLEANFILES += \
	test-libudev-sym.c

tests += \
	test-libudev-sym

EXTRA_DIST += \
        tools/gdb-sd_dump_hashmaps.py
