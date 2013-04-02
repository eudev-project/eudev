ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-DMODPROBE=\"$(MODPROBE)\" \
	-DROOTPREFIX=\"$(rootprefix)\" \
	-DUDEV_HWDB_DIR=\"$(udevhwdbdir)\" \
	-DUDEV_HWDB_BIN=\"$(udevhwdbbin)\" \
	-DUDEV_CONF_DIR=\"$(udevconfdir)\" \
	-DUDEV_RULES_DIR=\"$(udevrulesdir)\" \
	-DUDEV_LIBEXEC_DIR=\"$(udevlibexecdir)\" \
	-DUDEV_VERSION=\"$(UDEV_VERSION)\" \
	-I $(top_srcdir)/src/libudev

bin_PROGRAMS = \
	udevadm

sbin_PROGRAMS = \
	udevd

udevd_SOURCES = \
	udevd.c

udevd_LDADD = \
	libudev-core.la

udevadm_SOURCES = \
	udevadm.c \
	udevadm-info.c \
	udevadm-control.c \
	udevadm-monitor.c \
	udevadm-hwdb.c \
	udevadm-settle.c \
	udevadm-trigger.c \
	udevadm-test.c \
	udevadm-test-builtin.c

udevadm_LDADD = \
	libudev-core.la

noinst_LTLIBRARIES = \
        libudev-core.la

libudev_core_la_SOURCES = \
	udev-event.c \
	udev-watch.c \
	udev-node.c \
	udev-rules.c \
	udev-ctrl.c \
	udev-builtin.c \
	udev-builtin-btrfs.c \
	udev-builtin-firmware.c \
	udev-builtin-hwdb.c \
	udev-builtin-input_id.c \
	udev-builtin-net_id.c \
	udev-builtin-path_id.c \
	udev-builtin-usb_id.c \
	dev-setup.c \
	label.c \
	mkdir.c

if ENABLE_FIRMWARE
libudev_core_la_SOURCES += \
	udev-builtin-firmware.c
endif

noinst_HEADERS = \
	dev-setup.h \
	label.h \
	mkdir.h

include_HEADERS = \
	udev.h

libudev_core_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(BLKID_CFLAGS)

libudev_core_la_LIBADD = \
	$(top_builddir)/src/libudev/libudev-private.la \
	$(BLKID_LIBS) \
	$(SELINUX_LIBS)

if HAVE_BLKID
libudev_core_la_SOURCES += \
	udev-builtin-blkid.c
endif

if HAVE_MODULES
libudev_core_la_SOURCES += \
	udev-builtin-kmod.c

if HAVE_LIBKMOD
libudev_core_la_CFLAGS += $(KMOD_CFLAGS)
libudev_core_la_LIBADD += $(KMOD_LIBS)
endif
endif



libudev_core_la_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-DFIRMWARE_PATH="$(FIRMWARE_PATH)"

#
# Extras
#
dist_udevconf_DATA = \
	udev.conf

sharepkgconfig_DATA = \
	udev.pc

EXTRA_DIST = \
	udev.pc.in

CLEANFILES = \
	udev.pc

# install udevadm symlink in sbindir
install-exec-hook:
	ln -sf ../bin/udevadm $(DESTDIR)$(sbindir)/udevadm

uninstall-hook:
	rm -Rf $(DESTDIR)$(sbindir)/udevadm
