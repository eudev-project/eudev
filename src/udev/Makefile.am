ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

rootprefix=@rootprefix@

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-DROOTPREFIX=\"$(rootprefix)\" \
	-DUDEVLIBEXECDIR=\"$(udevlibexecdir)\" \
	-I $(top_srcdir)/src/libudev \
	-I $(top_srcdir)/src/udev \
	-I $(top_srcdir)/src/shared

sbin_PROGRAMS = \
	udevd \
	udevadm

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
	udev.h \
	udev-event.c \
	udev-watch.c \
	udev-node.c \
	udev-rules.c \
	udev-ctrl.c \
	udev-builtin.c \
	udev-builtin-blkid.c \
	udev-builtin-btrfs.c \
	udev-builtin-firmware.c \
	udev-builtin-hwdb.c \
	udev-builtin-input_id.c \
	udev-builtin-kmod.c \
	udev-builtin-net_id.c \
	udev-builtin-path_id.c \
	udev-builtin-usb_id.c

if HAVE_ACL
libudev_core_la_SOURCES += \
	udev-builtin-uaccess.c
endif

libudev_core_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(BLKID_CFLAGS) \
	$(KMOD_CFLAGS)

libudev_core_la_LIBADD = \
	libudev-private.la \
	$(BLKID_LIBS) \
	$(KMOD_LIBS)

libudev_core_la_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-DFIRMWARE_PATH="$(FIRMWARE_PATH)"

#
# Extras
#
udevconfdir = $(sysconfdir)/udev
dist_udevconf_DATA = \
	udev.conf

sharepkgconfigdir = $(datadir)/pkgconfig
sharepkgconfig_DATA = \
	udev.pc

EXTRA_DIST = \
	udev.pc.in

CLEANFILES = \
	udev.pc


# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------

udevlibexecdir=$(rootprefix)/lib/udev
udevhomedir = $(udevlibexecdir)
udevlibexec_PROGRAMS =

# ------------------------------------------------------------------------------
# Helper programs below
#

ata_id_SOURCES = \
	ata_id/ata_id.c

ata_id_LDADD = \
	libudev-private.la

udevlibexec_PROGRAMS += \
	ata_id

# ------------------------------------------------------------------------------
cdrom_id_SOURCES = \
	cdrom_id/cdrom_id.c

cdrom_id_LDADD = \
	libudev.la

udevlibexec_PROGRAMS += \
	cdrom_id

# ------------------------------------------------------------------------------
collect_SOURCES = \
	collect/collect.c

collect_LDADD = \
	libudev-private.la

udevlibexec_PROGRAMS += \
	collect

# ------------------------------------------------------------------------------
scsi_id_SOURCES =\
	scsi_id/scsi_id.c \
	scsi_id/scsi_serial.c \
	scsi_id/scsi.h \
	scsi_id/scsi_id.h

scsi_id_LDADD = \
	libudev-private.la

udevlibexec_PROGRAMS += \
	scsi_id

EXTRA_DIST += \
	scsi_id/README

# ------------------------------------------------------------------------------
v4l_id_SOURCES = \
	v4l_id/v4l_id.c

v4l_id_LDADD = \
	libudev.la

udevlibexec_PROGRAMS += \
	v4l_id

# ------------------------------------------------------------------------------
accelerometer_SOURCES = \
	accelerometer/accelerometer.c

accelerometer_LDADD = \
	libudev.la -lm

udevlibexec_PROGRAMS += \
	accelerometer

# ------------------------------------------------------------------------------

if ENABLE_KEYMAP
keymap_SOURCES = \
	keymap/keymap.c

keymap_CPPFLAGS = \
	$(AM_CPPFLAGS) -I keymap

nodist_keymap_SOURCES = \
	keymap/keys-from-name.h \
	keymap/keys-to-name.h

BUILT_SOURCES = \
	$(nodist_keymap_SOURCES)

udevlibexec_PROGRAMS += \
	keymap

dist_doc_DATA = \
	keymap/README.keymap.txt

dist_udevhome_SCRIPTS = \
	keymap/findkeyboards \
	keymap/keyboard-force-release.sh

TESTS = \
	keymap/check-keymaps.sh

CLEANFILES += \
	keymap/keys.txt \
	keymap/keys-from-name.gperf \
	keymap/keyboard-force-release.sh

keymap/keys.txt: Makefile
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(CPP) $(CFLAGS) $(AM_CPPFLAGS) $(CPPFLAGS) -dM -include linux/input.h - < /dev/null | $(AWK) '/^#define[ \t]+KEY_[^ ]+[ \t]+[0-9]/ { if ($$2 != "KEY_MAX") { print $$2 } }' | sed 's/^KEY_COFFEE$$/KEY_SCREENLOCK/' > $@

keymap/keys-from-name.gperf: keymap/keys.txt Makefile
	$(AM_V_GEN)$(AWK) 'BEGIN{ print "struct key { const char* name; unsigned short id; };"; print "%null-strings"; print "%%";} { print $$1 ", " $$1 }' < $< > $@

keymap/keys-from-name.h: keymap/keys-from-name.gperf Makefile
	$(AM_V_GEN)$(GPERF) -L ANSI-C -t --ignore-case -N lookup_key -H hash_key_name -p -C < $< > $@

keymap/keys-to-name.h: keymap/keys.txt Makefile
	$(AM_V_GEN)$(AWK) 'BEGIN{ print "const char* const key_names[KEY_CNT] = { "} { print "[" $$1 "] = \"" $$1 "\"," } END{print "};"}' < $< > $@
endif

EXTRA_DIST += \
	keymap/check-keymaps.sh \
	keymap/keyboard-force-release.sh.in

# ------------------------------------------------------------------------------
mtd_probe_SOURCES =  \
	mtd_probe/mtd_probe.c \
	mtd_probe/mtd_probe.h \
	mtd_probe/probe_smartmedia.c

mtd_probe_CPPFLAGS = \
	$(AM_CPPFLAGS)

udevlibexec_PROGRAMS += \
	mtd_probe

