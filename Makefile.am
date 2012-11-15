
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

# And these are the special ones for /
rootprefix=@rootprefix@
rootbindir=$(rootprefix)/bin
rootlibexecdir=$(rootprefix)/lib/systemd

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-DROOTPREFIX=\"$(rootprefix)\" \
	-I $(top_srcdir)/src/libudev \
	-I $(top_srcdir)/src/udev \
	$(OUR_CPPFLAGS)

# ------------------------------------------------------------------------------

if ENABLE_GTK_DOC
SUBDIRS += \
	docs/libudev
endif

include_HEADERS += \
	src/libudev/libudev.h

lib_LTLIBRARIES += \
	libudev.la

libudev_la_SOURCES =\
	src/libudev/libudev-private.h \
	src/libudev/libudev.c \
	src/libudev/libudev-list.c \
	src/libudev/libudev-util.c \
	src/libudev/libudev-device.c \
	src/libudev/libudev-enumerate.c \
	src/libudev/libudev-monitor.c \
	src/libudev/libudev-queue.c \
	src/libudev/libudev-hwdb-def.h \
	src/libudev/libudev-hwdb.c

libudev_la_CFLAGS = \
	$(AM_CFLAGS) \
	-fvisibility=hidden

libudev_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-version-info $(LIBUDEV_CURRENT):$(LIBUDEV_REVISION):$(LIBUDEV_AGE) \
	-Wl,--version-script=$(top_srcdir)/src/libudev/libudev.sym

pkgconfiglib_DATA += \
	src/libudev/libudev.pc

EXTRA_DIST += \
	src/libudev/libudev.pc.in \
	src/libudev/libudev.sym

CLEANFILES += \
	src/libudev/libudev.pc

# move lib from $(libdir) to $(rootlibdir) and update devel link, if needed
libudev-install-move-hook:
	if test "$(libdir)" != "$(rootlibdir)"; then \
		$(MKDIR_P) $(DESTDIR)$(rootlibdir) && \
		so_img_name=$$(readlink $(DESTDIR)$(libdir)/libudev.so) && \
		so_img_rel_target_prefix=$$(echo $(libdir) | sed 's,\(^/\|\)[^/][^/]*,..,g') && \
		ln -sf $$so_img_rel_target_prefix$(rootlibdir)/$$so_img_name $(DESTDIR)$(libdir)/libudev.so && \
		mv $(DESTDIR)$(libdir)/libudev.so.* $(DESTDIR)$(rootlibdir); \
	fi

libudev-uninstall-move-hook:
	rm -f $(DESTDIR)$(rootlibdir)/libudev.so*

INSTALL_EXEC_HOOKS += libudev-install-move-hook
UNINSTALL_EXEC_HOOKS += libudev-uninstall-move-hook

# ------------------------------------------------------------------------------
noinst_LTLIBRARIES += \
	libudev-private.la

libudev_private_la_SOURCES =\
	$(libudev_la_SOURCES) \
	src/libudev/libudev-device-private.c \
	src/libudev/libudev-queue-private.c

libudev_private_la_CFLAGS = \
	$(AM_CFLAGS) \
	-fvisibility=default

libudev_private_la_LIBADD = \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
MANPAGES += \
	man/udev.7 \
	man/udevadm.8 \
	man/systemd-udevd.service.8

udev-confdirs:
	-$(MKDIR_P) $(DESTDIR)$(sysconfdir)/udev/rules.d
	-$(MKDIR_P) $(DESTDIR)$(sysconfdir)/udev/hwdb.d

INSTALL_DATA_HOOKS += udev-confdirs

dist_udevrules_DATA += \
	rules/99-systemd.rules \
	rules/42-usb-hid-pm.rules \
	rules/50-udev-default.rules \
	rules/60-persistent-storage-tape.rules \
	rules/60-persistent-serial.rules \
	rules/60-persistent-input.rules \
	rules/60-persistent-alsa.rules \
	rules/60-persistent-storage.rules \
	rules/64-btrfs.rules \
	rules/75-net-description.rules \
	rules/75-tty-description.rules \
	rules/78-sound-card.rules \
	rules/80-drivers.rules \
	rules/95-udev-late.rules

dist_udevhwdb_DATA = \
	hwdb/20-pci-vendor-product.hwdb \
	hwdb/20-pci-classes.hwdb \
	hwdb/20-usb-vendor-product.hwdb \
	hwdb/20-usb-classes.hwdb \
	hwdb/20-acpi-vendor.hwdb \
	hwdb/20-OUI.hwdb

udevconfdir = $(sysconfdir)/udev
dist_udevconf_DATA = \
	src/udev/udev.conf

sharepkgconfigdir = $(datadir)/pkgconfig
sharepkgconfig_DATA = \
	src/udev/udev.pc

EXTRA_DIST += \
	rules/99-systemd.rules.in \
	src/udev/udev.pc.in

CLEANFILES += \
	rules/99-systemd.rules \
	src/udev/udev.pc

bin_PROGRAMS += \
	udevadm

libudev_core_la_SOURCES = \
	src/udev/udev.h \
	src/udev/udev-event.c \
	src/udev/udev-watch.c \
	src/udev/udev-node.c \
	src/udev/udev-rules.c \
	src/udev/udev-ctrl.c \
	src/udev/udev-builtin.c \
	src/udev/udev-builtin-blkid.c \
	src/udev/udev-builtin-btrfs.c \
	src/udev/udev-builtin-firmware.c \
	src/udev/udev-builtin-hwdb.c \
	src/udev/udev-builtin-input_id.c \
	src/udev/udev-builtin-kmod.c \
	src/udev/udev-builtin-net_id.c \
	src/udev/udev-builtin-path_id.c \
	src/udev/udev-builtin-usb_id.c

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

if HAVE_ACL
libudev_core_la_SOURCES += \
	src/udev/udev-builtin-uaccess.c
endif

systemd_udevd_SOURCES = \
	src/udev/udevd.c

systemd_udevd_LDADD = \
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
	src/udev/udevadm-test-builtin.c

udevadm_LDADD = \
	libudev-core.la

# ------------------------------------------------------------------------------
TESTS += \
	test/udev-test.pl \
	test/rules-test.sh

noinst_PROGRAMS += \
	test-libudev \
	test-udev

test_libudev_SOURCES = \
	src/test/test-libudev.c

test_libudev_LDADD = \
	libudev.la

test_udev_SOURCES = \
	src/test/test-udev.c

test_udev_LDADD = \
	libudev-core.la \
	$(BLKID_LIBS) \
	$(KMOD_LIBS) \
	$(SELINUX_LIBS)

check_DATA += \
	test/sys

# packed sysfs test tree
test/sys:
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)tar -C test/ -xJf $(top_srcdir)/test/sys.tar.xz

test-sys-distclean:
	-rm -rf test/sys
DISTCLEAN_LOCAL_HOOKS += test-sys-distclean

EXTRA_DIST += \
	test/sys.tar.xz \
	test/udev-test.pl \
	test/rules-test.sh \
	test/rule-syntax-check.py

# ------------------------------------------------------------------------------
ata_id_SOURCES = \
	src/udev/ata_id/ata_id.c

ata_id_LDADD = \
	libudev-private.la

udevlibexec_PROGRAMS += \
	ata_id

# ------------------------------------------------------------------------------
cdrom_id_SOURCES = \
	src/udev/cdrom_id/cdrom_id.c

cdrom_id_LDADD = \
	libudev.la

udevlibexec_PROGRAMS += \
	cdrom_id

dist_udevrules_DATA += \
	rules/60-cdrom_id.rules

# ------------------------------------------------------------------------------
collect_SOURCES = \
	src/udev/collect/collect.c

collect_LDADD = \
	libudev-private.la

udevlibexec_PROGRAMS += \
	collect

# ------------------------------------------------------------------------------
scsi_id_SOURCES =\
	src/udev/scsi_id/scsi_id.c \
	src/udev/scsi_id/scsi_serial.c \
	src/udev/scsi_id/scsi.h \
	src/udev/scsi_id/scsi_id.h

scsi_id_LDADD = \
	libudev-private.la

udevlibexec_PROGRAMS += \
	scsi_id

EXTRA_DIST += \
	src/udev/scsi_id/README

# ------------------------------------------------------------------------------
v4l_id_SOURCES = \
	src/udev/v4l_id/v4l_id.c

v4l_id_LDADD = \
	libudev.la

udevlibexec_PROGRAMS += \
	v4l_id

dist_udevrules_DATA += \
	rules/60-persistent-v4l.rules

# ------------------------------------------------------------------------------
accelerometer_SOURCES = \
	src/udev/accelerometer/accelerometer.c

accelerometer_LDADD = \
	libudev.la -lm

udevlibexec_PROGRAMS += \
	accelerometer

dist_udevrules_DATA += \
	rules/61-accelerometer.rules

# ------------------------------------------------------------------------------
if ENABLE_GUDEV
if ENABLE_GTK_DOC
SUBDIRS += \
	docs/gudev
endif

libgudev_includedir = \
	$(includedir)/gudev-1.0/gudev

libgudev_include_HEADERS = \
	src/gudev/gudev.h \
	src/gudev/gudevenums.h \
	src/gudev/gudevenumtypes.h \
	src/gudev/gudevtypes.h \
	src/gudev/gudevclient.h \
	src/gudev/gudevdevice.h \
	src/gudev/gudevenumerator.h

lib_LTLIBRARIES += libgudev-1.0.la

pkgconfiglib_DATA += \
	src/gudev/gudev-1.0.pc

CLEANFILES += \
	src/gudev/gudev-1.0.pc

libgudev_1_0_la_SOURCES = \
	src/gudev/gudevenums.h \
	src/gudev/gudevenumtypes.h \
	src/gudev/gudevenumtypes.h\
	src/gudev/gudevtypes.h \
	src/gudev/gudevclient.h \
	src/gudev/gudevclient.c \
	src/gudev/gudevdevice.h \
	src/gudev/gudevdevice.c \
	src/gudev/gudevenumerator.h \
	src/gudev/gudevenumerator.c \
	src/gudev/gudevprivate.h

nodist_libgudev_1_0_la_SOURCES = \
	src/gudev/gudevmarshal.h \
	src/gudev/gudevmarshal.c \
	src/gudev/gudevenumtypes.h \
	src/gudev/gudevenumtypes.c

BUILT_SOURCES += \
	$(nodist_libgudev_1_0_la_SOURCES)

libgudev_1_0_la_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-I$(top_builddir)/src\
	-I$(top_srcdir)/src\
	-I$(top_builddir)/src/gudev \
	-I$(top_srcdir)/src/gudev \
	-D_POSIX_PTHREAD_SEMANTICS -D_REENTRANT \
	-D_GUDEV_COMPILATION \
	-DG_LOG_DOMAIN=\"GUdev\"

libgudev_1_0_la_CFLAGS = \
	$(AM_CFLAGS) \
	-fvisibility=default \
	$(GLIB_CFLAGS)

libgudev_1_0_la_LIBADD = \
	libudev.la \
	$(GLIB_LIBS)

libgudev_1_0_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-version-info $(LIBGUDEV_CURRENT):$(LIBGUDEV_REVISION):$(LIBGUDEV_AGE) \
	-export-dynamic -no-undefined \
	-export-symbols-regex '^g_udev_.*'

src/gudev/gudevmarshal.h: src/gudev/gudevmarshal.list
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)glib-genmarshal $< --prefix=g_udev_marshal --header > $@

src/gudev/gudevmarshal.c: src/gudev/gudevmarshal.list
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)echo '#include "gudevmarshal.h"' > $@ && \
	glib-genmarshal $< --prefix=g_udev_marshal --body >> $@

src/gudev/gudevenumtypes.%: src/gudev/gudevenumtypes.%.template src/gudev/gudevenums.h
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)glib-mkenums --template $^ > $@

if HAVE_INTROSPECTION
-include $(INTROSPECTION_MAKEFILE)

src/gudev/GUdev-1.0.gir: libgudev-1.0.la

src_gudev_GUdev_1_0_gir_INCLUDES = GObject-2.0

src_gudev_GUdev_1_0_gir_CFLAGS = \
	$(INCLUDES) \
	-D_GUDEV_COMPILATION \
	-D_GUDEV_WORK_AROUND_DEV_T_BUG \
	-I$(top_srcdir)/src \
	-I$(top_builddir)/src \
	-I$(top_srcdir)/src/gdev \
	-I$(top_builddir)/src/gdev

src_gudev_GUdev_1_0_gir_LIBS = libgudev-1.0.la

src_gudev_GUdev_1_0_gir_SCANNERFLAGS = \
	--pkg-export=gudev-1.0 \
	--warn-all

src_gudev_GUdev_1_0_gir_FILES = \
	src/gudev/gudev.h \
	src/gudev/gudevtypes.h \
	src/gudev/gudevenums.h \
	src/gudev/gudevenumtypes.h \
	src/gudev/gudevclient.h \
	src/gudev/gudevdevice.h \
	src/gudev/gudevenumerator.h \
	src/gudev/gudevclient.c \
	src/gudev/gudevdevice.c \
	src/gudev/gudevenumerator.c

INTROSPECTION_GIRS = src/gudev/GUdev-1.0.gir
INTROSPECTION_SCANNER_ARGS = --c-include=gudev/gudev.h

girdir = $(datadir)/gir-1.0
gir_DATA = \
	src/gudev/GUdev-1.0.gir

typelibsdir = $(libdir)/girepository-1.0
typelibs_DATA = \
	src/gudev/GUdev-1.0.typelib

CLEANFILES += $(gir_DATA) $(typelibs_DATA)
endif # HAVE_INTROSPECTION

# move lib from $(libdir) to $(rootlibdir) and update devel link, if needed
libgudev-install-move-hook:
	if test "$(libdir)" != "$(rootlibdir)"; then \
		$(MKDIR_P) $(DESTDIR)$(rootlibdir) && \
		so_img_name=$$(readlink $(DESTDIR)$(libdir)/libgudev-1.0.so) && \
		so_img_rel_target_prefix=$$(echo $(libdir) | sed 's,\(^/\|\)[^/][^/]*,..,g') && \
		ln -sf $$so_img_rel_target_prefix$(rootlibdir)/$$so_img_name $(DESTDIR)$(libdir)/libgudev-1.0.so && \
		mv $(DESTDIR)$(libdir)/libgudev-1.0.so.* $(DESTDIR)$(rootlibdir); \
	fi

libgudev-uninstall-move-hook:
	rm -f $(DESTDIR)$(rootlibdir)/libgudev-1.0.so*

INSTALL_EXEC_HOOKS += libgudev-install-move-hook
UNINSTALL_EXEC_HOOKS += libgudev-uninstall-move-hook
endif

EXTRA_DIST += \
	src/gudev/gudev-1.0.pc.in \
	src/gudev/gudevmarshal.list \
	src/gudev/gudevenumtypes.h.template \
	src/gudev/gudevenumtypes.c.template \
	src/gudev/gjs-example.js \
	src/gudev/seed-example-enum.js \
	src/gudev/seed-example.js


# ------------------------------------------------------------------------------
if ENABLE_KEYMAP
keymap_SOURCES = \
	src/udev/keymap/keymap.c

keymap_CPPFLAGS = \
	$(AM_CPPFLAGS) -I src/udev/keymap

nodist_keymap_SOURCES = \
	src/udev/keymap/keys-from-name.h \
	src/udev/keymap/keys-to-name.h

BUILT_SOURCES += \
	$(nodist_keymap_SOURCES)

udevlibexec_PROGRAMS += \
	keymap

dist_doc_DATA += \
	src/udev/keymap/README.keymap.txt

dist_udevrules_DATA += \
	src/udev/keymap/95-keymap.rules \
	src/udev/keymap/95-keyboard-force-release.rules

dist_udevhome_SCRIPTS = \
	src/udev/keymap/findkeyboards \
	src/udev/keymap/keyboard-force-release.sh

TESTS += \
	src/udev/keymap/check-keymaps.sh

CLEANFILES += \
	src/udev/keymap/keys.txt \
	src/udev/keymap/keys-from-name.gperf \
	src/udev/keymap/keyboard-force-release.sh

udevkeymapdir = $(udevlibexecdir)/keymaps
dist_udevkeymap_DATA = \
	keymaps/acer \
	keymaps/acer-aspire_5720 \
	keymaps/acer-aspire_8930 \
	keymaps/acer-aspire_5920g \
	keymaps/acer-aspire_6920 \
	keymaps/acer-travelmate_c300 \
	keymaps/asus \
	keymaps/compaq-e_evo \
	keymaps/dell \
	keymaps/dell-latitude-xt2 \
	keymaps/everex-xt5000 \
	keymaps/fujitsu-amilo_li_2732 \
	keymaps/fujitsu-amilo_pa_2548 \
	keymaps/fujitsu-amilo_pro_edition_v3505 \
	keymaps/fujitsu-amilo_pro_v3205 \
	keymaps/fujitsu-amilo_si_1520 \
	keymaps/fujitsu-esprimo_mobile_v5 \
	keymaps/fujitsu-esprimo_mobile_v6 \
	keymaps/genius-slimstar-320 \
	keymaps/hewlett-packard \
	keymaps/hewlett-packard-2510p_2530p \
	keymaps/hewlett-packard-compaq_elitebook \
	keymaps/hewlett-packard-pavilion \
	keymaps/hewlett-packard-presario-2100 \
	keymaps/hewlett-packard-tablet \
	keymaps/hewlett-packard-tx2 \
	keymaps/hewlett-packard_elitebook-8440p \
	keymaps/ibm-thinkpad-usb-keyboard-trackpoint \
	keymaps/inventec-symphony_6.0_7.0 \
	keymaps/lenovo-3000 \
	keymaps/lenovo-ideapad \
	keymaps/lenovo-thinkpad-usb-keyboard-trackpoint \
	keymaps/lenovo-thinkpad_x6_tablet \
	keymaps/lenovo-thinkpad_x200_tablet \
	keymaps/lg-x110 \
	keymaps/logitech-wave \
	keymaps/logitech-wave-cordless \
	keymaps/logitech-wave-pro-cordless \
	keymaps/maxdata-pro_7000 \
	keymaps/medion-fid2060 \
	keymaps/medionnb-a555 \
	keymaps/micro-star \
	keymaps/module-asus-w3j \
	keymaps/module-ibm \
	keymaps/module-lenovo \
	keymaps/module-sony \
	keymaps/module-sony-old \
	keymaps/module-sony-vgn \
	keymaps/module-sony-vpc \
	keymaps/olpc-xo \
	keymaps/onkyo \
	keymaps/oqo-model2 \
	keymaps/samsung-other \
	keymaps/samsung-90x3a \
	keymaps/samsung-sq1us \
	keymaps/samsung-sx20s \
	keymaps/toshiba-satellite_a100 \
	keymaps/toshiba-satellite_a110 \
	keymaps/toshiba-satellite_m30x \
	keymaps/zepto-znote

udevkeymapforcereldir = $(udevlibexecdir)/keymaps/force-release
dist_udevkeymapforcerel_DATA = \
	keymaps-force-release/dell-touchpad \
	keymaps-force-release/dell-xps \
	keymaps-force-release/hp-other \
	keymaps-force-release/samsung-other \
	keymaps-force-release/samsung-90x3a \
	keymaps-force-release/common-volume-keys

src/udev/keymap/keys.txt: Makefile
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(CPP) $(CFLAGS) $(AM_CPPFLAGS) $(CPPFLAGS) -dM -include linux/input.h - < /dev/null | $(AWK) '/^#define[ \t]+KEY_[^ ]+[ \t]+[0-9]/ { if ($$2 != "KEY_MAX") { print $$2 } }' | sed 's/^KEY_COFFEE$$/KEY_SCREENLOCK/' > $@

src/udev/keymap/keys-from-name.gperf: src/udev/keymap/keys.txt Makefile
	$(AM_V_GEN)$(AWK) 'BEGIN{ print "struct key { const char* name; unsigned short id; };"; print "%null-strings"; print "%%";} { print $$1 ", " $$1 }' < $< > $@

src/udev/keymap/keys-from-name.h: src/udev/keymap/keys-from-name.gperf Makefile
	$(AM_V_GEN)$(GPERF) -L ANSI-C -t --ignore-case -N lookup_key -H hash_key_name -p -C < $< > $@

src/udev/keymap/keys-to-name.h: src/udev/keymap/keys.txt Makefile
	$(AM_V_GEN)$(AWK) 'BEGIN{ print "const char* const key_names[KEY_CNT] = { "} { print "[" $$1 "] = \"" $$1 "\"," } END{print "};"}' < $< > $@
endif

EXTRA_DIST += \
	src/udev/keymap/check-keymaps.sh \
	src/udev/keymap/keyboard-force-release.sh.in

# ------------------------------------------------------------------------------
mtd_probe_SOURCES =  \
	src/udev/mtd_probe/mtd_probe.c \
	src/udev/mtd_probe/mtd_probe.h \
	src/udev/mtd_probe/probe_smartmedia.c

mtd_probe_CPPFLAGS = \
	$(AM_CPPFLAGS)

dist_udevrules_DATA += \
	rules/75-probe_mtd.rules

udevlibexec_PROGRAMS += \
	mtd_probe

