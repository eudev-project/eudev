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
	mkdir.c \
	smack-util.c

if ENABLE_FIRMWARE
libudev_core_la_SOURCES += \
	udev-builtin-firmware.c
endif

noinst_HEADERS = \
	dev-setup.h \
	label.h \
	mkdir.h \
	smack-util.h \
	udev-util.h

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

if ENABLE_KEYMAP
AM_CPPFLAGS += \
	-I $(top_builddir)/src/udev

libudev_core_la_SOURCES += \
	udev-builtin-keyboard.c

nodist_libudev_core_la_SOURCES = \
	keyboard-keys-from-name.h \
	keyboard-keys-to-name.h

keyboard-keys.txt: Makefile
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(CPP) $(CFLAGS) $(AM_CPPFLAGS) $(CPPFLAGS) -dM -include linux/input.h - < /dev/null | $(AWK) '/^#define[ \t]+KEY_[^ ]+[ \t]+[0-9]/ { if ($$2 != "KEY_MAX") { print $$2 } }' | sed 's/^KEY_COFFEE$$/KEY_SCREENLOCK/' > $@

keyboard-keys-from-name.gperf: keyboard-keys.txt Makefile
	$(AM_V_GEN)$(AWK) 'BEGIN{ print "struct key { const char* name; unsigned short id; };"; print "%null-strings"; print "%%";} { print tolower(substr($$1 ,5)) ", " $$1 }' < $< > $@

keyboard-keys-from-name.h: keyboard-keys-from-name.gperf Makefile
	$(AM_V_GPERF)$(GPERF) -L ANSI-C -t -N keyboard_lookup_key -H hash_key_name -p -C < $< > $@

keyboard-keys-to-name.h: keyboard-keys.txt Makefile
	$(AM_V_GEN)$(AWK) 'BEGIN{ print "const char* const key_names[KEY_CNT] = { "} { print "[" $$1 "] = \"" $$1 "\"," } END{print "};"}' < $< > $@


BUILT_SOURCES = \
	$(nodist_libudev_core_la_SOURCES)

CLEANFILES += \
	keyboard-keys-from-name.gperf \
	keyboard-keys.txt \
	$(BUILT_SOURCES)

endif

# install udevadm symlink in sbindir
install-exec-hook:
	if test "$(bindir)" != "$(sbindir)"; then \
		$(LN_S) -n -f $(bindir)/udevadm $(DESTDIR)$(sbindir)/udevadm; \
	fi

uninstall-hook:
	rm -Rf $(DESTDIR)$(sbindir)/udevadm
