ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

AM_CPPFLAGS = \
	$(LIBC_CPPFLAGS) \
	-include $(top_builddir)/config.h \
	-DUDEV_HWDB_BIN=\"$(udevhwdbbin)\" \
	-DUDEV_CONF_DIR=\"$(udevconfdir)\" \
	-DUDEV_ROOT_RUN=\"$(rootrundir)\" \
	-DUDEV_RULES_DIR=\"$(udevrulesdir)\" \
	-DUDEV_LIBEXEC_DIR=\"$(udevlibexecdir)\" \
	-DUDEV_VERSION=\"$(UDEV_VERSION)\" \
	-I $(top_srcdir)/src/shared \
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
	udevadm-test-builtin.c \
	udevadm-verify.c \
	udevadm-cat.c \
	udevadm-wait.c \
	udevadm-lock.c \
	udevadm-util.c \
	udevadm-util.h


udevadm_LDADD = \
	libudev-core.la

if ENABLE_SYSTEMD_HWDB
bin_PROGRAMS += \
	systemd-hwdb

systemd_hwdb_SOURCES = \
	systemd-hwdb.c \
	udevadm-util.c \
	udevadm-util.h

systemd_hwdb_LDADD = \
	libudev-core.la
endif

noinst_LTLIBRARIES = \
        libudev-core.la

libudev_core_la_SOURCES = \
	blockdev-util.c \
	blockdev-util.h \
	reread-partition-table.c \
	reread-partition-table.h \
	udev-dump.c \
	udev-event.c \
	udev-watch.c \
	udev-node.c \
	udev-rules.c \
	udev-rules-check.c \
	udev-rules-check.h \
	hwdb-util.c \
	hwdb-util.h \
	udev-ctrl.c \
	udev-builtin.c \
	udev-builtin-btrfs.c \
	udev-builtin-factory_reset.c \
	udev-builtin-hwdb.c \
	udev-builtin-input_id.c \
	udev-builtin-net_driver.c \
	udev-builtin-net_id.c \
	udev-builtin-net_id-eudev.c \
	netif-naming-scheme.c \
	netif-naming-scheme.h \
	udev-netlink.c \
	udev-netlink.h \
	udev-builtin-path_id.c \
	udev-builtin-usb_id.c

noinst_HEADERS = \
	udev.h

libudev_core_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(BLKID_CFLAGS)

libudev_core_la_LIBADD = \
	$(top_builddir)/src/shared/libudev_shared.la \
	$(top_builddir)/src/libudev/libudev-private.la \
	$(BLKID_LIBS) \
	$(SELINUX_LIBS)

if HAVE_BLKID
libudev_core_la_SOURCES += \
	udev-builtin-blkid.c
endif

if ENABLE_TPM2
libudev_core_la_SOURCES += \
	udev-builtin-tpm2_id.c
endif

if HAVE_KMOD
libudev_core_la_SOURCES += \
	udev-builtin-kmod.c
libudev_core_la_CFLAGS += \
	$(KMOD_CFLAGS)
libudev_core_la_LIBADD += \
	$(KMOD_LIBS)
endif

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


AM_CPPFLAGS += \
	-I $(top_builddir)/src/udev

libudev_core_la_SOURCES += \
	udev-builtin-keyboard.c

nodist_libudev_core_la_SOURCES = \
	keyboard-keys-from-name.h

# The awk program spells out the word boundaries \< and \> of the one of systemd, which mawk does not
# know.
keyboard-keys.txt: Makefile
	$(AM_V_at)f="$@"; case $$f in */*) $(MKDIR_P) "$${f%/*}"; esac
	$(AM_V_GEN)$(CPP) $(CFLAGS) $(AM_CPPFLAGS) $(CPPFLAGS) -dM -include linux/input.h - < /dev/null | $(AWK) ' \
		/(^|[^A-Za-z0-9_])(KEY_(MAX|MIN_INTERESTING))|(BTN_(MISC|MOUSE|JOYSTICK|GAMEPAD|DIGI|WHEEL|TRIGGER_HAPPY))([^A-Za-z0-9_]|$$)/ { next } \
		/^#define[ \t]+(KEY|BTN)_[^ ]+[ \t]+[0-9BK]/ { print $$2 } \
	' > $@

keyboard-keys-from-name.gperf: keyboard-keys.txt Makefile
	$(AM_V_GEN)$(AWK) 'BEGIN{ print "struct key { const char* name; unsigned short id; };"; print "%null-strings"; print "%%";} /^KEY_/{ print tolower(substr($$1 ,5)) ", " $$1 } { print tolower($$1) ", " $$1 }' keyboard-keys.txt > $@

keyboard-keys-from-name.h: keyboard-keys-from-name.gperf Makefile
	$(AM_V_GPERF)$(GPERF) -L ANSI-C -t -N keyboard_lookup_key -H hash_key_name -p -C < keyboard-keys-from-name.gperf > $@


BUILT_SOURCES = \
	$(nodist_libudev_core_la_SOURCES)

CLEANFILES += \
	keyboard-keys-from-name.gperf \
	keyboard-keys.txt \
	$(BUILT_SOURCES)

# no longer generated, but left behind in build trees of older versions
CLEANFILES += \
	keyboard-keys-to-name.h
