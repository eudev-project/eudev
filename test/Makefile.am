ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

AM_CPPFLAGS = \
	$(LIBC_CPPFLAGS) \
	$(PROJECT_FILE_CPPFLAGS) \
	-include $(top_builddir)/config.h \
	-DUDEV_ROOT_RUN=\"$(rootrundir)\" \
	-DVERSION=\"@VERSION@\" \
	-I $(top_srcdir)/src/shared \
	-I $(top_srcdir)/src/libudev \
	-I $(top_srcdir)/src/udev

noinst_PROGRAMS = \
	test-libudev \
	test-udev \
	test-udev-devlink

check_PROGRAMS = \
	test-collect \
	test-event-device \
	test-json-writer \
	test-scsi_id

test_collect_SOURCES = \
	test-collect.c

test_collect_LDADD = \
	$(top_builddir)/src/libudev/libudev-private.la \
	$(top_builddir)/src/udev/libudev-core.la

test_event_device_SOURCES = \
	test-event-device.c

test_event_device_LDADD = \
	$(top_builddir)/src/libudev/libudev-private.la \
	$(top_builddir)/src/udev/libudev-core.la

test_json_writer_SOURCES = \
	test-json-writer.c

test_json_writer_LDADD = \
	$(top_builddir)/src/shared/libudev_shared.la

test_scsi_id_SOURCES = \
	test-scsi_id.c

test_scsi_id_LDADD = \
	$(top_builddir)/src/libudev/libudev-private.la \
	$(top_builddir)/src/udev/libudev-core.la

test_scsi_id_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-DUDEV_VERSION=\"$(UDEV_VERSION)\"

test_libudev_SOURCES = \
	test-libudev.c

test_libudev_LDADD = \
	$(top_builddir)/src/libudev/libudev-private.la \
	$(top_builddir)/src/udev/libudev-core.la

test_libudev_CPPFLAGS = \
	-I $(top_srcdir)/src/libudev \
	$(AM_CPPFLAGS)

test_udev_SOURCES = \
	test-udev.c

test_udev_LDADD = \
	$(top_builddir)/src/libudev/libudev-private.la \
	$(top_builddir)/src/udev/libudev-core.la \
	$(BLKID_LIBS) \
	$(SELINUX_LIBS)

if HAVE_KMOD
test_udev_LDADD += \
	$(KMOD_LIBS)
endif

test_udev_CPPFLAGS = \
	-I $(top_srcdir)/src/udev \
	$(AM_CPPFLAGS)

test_udev_devlink_SOURCES = \
	test-udev-devlink.c

test_udev_devlink_LDADD = \
	$(test_udev_LDADD)

test_udev_devlink_CPPFLAGS = \
	$(test_udev_CPPFLAGS)

# The tests use a directory or tmpfs as /sys, which libudev refuses by default; rules-test.sh also
# checks the rules that the build generates, in the build tree.
AM_TESTS_ENVIRONMENT = \
	UDEV_DEVICE_VERIFY_SYSFS=0; export UDEV_DEVICE_VERIFY_SYSFS; \
	abs_top_builddir='$(abs_top_builddir)'; export abs_top_builddir;

TESTS = \
	test-collect \
	test-event-device \
	test-json-writer \
	test-scsi_id \
	udev-test.pl \
	rules-test.sh \
	udev-devlink-test.sh \
	hwdb-test.sh \
	dmi-memory-id-test.sh

check_DATA = \
	test/sys

test/sys:
	$(AM_V_at)f="$@"; $(MKDIR_P) "$${f%/*}"
	$(AM_V_GEN)tar -C $(top_builddir)/test/test -xJf $(top_srcdir)/test/sys.tar.xz

test-sys-distclean:
	-rm -rf $(top_builddir)/test/test/sys

clean-local: \
	test-sys-distclean

EXTRA_DIST = \
	sys.tar.xz \
	udev-test.pl \
	rules-test.sh \
	udev-devlink-test.sh \
	hwdb-test.sh \
	dmi-memory-id-test.sh \
	rule-syntax-check.py \
	$(DMIDECODE_DUMPS)

# the dumps of dmi-memory-id-test.sh with their expected outputs, and the script that writes the crafted ones
DMIDECODE_DUMPS = \
	dmidecode-dumps/HP-Z600.bin \
	dmidecode-dumps/HP-Z600.bin.txt \
	dmidecode-dumps/Lenovo-ThinkPad-X280.bin \
	dmidecode-dumps/Lenovo-ThinkPad-X280.bin.txt \
	dmidecode-dumps/Lenovo-Thinkcentre-m720s.bin \
	dmidecode-dumps/Lenovo-Thinkcentre-m720s.bin.txt \
	dmidecode-dumps/crafted-64-bit-sizes.bin \
	dmidecode-dumps/crafted-64-bit-sizes.bin.txt \
	dmidecode-dumps/crafted-extended-size.bin \
	dmidecode-dumps/crafted-extended-size.bin.txt \
	dmidecode-dumps/crafted-voltages.bin \
	dmidecode-dumps/crafted-voltages.bin.txt \
	dmidecode-dumps/make-crafted-dumps.py
