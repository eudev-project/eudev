ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-DVERSION=\"@VERSION@\" \
	-I $(top_srcdir)/src/libudev \
	-I $(top_srcdir)/src/udev

noinst_PROGRAMS = \
	test-libudev \
	test-udev \
	test-utf8 \
	test-device_nodes

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

test_utf8_SOURCES = \
	test-utf8.c

test_utf8_CFLAGS = \
	$(AM_CFLAGS)

test_utf8_LDADD = \
	$(top_builddir)/src/libudev/libudev-private.la

test_device_nodes_SOURCES = \
	test-device-nodes.c

test_device_nodes_CFLAGS = \
	$(AM_CFLAGS)

test_device_nodes_LDADD = \
	$(top_builddir)/src/libudev/libudev-private.la

if HAVE_LIBKMOD
test_udev_LDADD += $(KMOD_LIBS)
endif

test_udev_CPPFLAGS = \
	-I $(top_srcdir)/src/udev \
	$(AM_CPPFLAGS)


TESTS = \
	udev-test.pl \
	rules-test.sh

check_DATA = \
	test/sys

test/sys:
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)tar -C $(top_builddir)/test/test -xJf $(top_srcdir)/test/sys.tar.xz

test-sys-distclean:
	-rm -rf $(top_builddir)/test/test/sys

clean-local: \
	test-sys-distclean

EXTRA_DIST = \
	sys.tar.xz \
	udev-test.pl \
	rules-test.sh \
	rule-syntax-check.py
