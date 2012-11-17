ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

noinst_PROGRAMS = \
	test-libudev \
	test-udev

test_libudev_SOURCES = \
	test-libudev.c

test_libudev_LDADD = \
	$(top_srcdir)/src/libudev/libudev.la

test_libudev_CPPFLAGS = \
	-I $(top_srcdir)/src/shared

test_udev_SOURCES = \
	test-udev.c

test_udev_CPPFLAGS = \
	-I $(top_srcdir)/src/shared

test_udev_LDADD = \
	$(top_srcdir)/src/udev/libudev-core.la \
	$(SELINUX_LIBS)
