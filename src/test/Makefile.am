ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

noinst_PROGRAMS = \
	test-libudev \
	test-udev

test_libudev_SOURCES = \
	test-libudev.c

test_libudev_LDADD = \
	libudev.la

test_udev_SOURCES = \
	src/test/test-udev.c

test_udev_LDADD = \
	libudev-core.la \
	$(SELINUX_LIBS)

