ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

AM_CPPFLAGS = \
	-DVERSION \
	-DCLONE_NEWNS \
        -I $(top_srcdir)/src/libudev \
        -I $(top_srcdir)/src/udev

noinst_PROGRAMS = \
	test-libudev \
	test-udev

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

test_udev_CPPFLAGS = \
	-I $(top_srcdir)/src/udev \
	$(AM_CPPFLAGS)
