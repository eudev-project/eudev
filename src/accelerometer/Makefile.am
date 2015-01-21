ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

AM_CPPFLAGS = \
	-I $(top_srcdir)/src/shared \
	-I $(top_srcdir)/src/libudev

udevlibexec_PROGRAMS = \
	accelerometer

accelerometer_SOURCES = \
	accelerometer.c

accelerometer_LDADD = \
	$(top_builddir)/src/libudev/libudev-private.la \
	$(top_builddir)/src/udev/libudev-core.la \
	$(LIBM)
