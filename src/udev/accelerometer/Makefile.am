ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

rootprefix=@rootprefix@
udevlibexecdir=$(rootprefix)/lib/udev

udevlibexec_PROGRAMS = \
	accelerometer

accelerometer_SOURCES = \
	accelerometer.c

accelerometer_LDADD = \
	$(top_srcdir)/src/libudev/libudev.la \
	-lm
