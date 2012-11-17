ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

rootprefix=@rootprefix@
udevlibexecdir=$(rootprefix)/lib/udev

udevlibexec_PROGRAMS = \
	v4l_id

v4l_id_SOURCES = \
	v4l_id.c

v4l_id_LDADD = \
	$(top_srcdir)/src/libudev/libudev-private.la \
	$(top_srcdir)/src/udev/libudev-core.la
