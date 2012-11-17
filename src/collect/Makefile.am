ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

rootprefix=@rootprefix@
udevlibexecdir=$(rootprefix)/lib/udev

udevlibexec_PROGRAMS = \
	collect

collect_SOURCES = \
	collect.c

collect_LDADD = \
	$(top_srcdir)/src/libudev/libudev-private.la \
	$(top_srcdir)/src/udev/libudev-core.la
