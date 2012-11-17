ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

rootprefix=@rootprefix@
udevlibexecdir=$(rootprefix)/lib/udev

udevlibexec_PROGRAMS = \
	cdrom_id

cdrom_id_SOURCES = \
	cdrom_id.c

cdrom_id_LDADD = \
	$(top_srcdir)/src/libudev/libudev-private.la \
	$(top_srcdir)/src/udev/libudev-core.la
