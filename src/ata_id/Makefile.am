ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

rootprefix=@rootprefix@
udevlibexecdir=$(rootprefix)/lib/udev

udevlibexec_PROGRAMS = \
	ata_id

ata_id_SOURCES = \
	ata_id.c

ata_id_LDADD = \
	$(top_srcdir)/src/libudev/libudev-private.la \
	$(top_srcdir)/src/udev/libudev-core.la
