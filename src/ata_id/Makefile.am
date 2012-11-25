ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

AM_CPPFLAGS = \
	-I $(top_srcdir)/src/libudev \
	-I $(top_srcdir)/src/udev

udevlibexec_PROGRAMS = \
	ata_id

ata_id_SOURCES = \
	ata_id.c

ata_id_LDADD = \
	$(top_builddir)/src/libudev/libudev-private.la \
	$(top_builddir)/src/udev/libudev-core.la
