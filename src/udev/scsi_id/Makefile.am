ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

rootprefix=@rootprefix@
udevlibexecdir=$(rootprefix)/lib/udev

udevlibexec_PROGRAMS = \
	scsi_id

scsi_id_SOURCES =\
	scsi_id.c \
	scsi_serial.c \
	scsi.h \
	scsi_id.h

scsi_id_LDADD = \
	$(top_srcdir)/src/libudev/libudev-private.la \
	$(top_srcdir)/src/udev/libudev-core.la

EXTRA_DIST = \
	scsi_id/README
