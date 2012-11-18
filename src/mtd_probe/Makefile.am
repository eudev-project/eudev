ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

rootprefix=@rootprefix@
udevlibexecdir=$(rootprefix)/lib/udev

udevlibexec_PROGRAMS = \
	mtd_probe

mtd_probe_SOURCES =  \
	mtd_probe.c \
	mtd_probe.h \
	probe_smartmedia.c
