ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

rootprefix=@rootprefix@
udevlibexecdir=$(rootprefix)/lib/udev

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-DROOTPREFIX=\"$(rootprefix)\" \
	-DUDEVLIBEXECDIR=\"$(udevlibexecdir)\" \
	-I $(top_srcdir)/src/libudev \
	-I $(top_srcdir)/src/udev \
	-I $(top_srcdir)/src/include

udevlibexec_PROGRAMS += \
	mtd_probe

mtd_probe_SOURCES =  \
	mtd_probe.c \
	mtd_probe.h \
	probe_smartmedia.c

mtd_probe_CPPFLAGS = \
	$(AM_CPPFLAGS)
