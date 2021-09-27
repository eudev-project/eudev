ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

AM_CPPFLAGS = \
	-I $(top_srcdir)/src/shared

udevlibexec_PROGRAMS = \
	mtd_probe

mtd_probe_SOURCES =  \
	mtd_probe.c \
	mtd_probe.h \
	probe_smartmedia.c

mtd_probe_LDADD = \
	$(top_builddir)/src/libudev/libudev-private.la \
	$(top_builddir)/src/udev/libudev-core.la
