ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

AM_CPPFLAGS = \
	-I $(top_srcdir)/src/shared \
	-I $(top_srcdir)/src/udev \
	-I $(top_srcdir)/src/libudev

udevlibexec_PROGRAMS = \
	dmi_memory_id

dmi_memory_id_SOURCES = \
	dmi_memory_id.c

dmi_memory_id_LDADD = \
	$(top_builddir)/src/libudev/libudev-private.la \
	$(top_builddir)/src/udev/libudev-core.la
