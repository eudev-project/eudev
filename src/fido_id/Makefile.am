ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

AM_CPPFLAGS = \
	-I $(top_srcdir)/src/shared \
	-I $(top_srcdir)/src/libudev \
	-I $(top_srcdir)/src/udev

udevlibexec_PROGRAMS = \
	fido_id

fido_id_SOURCES =\
	fido_id.c \
	fido_id_desc.c \
	fido_id_desc.h

fido_id_LDADD = \
	$(top_builddir)/src/libudev/libudev-private.la \
	$(top_builddir)/src/udev/libudev-core.la

