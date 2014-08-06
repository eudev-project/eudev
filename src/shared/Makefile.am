ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h

libudev_shared_la_SOURCES=\
	cgroup-util.c \
	conf-files.c \
	device-nodes.c \
	exit-status.c \
	fileio.c \
	hashmap.c \
	log.c \
	MurmurHash2.c \
	path-util.c \
	set.c \
	siphash24.c \
	strbuf.c \
	strv.c \
	strxcpyx.c  \
	time-util.c \
	util.c \
	utf8.c \
        dev-setup.c \
        label.c \
        mkdir.c \
        smack-util.c

noinst_HEADERS = \
	cgroup-util.h \
	conf-files.h \
	def.h \
	device-nodes.h \
	exit-status.h \
	fileio.h \
	hashmap.h \
	ioprio.h \
	log.h \
	macro.h \
	missing.h \
	MurmurHash2.h \
	path-util.h \
	set.h \
	siphash24.h \
	socket-util.h \
	sparse-endian.h \
	strbuf.h \
	strv.h \
	strxcpyx.h \
	time-util.h \
	util.h \
	utf8.h \
        dev-setup.h \
        label.h \
        mkdir.h \
        smack-util.h \
        udev-util.h

libudev_shared_la_LDFLAGS = \
	$(AM_LDFLAGS)

noinst_LTLIBRARIES = \
	libudev_shared.la
