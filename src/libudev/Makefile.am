ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

libdir=@rootlibdir@

LIBUDEV_CURRENT=3
LIBUDEV_REVISION=0
LIBUDEV_AGE=2

AM_CPPFLAGS = \
	-DUDEV_CONF_FILE=\"$(udevconffile)\" \
	-DUDEV_HWDB_BIN=\"$(udevhwdbbin)\" \
	-I $(top_srcdir)/src/udev

lib_LTLIBRARIES = \
	libudev.la

libudev_la_SOURCES =\
	libudev.c \
	libudev-list.c \
	libudev-util.c \
	libudev-device.c \
	libudev-enumerate.c \
	libudev-monitor.c \
	libudev-queue.c \
	libudev-hwdb.c \
	cgroup-util.c \
	conf-files.c \
	exit-status.c \
	hashmap.c \
	log.c \
	path-util.c \
	set.c \
	strbuf.c \
	strv.c \
	util.c

noinst_HEADERS = \
	libudev-hwdb-def.h \
	libudev-private.h \
	cgroup-util.h \
	conf-files.h \
	def.h \
	exit-status.h \
	hashmap.h \
	ioprio.h \
	log.h \
	macro.h \
	missing.h \
	path-util.h \
	set.h \
	socket-util.h \
	sparse-endian.h \
	strbuf.h \
	strv.h \
	util.h

include_HEADERS = \
	libudev.h

libudev_la_CFLAGS = \
	$(AM_CFLAGS) \
	-fvisibility=hidden

libudev_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-version-info $(LIBUDEV_CURRENT):$(LIBUDEV_REVISION):$(LIBUDEV_AGE)


libudev_private_la_SOURCES =\
	$(libudev_la_SOURCES) \
	libudev-device-private.c \
	libudev-queue-private.c

libudev_private_la_CFLAGS = \
	$(AM_CFLAGS) \
	-fvisibility=default

noinst_LTLIBRARIES = \
	libudev-private.la

pkgconfiglib_DATA = \
	libudev.pc

EXTRA_DIST = \
	libudev.pc.in

CLEANFILES = \
	libudev.pc
