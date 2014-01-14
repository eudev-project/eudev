ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

LIBUDEV_CURRENT=4
LIBUDEV_REVISION=0
LIBUDEV_AGE=3

define move-to-rootlibdir
	if test "$(libdir)" != "$(rootlibdir)"; then \
		$(MKDIR_P) $(DESTDIR)$(rootlibdir) && \
		so_img_name=$$(readlink $(DESTDIR)$(libdir)/$$libname) && \
		so_img_rel_target_prefix=$$(echo $(libdir) | sed 's,\(^/\|\)[^/][^/]*,..,g') && \
		$(LN_S) -f $$so_img_rel_target_prefix$(rootlibdir)/$$so_img_name $(DESTDIR)$(libdir)/$$libname && \
		mv $(DESTDIR)$(libdir)/$$libname.* $(DESTDIR)$(rootlibdir); \
	fi
endef

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-DUDEV_CONF_FILE=\"$(udevconffile)\" \
	-DUDEV_HWDB_BIN=\"$(udevhwdbbin)\" \
	-DUDEV_VERSION=$(UDEV_VERSION) \
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
	util.c \
	utf8.c

noinst_HEADERS = \
	libudev-hwdb-def.h \
	libudev-private.h \
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
	util.h \
	utf8.h

include_HEADERS = \
	libudev.h

libudev_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-version-info $(LIBUDEV_CURRENT):$(LIBUDEV_REVISION):$(LIBUDEV_AGE) \
	-Wl,--version-script=$(top_srcdir)/src/libudev/libudev.sym


libudev_private_la_SOURCES =\
	libudev-device-private.c \
	libudev-queue-private.c

libudev_private_la_LIBADD =\
	libudev.la

noinst_LTLIBRARIES = \
	libudev-private.la

pkgconfiglib_DATA = \
	libudev.pc

EXTRA_DIST = \
	libudev.pc.in \
	libudev.sym

CLEANFILES = \
	libudev.pc

install-exec-hook:
	libname=libudev.so && $(move-to-rootlibdir)

uninstall-hook:
	rm -f $(DESTDIR)$(rootlibdir)/libudev.so*
