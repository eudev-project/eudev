ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

define move-legacylib
	$(MKDIR_P) $(DESTDIR)$(rootlibdir) && \
	mv $(DESTDIR)$(libdir)/$$libname $(DESTDIR)$(rootlibdir)/libudev.so.0
endef

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-DUDEV_CONF_FILE=\"$(udevconffile)\"

lib_LTLIBRARIES = \
	libudev-legacy.la

libudev_legacy_la_SOURCES =\
	libudev.c \
	libudev-list.c \
	libudev-util.c \
	libudev-device.c \
	libudev-enumerate.c \
	libudev-monitor.c \
	libudev-queue.c

libudev_legacy_la_CFLAGS =\
	$(AM_CFLAGS) \
	-shared

noinst_HEADERS = \
	libudev.h \
	libudev-private.h

libudev_legacy_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-avoid-version

install-exec-hook:
	libname=libudev-legacy.so && $(move-legacylib)

EXTRA_DIST = \
	COPYING
