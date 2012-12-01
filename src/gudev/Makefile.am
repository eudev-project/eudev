ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

LIBGUDEV_CURRENT=1
LIBGUDEV_REVISION=2
LIBGUDEV_AGE=1

libgudev_include_HEADERS = \
	gudev.h \
	gudevenums.h \
	gudevenumtypes.h \
	gudevtypes.h \
	gudevclient.h \
	gudevdevice.h \
	gudevenumerator.h

EXTRA_DIST = \
	gudev-1.0.pc.in \
	gudevmarshal.list \
	gudevprivate.h \
	gudevenumtypes.h.template \
	gudevenumtypes.c.template \
	gjs-example.js \
	seed-example-enum.js \
	seed-example.js

lib_LTLIBRARIES = \
	libgudev-1.0.la

pkgconfiglib_DATA = \
	gudev-1.0.pc

CLEANFILES = \
	gudev-1.0.pc

libgudev_1_0_la_SOURCES = \
	gudevenumtypes.c\
	gudevclient.c \
	gudevdevice.c \
	gudevenumerator.c

nodist_libgudev_1_0_la_SOURCES = \
	gudevmarshal.c

BUILT_SOURCES = \
	gudevenumtypes.h\
	gudevmarshal.h \
	$(nodist_libgudev_1_0_la_SOURCES)

libgudev_1_0_la_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-I$(top_srcdir)/src\
	-I$(top_builddir)/src\
	-I$(top_srcdir)/src/libudev \
	-I$(top_builddir)/src/gudev \
	-I$(top_srcdir)/src/gudev \
	-D_POSIX_PTHREAD_SEMANTICS -D_REENTRANT \
	-D_GUDEV_COMPILATION \
	-DG_LOG_DOMAIN=\"GUdev\"

libgudev_1_0_la_CFLAGS = \
	$(AM_CFLAGS) \
	-fvisibility=default \
	$(GLIB_CFLAGS)

libgudev_1_0_la_LIBADD = \
	$(top_builddir)/src/libudev/libudev.la \
	$(GLIB_LIBS)

libgudev_1_0_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-version-info $(LIBGUDEV_CURRENT):$(LIBGUDEV_REVISION):$(LIBGUDEV_AGE) \
	-export-dynamic -no-undefined \
	-export-symbols-regex '^g_udev_.*'

gudevmarshal.h: gudevmarshal.list
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)glib-genmarshal $< --prefix=g_udev_marshal --header > $@

gudevmarshal.c: gudevmarshal.list
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)echo '#include "gudevmarshal.h"' > $@ && \
	glib-genmarshal $< --prefix=g_udev_marshal --body >> $@

gudevenumtypes.%: gudevenumtypes.%.template gudevenums.h
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)glib-mkenums --template $^ > $@

CLEANFILES += \
	gudevmarshal.h \
	gudevmarshal.c \
	gudevenumtypes.h \
	gudevenumtypes.c

if HAVE_INTROSPECTION
-include $(INTROSPECTION_MAKEFILE)

GUdev-1.0.gir: \
	libgudev-1.0.la

GUdev_1_0_gir_INCLUDES = \
	GObject-2.0

GUdev_1_0_gir_CFLAGS = \
	$(INCLUDES) \
	-D_GUDEV_COMPILATION \
	-D_GUDEV_WORK_AROUND_DEV_T_BUG \
	-I$(top_srcdir)/src \
	-I$(top_builddir)/src \
	-I$(top_srcdir)/src/gudev \
	-I$(top_builddir)/src/gudev

GUdev_1_0_gir_LIBS = \
	$(top_builddir)/src/gudev/libgudev-1.0.la \
	$(top_builddir)/src/udev/libudev-core.la

GUdev_1_0_gir_SCANNERFLAGS = \
	--pkg-export=gudev-1.0 \
	--warn-all

GUdev_1_0_gir_FILES = \
	gudev.h \
	gudevtypes.h \
	gudevenums.h \
	gudevenumtypes.h \
	gudevclient.h \
	gudevdevice.h \
	gudevenumerator.h \
	gudevclient.c \
	gudevdevice.c \
	gudevenumerator.c

INTROSPECTION_GIRS = \
	GUdev-1.0.gir

INTROSPECTION_SCANNER_ARGS = \
	--c-include=gudev.h

gir_DATA = \
	GUdev-1.0.gir

typelibs_DATA = \
	GUdev-1.0.typelib

CLEANFILES += \
	$(gir_DATA) $(typelibs_DATA)

endif # HAVE_INTROSPECTION

# move lib from $(libdir) to $(rootlibdir) and update devel link, if needed
libgudev-install-move-hook:
	if test "$(libdir)" != "$(rootlibdir)"; then \
		$(MKDIR_P) $(DESTDIR)$(rootlibdir) && \
		so_img_name=$$(readlink $(DESTDIR)$(libdir)/libgudev-1.0.so) && \
		so_img_rel_target_prefix=$$(echo $(libdir) | sed 's,\(^/\|\)[^/][^/]*,..,g') && \
		ln -sf $$so_img_rel_target_prefix$(rootlibdir)/$$so_img_name $(DESTDIR)$(libdir)/libgudev-1.0.so && \
		mv $(DESTDIR)$(libdir)/libgudev-1.0.so.* $(DESTDIR)$(rootlibdir); \
	fi

libgudev-uninstall-move-hook:
	rm -f $(DESTDIR)$(rootlibdir)/libgudev-1.0.so*

INSTALL_EXEC_HOOKS = \
	libgudev-install-move-hook

UNINSTALL_EXEC_HOOKS = \
	libgudev-uninstall-move-hook

