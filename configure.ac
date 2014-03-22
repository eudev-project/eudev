
AC_PREREQ([2.68])
AC_INIT([eudev],[1.5.3],[https://github.com/gentoo/eudev/issues])
AC_SUBST(UDEV_VERSION, 211)
AC_CONFIG_SRCDIR([src/udev/udevd.c])

AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AC_PREFIX_DEFAULT([/usr])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([foreign 1.11])
AM_SILENT_RULES([yes])

LT_PREREQ(2.2)
LT_INIT

# Checks for programs.
AC_PROG_MKDIR_P
AC_PROG_LN_S
AC_PROG_SED
AC_PROG_GREP
AC_PROG_AWK

AC_PROG_CC_C99
AS_IF([test "x$ac_cv_prog_cc_c99" = "xno"], [
        AC_MSG_ERROR([no C99 compiler found, $PACKAGE requires a C99 compiler.])
])

AC_PROG_CXX
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET

AC_PATH_PROG([M4], [m4])
AC_PATH_PROG([XSLTPROC], [xsltproc])

# Checks for header files.
AC_CHECK_HEADERS(
        [arpa/inet.h fcntl.h inttypes.h langinfo.h limits.h locale.h \
         netinet/in.h sys/ioctl.h sys/mount.h \
         sys/param.h sys/socket.h sys/statvfs.h sys/time.h sys/vfs.h syslog.h \
         termios.h unistd.h],
        [],
        [AC_MSG_ERROR([*** POSIX header not found])]
)

AC_CHECK_HEADERS(
	[mtd/mtd-user.h],
	[],
	[AC_MSG_ERROR([*** KERNEL header not found])]
)

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_CHECK_MEMBERS([struct stat.st_rdev])
AC_CHECK_DECLS([gettid, pivot_root, name_to_handle_at, accept4, mkostemp], [], [], [[#include <sys/types.h>
#include <unistd.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <sys/socket.h>]])


# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_FUNC_FSEEKO
AC_FUNC_GETGROUPS
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_HEADER_MAJOR
AC_FUNC_MMAP

AC_CHECK_FUNCS(
        [alarm dup2 ftruncate localtime_r mempcpy \
         mkdir munmap nl_langinfo rmdir setlocale socket stpcpy \
         uname],
        [],
        [AC_MSG_ERROR([*** POSIX function not found])]
)
AC_SEARCH_LIBS([clock_gettime], [rt], [], [AC_MSG_ERROR([*** POSIX librt not found])])
AC_SEARCH_LIBS([sqrt], [m], [], [AC_MSG_ERROR([*** POSIX libm not found])])

# ------------------------------------------------------------------------------

# TODO: the old python checks are irrelevant, but we do need python and perl for tests

# ------------------------------------------------------------------------------
# Set paths here

AC_ARG_WITH(
        [rootprefix],
        [AS_HELP_STRING(
                [--with-rootprefix=DIR],
                [rootfs directory prefix for config files and kernel modules])],
        [],
        [with_rootprefix="\${prefix}"]
)

AC_ARG_WITH(
        [rootlibdir],
        [AS_HELP_STRING(
                [--with-rootlibdir=DIR],
                [Root directory for libraries necessary for boot])],
        [],
        [with_rootlibdir=${libdir}]
)

AC_ARG_ENABLE(
        [split-usr],
        [AS_HELP_STRING(
                [--enable-split-usr],
                [Include hard-coded default search paths in / and /usr])],
        [],
        [AS_IF(
                [test "x${ac_default_prefix}" != "x${with_rootprefix}" && test "x${with_rootprefix}" != "x\${prefix}"],
                [enable_split_usr=yes],
                [enable_split_usr=no])]
)

AS_IF(
        [test "x${enable_split_usr}" = "xyes"],
        [AC_DEFINE(HAVE_SPLIT_USR, 1, [Define to include hard-coded default search paths in / and /usr])]
)

# Configured paths
AC_SUBST([rootprefix], [$with_rootprefix])
AC_SUBST([rootlibdir], [$with_rootlibdir])
AC_SUBST([udevlibexecdir], [${rootprefix}/lib/udev])

# sysconfdir paths
AC_SUBST([udevconfdir],[${sysconfdir}/udev])
AC_SUBST([udevconffile],[${udevconfdir}/udev.conf])
AC_SUBST([udevhwdbdir],[${udevconfdir}/hwdb.d])
AC_SUBST([udevhwdbbin],[${udevconfdir}/hwdb.bin])

# udevlibexecdir paths
AC_SUBST([udevkeymapdir],[${udevlibexecdir}/keymaps])
AC_SUBST([udevkeymapforceredir],[${udevkeymapdir}/force-release])
AC_SUBST([udevrulesdir],[${udevlibexecdir}/rules.d])

# pkgconfigdir paths
AC_SUBST([pkgconfiglibdir], [${libdir}/pkgconfig])
AC_SUBST([sharepkgconfigdir],[${datadir}/pkgconfig])

# gudev paths
AC_SUBST([libgudev_includedir],[${includedir}/gudev-1.0/gudev])

# introspection paths
AC_SUBST([girdir], [${datadir}/gir-1.0])
AC_SUBST([typelibsdir], [${libdir}/girepository-1.0])

# ------------------------------------------------------------------------------

GOBJECT_INTROSPECTION_CHECK([1.31.1])
AM_CONDITIONAL([HAVE_INTROSPECTION], [test "$enable_introspection" = "yes"])

# ------------------------------------------------------------------------------
have_blkid=no
AC_ARG_ENABLE(blkid, AS_HELP_STRING([--disable-blkid], [Disable optional blkid support]))
if test "x$enable_blkid" != "xno"; then
        PKG_CHECK_MODULES([BLKID], [blkid >= 2.20],
                [AC_DEFINE(HAVE_BLKID, 1, [Define if blkid is available]) have_blkid=yes], have_blkid=no)
        if test "x$have_blkid" = xno -a "x$enable_blkd" = xyes; then
                AC_MSG_ERROR([*** blkid support requested but not found])
        fi
fi
AM_CONDITIONAL(HAVE_BLKID, [test "x$have_blkid" = "xyes"])

# ------------------------------------------------------------------------------
have_selinux=no
AC_ARG_ENABLE(selinux, AS_HELP_STRING([--disable-selinux], [Disable optional SELINUX support]))
if test "x$enable_selinux" != "xno"; then
        PKG_CHECK_MODULES([SELINUX], [libselinux >= 2.1.9],
                [AC_DEFINE(HAVE_SELINUX, 1, [Define if SELinux is available]) have_selinux=yes], have_selinux=no)
        if test "x$have_selinux" = xno -a "x$enable_selinux" = xyes; then
                AC_MSG_ERROR([*** SELinux support requested but libraries not found])
        fi
fi
AM_CONDITIONAL(HAVE_SELINUX, [test "$have_selinux" = "yes"])
if test "x${have_selinux}" != xno ; then
        sushell=/sbin/sushell
else
        sushell=/bin/bash
fi
AC_SUBST(sushell)

# ------------------------------------------------------------------------------

AC_CHECK_DECL([unshare],
        [AC_DEFINE(HAVE_UNSHARE, 1, [Define if unshare is declared])],
        [AC_CHECK_DECL([SYS_unshare],
                [ ] ,
                [AC_MSG_ERROR([*** unshare nor SYS_unshare found.])],
                [#include <syscall.h>])],
        [#include <sched.h>])

# ------------------------------------------------------------------------------
AC_ARG_WITH(firmware-path,
       AS_HELP_STRING([--with-firmware-path=DIR[[[:DIR[...]]]]],
          [Firmware search path (default="")]),
       [], [with_firmware_path=""])
OLD_IFS=$IFS
IFS=:
for i in $with_firmware_path; do
       if test "x${FIRMWARE_PATH}" = "x"; then
              FIRMWARE_PATH="\\\"${i}/\\\""
       else
              FIRMWARE_PATH="${FIRMWARE_PATH}, \\\"${i}/\\\""
       fi
done
IFS=$OLD_IFS
AC_SUBST(FIRMWARE_PATH)
AS_IF([test "x${FIRMWARE_PATH}" != "x"], [ AC_DEFINE(HAVE_FIRMWARE, 1, [Define if FIRMWARE is available]) ])
AM_CONDITIONAL(ENABLE_FIRMWARE, [test "x${FIRMWARE_PATH}" != "x"])

# ------------------------------------------------------------------------------
AC_ARG_ENABLE([gudev],
       AS_HELP_STRING([--disable-gudev], [disable Gobject libudev support @<:@default=enabled@:>@]),
       [], [enable_gudev=yes])
AS_IF([test "x$enable_gudev" = "xyes"], [ PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.22.0 gobject-2.0 >= 2.22.0]) ])
AM_CONDITIONAL([ENABLE_GUDEV], [test "x$enable_gudev" = "xyes"])

# ------------------------------------------------------------------------------
AC_ARG_ENABLE([keymap],
        AS_HELP_STRING([--disable-keymap], [disable keymap fixup support @<:@default=enabled@:>@]),
        [], [enable_keymap=yes])

if test "x$enable_keymap" = "xyes"; then
        AC_PATH_TOOL(GPERF, gperf)
        if test -z "$GPERF" ; then
                AC_MSG_ERROR([*** gperf not found])
        fi
        AC_DEFINE([ENABLE_KEYMAP], [1], [Define if we are enabling rule generator])
fi

AM_CONDITIONAL([ENABLE_KEYMAP], [test "x$enable_keymap" = "xyes"])

# ------------------------------------------------------------------------------

GTK_DOC_CHECK([1.18],[--flavour no-tmpl])
AM_CONDITIONAL([ENABLE_GTK_DOC],[test "x$enable_gtk_doc" = "xyes"])

AS_IF([test "x$enable_gtk_doc" = "xyes" -a "x$XSLTPROC" = x], [
        AC_MSG_ERROR([*** GTK doc requested but xsltproc not found])
])

# ------------------------------------------------------------------------------

AC_ARG_VAR([XML_CATALOG_FILES],[Used to find Docbook catalog (to build man pages)])
AC_ARG_ENABLE([manpages], AS_HELP_STRING([--disable-manpages], [disable manpages]))

if test "x$enable_manpages" != "xno" -a "x$XSLTPROC" != "x"; then
        AC_MSG_CHECKING([for local Docbook stylesheets])
        $XSLTPROC --nonet http://docbook.sourceforge.net/release/xsl/current/xhtml/docbook.xsl >/dev/null 2>&1 << END
<?xml version="1.0" encoding='ISO-8859-1'?>
<!DOCTYPE book PUBLIC "-//OASIS//DTD DocBook XML V4.1.2//EN" "http://www.oasis-open.org/docbook/xml/4.1.2/docbookx.dtd">
<book id="test">
</book>
END
        if test "$?" = 0; then
                docbook_ok=yes
                XSLTPROC_FLAGS=--nonet
                AC_MSG_RESULT(${docbook_ok})
        else 
                AC_MSG_RESULT([no])
		        AC_MSG_CHECKING([for Docbook stylesheets via internet(use '--disable-manpages' flag to omit)])
                $XSLTPROC http://docbook.sourceforge.net/release/xsl/current/xhtml/docbook.xsl >/dev/null 2>&1 << END
<?xml version="1.0" encoding='ISO-8859-1'?>
<!DOCTYPE book PUBLIC "-//OASIS//DTD DocBook XML V4.1.2//EN" "http://www.oasis-open.org/docbook/xml/4.1.2/docbookx.dtd">
<book id="test">
</book>
END
                if test "$?" = 0; then
                       docbook_ok=yes
                       XSLTPROC_FLAGS=
                else
			           docbook_ok=no
			    fi
                AC_MSG_RESULT(${docbook_ok})
        fi
		
        AS_IF([test "x${docbook_ok}" = "xyes"],[have_manpages=yes], [
		       AC_MSG_WARN([Manpages requested but docbook not enabled. Manpages disabled!])
        ])
fi	
AM_CONDITIONAL(ENABLE_MANPAGES, [test "x$have_manpages" = "xyes"])
AC_SUBST(XSLTPROC_FLAGS)

# ------------------------------------------------------------------------------

AC_ARG_ENABLE(modules, [AS_HELP_STRING([--disable-modules], [Disable loadable module support @<:@default=enabled@:>@])], [], [enable_modules=yes])
AC_ARG_ENABLE(libkmod, [AS_HELP_STRING([--enable-libkmod], [Enable module loading through kmod @<:@default=disabled@:>@])], [], [enable_libkmod=no])

if test "x${enable_modules}" = xyes; then

        AC_DEFINE([HAVE_MODULES], [1], [Define if we support loading modules])

        AS_IF([test "x${enable_libkmod}" = xyes],
          [AC_CHECK_LIB([kmod], [main],
            [PKG_CHECK_MODULES(KMOD, [libkmod >= 5])
             AC_SUBST([LIBKMOD], ["-lkmod"])
             AC_DEFINE([HAVE_LIBKMOD], [1],
                       [Define if you have libkmod])
            ],
            [AC_MSG_FAILURE(
               [--enable-libkmod was given, but test for kmod failed])],
            [-lkmod])])

fi

AM_CONDITIONAL([HAVE_MODULES], [test "x${enable_modules}" = xyes])
AM_CONDITIONAL([HAVE_LIBKMOD], [test "x${enable_libkmod}" = xyes])


# ------------------------------------------------------------------------------

AC_ARG_WITH([modprobe],
            [AS_HELP_STRING([--with-modprobe=modprobe],
              [specify location of modprobe when -- @<:@default=$sbindir/modprobe@:>@])],
            [],
            [with_modprobe="${sbindir}/modprobe"])

AC_SUBST([MODPROBE], ["${with_modprobe}"])

# ------------------------------------------------------------------------------
# rule-generator - persistent network and optical device rule generator
# ------------------------------------------------------------------------------
AC_ARG_ENABLE([rule-generator],
        AS_HELP_STRING([--enable-rule-generator], [enable legacy persistent network, cdrom support]),
        [], [enable_rule_generator=no])

if test "x${enable_rule_generator}" != xno; then
        AC_DEFINE([ENABLE_RULE_GENERATOR], [1], [Define if we are enabling rule generator])
fi

AM_CONDITIONAL([ENABLE_RULE_GENERATOR], [test "x$enable_rule_generator" = xyes])

# ------------------------------------------------------------------------------

AC_CONFIG_FILES([Makefile
                 docs/Makefile
                 docs/gudev/Makefile
                 docs/gudev/version.xml
                 docs/libudev/Makefile
                 docs/libudev/version.xml
                 hwdb/Makefile
                 man/Makefile
                 rules/Makefile
                 rule_generator/Makefile
                 rule_generator/write_cd_rules
                 rule_generator/write_net_rules
                 src/Makefile
                 src/accelerometer/Makefile
                 src/ata_id/Makefile
                 src/cdrom_id/Makefile
                 src/collect/Makefile
                 src/mtd_probe/Makefile
                 src/scsi_id/Makefile
                 src/v4l_id/Makefile
                 src/gudev/Makefile
                 src/gudev/gudev-1.0.pc
                 src/libudev/Makefile
                 src/libudev/libudev.pc
                 src/udev/Makefile
                 src/udev/udev.pc
                 test/Makefile])

AC_OUTPUT

# ------------------------------------------------------------------------------

AC_MSG_RESULT([
        prefix:                  ${prefix}
        exec_prefix:             ${exec_prefix}
        sysconfdir:              ${sysconfdir}
        datadir:                 ${datadir}
        includedir:              ${includedir}
        libdir:                  ${libdir}

        rootprefix:              ${rootprefix}
        rootlibdir:              ${rootlibdir}
        udevlibexecdir:          ${udevlibexecdir}
        datarootdir:             ${datarootdir}

        udevconfdir:             ${udevconfdir}
        udevconffile:            ${udevconffile}
        udevhwdbdir:             ${udevhwdbdir}
        udevhwdbbin:             ${udevhwdbbin}
        udevkeymapdir:           ${udevkeymapdir}
        udevkeymapforceredir:    ${udevkeymapforceredir}
        udevrulesdir:            ${udevrulesdir}

        pkgconfiglibdir:         ${libdir}/pkgconfig
        sharepkgconfigdir        ${datadir}/pkgconfig

        libgudev_includedir      ${includedir}/gudev-1.0/gudev

        girdir                   ${datadir}/gir-1.0
        typelibsdir              ${libdir}/girepository-1.0
])

# ------------------------------------------------------------------------------

dnl Set configured scripts executable
if test -f  src/keymap/check-keymaps.sh; then
        chmod +x src/keymap/check-keymaps.sh
fi

if test -f src/keymap/keyboard-force-release.sh; then
        chmod +x src/keymap/keyboard-force-release.sh
fi

