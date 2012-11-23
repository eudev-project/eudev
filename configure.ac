
AC_PREREQ([2.68])
AC_INIT([eudev], [0.1], [http://bugzilla.gentoo.org])
AC_CONFIG_SRCDIR([src/udev/udevd.c])

AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE

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

AC_PROG_CC
AC_PROG_CXX
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET

AC_PATH_PROG([M4], [m4])
AC_PATH_PROG([XSLTPROC], [xsltproc])
AC_PATH_TOOL(GPERF, gperf)
if test -z "$GPERF" ; then
        AC_MSG_ERROR([*** gperf not found])
fi

PKG_CHECK_MODULES(BLKID,[blkid >= 2.20])

# Checks for header files.
AC_CHECK_HEADERS(
    [arpa/inet.h fcntl.h inttypes.h langinfo.h limits.h locale.h malloc.h \
     netinet/in.h stddef.h stdint.h stdlib.h string.h sys/ioctl.h sys/mount.h \
     sys/param.h sys/socket.h sys/statvfs.h sys/time.h sys/vfs.h syslog.h \
     termios.h unistd.h],
    [],
    [AC_MSG_ERROR([*** POSIX header not found])]
)

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_CHECK_MEMBERS([struct stat.st_rdev])
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_CHECK_DECLS([gettid, pivot_root, name_to_handle_at], [], [], [[#include <sys/types.h>
#include <unistd.h>
#include <sys/mount.h>
#include <fcntl.h>]])


# Checks for library functions.
AC_FUNC_ALLOCA
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_FUNC_FSEEKO
AC_FUNC_GETGROUPS
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_HEADER_MAJOR
AC_FUNC_MALLOC
AC_FUNC_MKTIME
AC_FUNC_MMAP
AC_FUNC_REALLOC
AC_FUNC_STRNLEN
AC_FUNC_STRTOD

AC_CHECK_FUNCS(
    [alarm dup2 ftruncate localtime_r memchr memmove mempcpy memset \
     mkdir munmap nl_langinfo rmdir setlocale socket stpcpy strcasecmp \
     strchr strcspn strdup strerror strndup strpbrk strrchr strspn \
     strstr strtol strtoul strtoull uname],
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
	[with_rootprefix=${ac_default_prefix}]
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
		[Assume that /bin, /sbin are not symlinks into /usr])],
	[],
	[AS_IF(
		[test "x${ac_default_prefix}" != "x${with_rootprefix}"],
		[enable_split_usr=yes],
		[enable_split_usr=no])]
)

AS_IF(
	[test "x${enable_split_usr}" = "xyes"],
	[AC_DEFINE(HAVE_SPLIT_USR, 1, [Define if /bin, /sbin are not symlinks into /usr])]
)

# Configured paths
AC_SUBST([rootprefix], [$with_rootprefix])
AC_SUBST([rootlibdir], [$with_rootlibdir])
AC_SUBST([udevlibexecdir], [${with_rootlibdir}/udev])

# sysconfdir paths
AC_SUBST([udevconfdir],[${sysconfdir}/udev])
AC_SUBST([udevconffile],[${udevconfdir}/udev.conf])
AC_SUBST([udevhwdbdir],[${udevconfdir}/hwdb.d])
AC_SUBST([udevhwdbbin],[${udevconfdir}/hwdb.bin])
AC_SUBST([udevkeymapdir],[${udevconfdir}/keymaps])
AC_SUBST([udevkeymapforceredir],[${udevkeymapdir}/force-release])
AC_SUBST([udevrulesdir],[${udevconfdir}/rules.d])

# pkgconfigdir paths
AC_SUBST([sharepkgconfigdir],[${datadir}/pkgconfig])

# ------------------------------------------------------------------------------

have_introspection=no
AC_ARG_ENABLE([introspection],
        [AS_HELP_STRING([--without-introspection], [Disable man page index and systemd-python (default: no)])])
GOBJECT_INTROSPECTION_CHECK([1.31.1])
AM_CONDITIONAL([HAVE_INTROSPECTION], [test "$have_introspection" = "yes"])

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
AC_ARG_ENABLE([acl],
        AS_HELP_STRING([--disable-acl],[Disable optional ACL support]),
                [case "${enableval}" in
                        yes) have_acl=yes ;;
                        no) have_acl=no ;;
                        *) AC_MSG_ERROR(bad value ${enableval} for --disable-acl) ;;
                esac],
                [have_acl=auto])

if test "x${have_acl}" != xno ; then
        AC_CHECK_HEADERS(
                [sys/acl.h acl/libacl.h],
                [have_acl=yes],
                [if test "x$have_acl" = xyes ; then
                        AC_MSG_ERROR([*** ACL headers not found.])
                fi])

        AC_CHECK_LIB(
                [acl],
                [acl_get_file],
                [have_acl=yes],
                [if test "x$have_acl" = xyes ; then
                        AC_MSG_ERROR([*** libacl not found.])
                fi])

        if test "x$have_acl" = xyes ; then
                ACL_LIBS="-lacl"
                AC_DEFINE(HAVE_ACL, 1, [ACL available])
        else
                have_acl=no
        fi
else
        ACL_LIBS=
fi
AC_SUBST(ACL_LIBS)
AM_CONDITIONAL([HAVE_ACL], [test "x$have_acl" != xno])

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
          [Firmware search path (default=ROOTPREFIX/lib/firmware/updates:ROOTPREFIX/lib/firmware)]),
       [], [with_firmware_path="$rootprefix/lib/firmware/updates:$rootprefix/lib/firmware"])
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
AC_SUBST([FIRMWARE_PATH], [$FIRMWARE_PATH])

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
AM_CONDITIONAL([ENABLE_KEYMAP], [test "x$enable_keymap" = "xyes"])

# ------------------------------------------------------------------------------

GTK_DOC_CHECK([1.18],[--flavour no-tmpl])
AM_CONDITIONAL([ENABLE_GTK_DOC],[test "x$enable_gtk_doc" = "xyes"])

AS_IF([test "x$enable_gtk_doc" = "xyes" -a "x$XSLTPROC" = x], [
	AC_MSG_ERROR([*** GTK doc requested but xsltproc not found])
])

DISTCHECK_CONFIGURE_FLAGS=--enable-gtk-doc

# ------------------------------------------------------------------------------
have_manpages=no
AC_ARG_ENABLE(manpages, AS_HELP_STRING([--disable-manpages], [disable manpages]))
AS_IF([test "x$enable_manpages" != xno], [
        AS_IF([test "x$enable_manpages" = xyes -a "x$XSLTPROC" = x], [
                AC_MSG_ERROR([*** Manpages requested but xsltproc not found])
        ])
        AS_IF([test "x$XSLTPROC" != x], [have_manpages=yes])
])
AM_CONDITIONAL(ENABLE_MANPAGES, [test "x$have_manpages" = "xyes"])

# ------------------------------------------------------------------------------

LIBKMOD=
AC_ARG_ENABLE([modules], [AS_HELP_STRING([--disable-modules], [Disable loadable module support @<:@default=enabled@:>@])], [have_modules=no], [have_modules=yes])
AC_ARG_ENABLE([libkmod], [AS_HELP_STRING([--enable-libkmod], [Enable module loading through kmod @<:@default=disabled@:>@])], [have_libkmod=yes], [have_libkmod=no])

if test "x$have_modules" == "xyes"; then

	AC_DEFINE([HAVE_MODULES], [1], [Define if we support loading modules])

	AS_IF([test "x$have_libkmod" != xno],
	  [AC_CHECK_LIB([kmod], [main],
	    [PKG_CHECK_MODULES(KMOD, [libkmod >= 5])
	     AC_SUBST([LIBKMOD], ["-lkmod"])
	     AC_DEFINE([HAVE_LIBKMOD], [1],
		       [Define if you have libkmod])
	    ],
	    [AC_MSG_FAILURE(
	       [--with-libkmod was given, but test for kmod failed])],
	    [-lkmod])])

fi

AM_CONDITIONAL([HAVE_MODULES], [test "x$have_modules" == "xyes"])
AM_CONDITIONAL([HAVE_LIBKMOD], [test "x$have_libkmod" == "xyes"])


# ------------------------------------------------------------------------------

AC_ARG_WITH([modprobe],
            [AS_HELP_STRING([--with-modprobe=modprobe],
              [specify location of modprobe when -- @<:@default=$sbindir/modprobe@:>@])],
            [],
            [with_modprobe="${sbindir}/modprobe"])

AC_SUBST([MODPROBE], ["${with_modprobe}"])

# ------------------------------------------------------------------------------

AC_CONFIG_FILES([Makefile
                 docs/Makefile
                 docs/gudev/Makefile
                 docs/gudev/version.xml
                 docs/libudev/Makefile
                 docs/libudev/version.xml
                 hwdb/Makefile
                 keymaps-force-release/Makefile
                 keymaps/Makefile
                 man/Makefile
                 rules/Makefile
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
                 src/keymap/Makefile
                 src/keymap/check-keymaps.sh
                 src/keymap/keyboard-force-release.sh
                 src/libudev/Makefile
                 src/libudev/libudev.pc
                 src/udev/Makefile
                 src/udev/udev.pc
                 src/test/Makefile
                 test/Makefile])


AC_OUTPUT

dnl Set configured scripts executable
if test -f  src/keymap/check-keymaps.sh; then
	chmod +x src/keymap/check-keymaps.sh
fi

if test -f src/keymap/keyboard-force-release.sh; then
	chmod +x src/keymap/keyboard-force-release.sh
fi
